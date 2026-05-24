"""
API RIPPER v2.0 — Knowledge Graph
Shared brain for all agents. Stores endpoint registry, behavioral profiles,
schemas, relationships, auth boundaries, and technology profiles.

Integrity Rules (STRICTLY ENFORCED):
  - No direct overwrites — all updates use atomic merge logic
  - Higher-confidence sources win on conflicts
  - Version tracking per field for audit
  - Thread-safe read/write operations
"""

import hashlib
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


@dataclass
class FieldVersion:
    """Tracks the version history of a single field on an endpoint."""
    value: Any
    source_agent: str
    confidence: float
    updated_at: str
    version: int = 1


@dataclass
class EndpointNode:
    """
    Rich model of a single API endpoint.
    All agents contribute to building this profile.
    """
    url: str
    methods: List[str] = field(default_factory=list)
    parameters: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    # Behavioral profile (from Behavioral Agent)
    behavior_profile: Dict[str, Any] = field(default_factory=dict)
    # Response schema (from Schema Agent)
    response_schema: Dict[str, Any] = field(default_factory=dict)
    # Risk scoring (from Risk Agent)
    risk_score: float = 0.0
    risk_factors: List[str] = field(default_factory=list)
    # Auth info
    auth_required: Optional[bool] = None
    auth_type: Optional[str] = None       # bearer, cookie, api_key, none
    # Classification
    classification: str = "unknown"        # auth, data_read, data_write, admin, public, upload, search
    # Data sensitivity
    sensitive_fields: List[str] = field(default_factory=list)
    # Stability
    stability_score: float = 1.0
    error_triggers: List[str] = field(default_factory=list)
    # Metadata
    discovered_by: str = ""
    first_seen: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    last_updated: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    # Version tracking for conflict resolution
    _field_versions: Dict[str, FieldVersion] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "methods": self.methods,
            "parameters": self.parameters,
            "behavior_profile": self.behavior_profile,
            "response_schema": self.response_schema,
            "risk_score": self.risk_score,
            "risk_factors": self.risk_factors,
            "auth_required": self.auth_required,
            "auth_type": self.auth_type,
            "classification": self.classification,
            "sensitive_fields": self.sensitive_fields,
            "stability_score": self.stability_score,
            "error_triggers": self.error_triggers,
            "discovered_by": self.discovered_by,
            "first_seen": self.first_seen,
            "last_updated": self.last_updated,
        }


@dataclass
class DataFlow:
    """Tracks data flowing between endpoints (shared parameters, IDs)."""
    source_endpoint: str
    target_endpoint: str
    shared_fields: List[str]
    flow_type: str = "parameter"    # parameter, id_reference, token
    confidence: float = 0.5


@dataclass
class AuthBoundary:
    """Defines an authentication boundary in the API."""
    protected_endpoints: List[str]
    unprotected_endpoints: List[str]
    auth_type: str
    boundary_confidence: float = 0.5


@dataclass
class Relationship:
    """Typed relationship between two endpoints in the graph."""
    source_endpoint: str
    target_endpoint: str
    type: str           # "data_flow" | "auth_dependency" | "parent_child"
    confidence: float
    evidence: str = ""

    def to_dict(self) -> dict:
        return {
            "source": self.source_endpoint,
            "target": self.target_endpoint,
            "type": self.type,
            "confidence": self.confidence,
            "evidence": self.evidence,
        }


@dataclass
class CorrelationEdge:
    """A generic edge connecting different entities in the Signal Correlation Graph."""
    source_id: str
    source_type: str    # "signal" | "endpoint" | "parameter" | "response" | "chain"
    target_id: str
    target_type: str    # "signal" | "endpoint" | "parameter" | "response" | "chain"
    relation: str       # e.g., "targets", "uses", "generates", "part_of"
    confidence: float

    def to_dict(self) -> dict:
        return {
            "source": self.source_id,
            "source_type": self.source_type,
            "target": self.target_id,
            "target_type": self.target_type,
            "relation": self.relation,
            "confidence": self.confidence,
        }

class KnowledgeGraph:
    """
    Shared state for all agents — the system's memory.

    Thread-safe with atomic merge logic for conflict resolution.
    Higher-confidence sources always win on field conflicts.
    """

    def __init__(self):
        self._lock = threading.RLock()  # Reentrant for nested calls
        self._endpoints: Dict[str, EndpointNode] = {}     # url → EndpointNode
        self._data_flows: List[DataFlow] = []
        self._auth_boundaries: List[AuthBoundary] = []
        self._relationships: List[Relationship] = []      # Typed edges (legacy endpoint-to-endpoint)
        
        # Phase 3: Signal Correlation Graph
        self._correlation_edges: List[CorrelationEdge] = []
        self._signals: Dict[str, Any] = {}
        self._parameters: Dict[str, Any] = {}
        self._responses: Dict[str, Any] = {}
        self._chains: Dict[str, Any] = {}

        self._tech_profile: Dict[str, Any] = {}
        self._endpoint_clusters: Dict[str, List[str]] = {}  # cluster_name → [urls]
        self._raw_observations: List[Dict[str, Any]] = []   # Agent observations log
        self._update_count = 0
        self._snapshot_hashes: List[str] = []  # For convergence tracking
        
        # Global context: shared mutable state for cross-agent intelligence
        self._global_context: Dict[str, Any] = {
            "technology_profile": {},   # Detected tech stack
            "waf_profile": {},          # Detected WAF info
            "failed_payloads": {},      # endpoint → [payload_hashes] that returned 404/error
            "successful_probes": {},    # endpoint → [probe_types] that caused anomalies
            "parameter_map": {},        # endpoint → {param_name: param_info} discovered params
            "injection_points": [],     # [{endpoint, param, location, type}] verified injection points
        }

    # ── Signal Correlation Graph Methods ────────────────────

    def add_correlation(self, source_id: str, source_type: str, target_id: str, target_type: str, relation: str, confidence: float = 1.0):
        with self._lock:
            edge = CorrelationEdge(source_id, source_type, target_id, target_type, relation, confidence)
            # Avoid duplicates
            if not any(e.source_id == source_id and e.target_id == target_id and e.relation == relation for e in self._correlation_edges):
                self._correlation_edges.append(edge)
                self._update_count += 1

    def register_entity(self, entity_type: str, entity_id: str, data: dict):
        """Register a node in the correlation graph (signal, parameter, response, chain)."""
        with self._lock:
            if entity_type == "signal":
                self._signals[entity_id] = data
            elif entity_type == "parameter":
                self._parameters[entity_id] = data
            elif entity_type == "response":
                self._responses[entity_id] = data
            elif entity_type == "chain":
                self._chains[entity_id] = data
            self._update_count += 1

    # ── Endpoint Operations ─────────────────────────────────

    def add_endpoint(
        self,
        url: str,
        method: str = "GET",
        source_agent: str = "",
        confidence: float = 0.5,
        **kwargs
    ) -> EndpointNode:
        """
        Add or update an endpoint in the knowledge graph.
        Uses atomic merge — existing data is preserved, new data is merged.
        Higher-confidence sources win on conflicts.
        """
        with self._lock:
            normalized_url = self._normalize_url(url)

            if normalized_url not in self._endpoints:
                # New endpoint
                node = EndpointNode(
                    url=normalized_url,
                    methods=[method.upper()] if method else [],
                    discovered_by=source_agent,
                )
                self._endpoints[normalized_url] = node
                logger.debug(f"[KG] New endpoint: {normalized_url} (by {source_agent})")
            else:
                node = self._endpoints[normalized_url]
                # Merge method
                if method and method.upper() not in node.methods:
                    node.methods.append(method.upper())

            # Merge additional fields with conflict resolution
            for key, value in kwargs.items():
                if hasattr(node, key) and value is not None:
                    self._atomic_update(node, key, value, source_agent, confidence)

            node.last_updated = datetime.utcnow().isoformat()
            self._update_count += 1
            return node

    def get_endpoint(self, url: str) -> Optional[Dict[str, Any]]:
        """Get endpoint data as a dictionary."""
        with self._lock:
            normalized = self._normalize_url(url)
            node = self._endpoints.get(normalized)
            return node.to_dict() if node else None

    def get_endpoint_node(self, url: str) -> Optional[EndpointNode]:
        """Get the raw EndpointNode (for agents that need direct access)."""
        with self._lock:
            return self._endpoints.get(self._normalize_url(url))

    def get_all_endpoints(self) -> List[Dict[str, Any]]:
        """Get all endpoints as a list of dictionaries."""
        with self._lock:
            return [node.to_dict() for node in self._endpoints.values()]

    def get_endpoints_by_classification(self, classification: str) -> List[EndpointNode]:
        """Get endpoints filtered by classification."""
        with self._lock:
            return [
                node for node in self._endpoints.values()
                if node.classification == classification
            ]

    def get_endpoints_by_auth(self, auth_required: bool) -> List[EndpointNode]:
        """Get endpoints filtered by auth requirement."""
        with self._lock:
            return [
                node for node in self._endpoints.values()
                if node.auth_required == auth_required
            ]

    def get_fragile_endpoints(self, threshold: float = 0.5) -> List[EndpointNode]:
        """Get endpoints with stability score below threshold."""
        with self._lock:
            return [
                node for node in self._endpoints.values()
                if node.stability_score < threshold
            ]

    # ── Atomic Update with Conflict Resolution ──────────────

    def _atomic_update(
        self,
        node: EndpointNode,
        field_name: str,
        new_value: Any,
        source_agent: str,
        confidence: float,
    ):
        """
        Atomically update a field on an endpoint.
        Conflict resolution: higher confidence wins.
        Lists are merged, not replaced.
        Dicts are deep-merged.
        """
        current_value = getattr(node, field_name, None)
        version_key = field_name
        current_version = node._field_versions.get(version_key)

        # If no previous version, accept unconditionally
        if current_version is None:
            setattr(node, field_name, new_value)
            node._field_versions[version_key] = FieldVersion(
                value=new_value,
                source_agent=source_agent,
                confidence=confidence,
                updated_at=datetime.utcnow().isoformat(),
            )
            return

        # Conflict resolution: higher confidence wins
        if confidence >= current_version.confidence:
            # Merge strategy depends on type
            if isinstance(current_value, list) and isinstance(new_value, list):
                # Merge lists (union, no duplicates)
                merged = list(set(current_value + new_value))
                setattr(node, field_name, merged)
            elif isinstance(current_value, dict) and isinstance(new_value, dict):
                # Deep merge dicts
                merged = {**current_value, **new_value}
                setattr(node, field_name, merged)
            else:
                # Scalar: overwrite
                setattr(node, field_name, new_value)

            node._field_versions[version_key] = FieldVersion(
                value=new_value,
                source_agent=source_agent,
                confidence=confidence,
                updated_at=datetime.utcnow().isoformat(),
                version=current_version.version + 1,
            )

    # ── Data Flows ──────────────────────────────────────────

    def add_data_flow(self, flow: DataFlow):
        """Record a data flow between two endpoints."""
        with self._lock:
            # Deduplicate
            for f in self._data_flows:
                if f.source_endpoint == flow.source_endpoint and f.target_endpoint == flow.target_endpoint:
                    f.shared_fields = list(set(f.shared_fields + flow.shared_fields))
                    f.confidence = max(f.confidence, flow.confidence)
                    return
            self._data_flows.append(flow)


    def get_data_flows(self) -> List[Dict[str, Any]]:
        """Get all data flows."""
        with self._lock:
            return [
                {
                    "source": f.source_endpoint,
                    "target": f.target_endpoint,
                    "shared_fields": f.shared_fields,
                    "flow_type": f.flow_type,
                    "confidence": f.confidence,
                }
                for f in self._data_flows
            ]

    # ── Auth Boundaries ─────────────────────────────────────

    def add_auth_boundary(self, boundary: AuthBoundary):
        """Record an authentication boundary."""
        with self._lock:
            self._auth_boundaries.append(boundary)

    def get_auth_boundaries(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [
                {
                    "protected": b.protected_endpoints,
                    "unprotected": b.unprotected_endpoints,
                    "auth_type": b.auth_type,
                    "confidence": b.boundary_confidence,
                }
                for b in self._auth_boundaries
            ]

    # ── Technology Profile ──────────────────────────────────

    def update_tech_profile(self, data: Dict[str, Any], source_agent: str, confidence: float):
        """Update the target's technology profile."""
        with self._lock:
            for key, value in data.items():
                existing_conf = self._tech_profile.get(f"_conf_{key}", 0.0)
                if confidence >= existing_conf:
                    self._tech_profile[key] = value
                    self._tech_profile[f"_conf_{key}"] = confidence

    def get_tech_profile(self) -> Dict[str, Any]:
        with self._lock:
            return {k: v for k, v in self._tech_profile.items() if not k.startswith("_conf_")}

    # ── Endpoint Clustering ─────────────────────────────────

    def add_cluster(self, cluster_name: str, endpoints: List[str]):
        """Group endpoints into a named cluster (e.g., 'user_domain', 'auth')."""
        with self._lock:
            if cluster_name not in self._endpoint_clusters:
                self._endpoint_clusters[cluster_name] = []
            for ep in endpoints:
                normalized = self._normalize_url(ep)
                if normalized not in self._endpoint_clusters[cluster_name]:
                    self._endpoint_clusters[cluster_name].append(normalized)

    def get_clusters(self) -> Dict[str, List[str]]:
        with self._lock:
            return dict(self._endpoint_clusters)

    # ── Observations Log ────────────────────────────────────

    def log_observation(self, agent: str, data: Dict[str, Any]):
        """Log a raw observation from an agent."""
        with self._lock:
            self._raw_observations.append({
                "agent": agent,
                "data": data,
                "timestamp": datetime.utcnow().isoformat(),
            })

    # ── Global Context (Cross-Agent Intelligence) ────────────

    def update_global_context(self, updates: Dict[str, Any]):
        """Merge updates into the shared global context."""
        with self._lock:
            for key, value in updates.items():
                if key in self._global_context and isinstance(self._global_context[key], dict) and isinstance(value, dict):
                    self._global_context[key].update(value)
                elif key in self._global_context and isinstance(self._global_context[key], list) and isinstance(value, list):
                    self._global_context[key].extend(value)
                else:
                    self._global_context[key] = value

    def get_global_context(self) -> Dict[str, Any]:
        """Get the full global context snapshot."""
        with self._lock:
            return dict(self._global_context)

    def record_failed_payload(self, endpoint: str, payload_hash: str):
        """Record a payload that failed at an endpoint so we don't retry it."""
        with self._lock:
            if endpoint not in self._global_context["failed_payloads"]:
                self._global_context["failed_payloads"][endpoint] = []
            if payload_hash not in self._global_context["failed_payloads"][endpoint]:
                self._global_context["failed_payloads"][endpoint].append(payload_hash)

    def is_payload_failed(self, endpoint: str, payload_hash: str) -> bool:
        """Check if a payload already failed at this endpoint."""
        with self._lock:
            return payload_hash in self._global_context.get("failed_payloads", {}).get(endpoint, [])

    def record_injection_point(self, endpoint: str, param: str, location: str, vuln_type: str):
        """Record a verified injection point for targeted exploitation."""
        with self._lock:
            point = {"endpoint": endpoint, "param": param, "location": location, "type": vuln_type}
            if point not in self._global_context["injection_points"]:
                self._global_context["injection_points"].append(point)

    def get_injection_points(self, endpoint: str = None) -> List[Dict]:
        """Get verified injection points, optionally filtered by endpoint."""
        with self._lock:
            points = self._global_context.get("injection_points", [])
            if endpoint:
                return [p for p in points if p["endpoint"] == endpoint]
            return list(points)

    # ── Relationships ────────────────────────────────────────

    def add_relationship(
        self,
        source_url: str,
        target_url: str,
        rel_type: str,
        confidence: float,
        evidence: str = "",
    ):
        """Add a typed relationship between two endpoints."""
        with self._lock:
            src = self._normalize_url(source_url)
            tgt = self._normalize_url(target_url)
            # Deduplicate
            for r in self._relationships:
                if r.source_endpoint == src and r.target_endpoint == tgt and r.type == rel_type:
                    if confidence > r.confidence:
                        r.confidence = confidence
                        r.evidence = evidence
                    return
            self._relationships.append(Relationship(
                source_endpoint=src,
                target_endpoint=tgt,
                type=rel_type,
                confidence=confidence,
                evidence=evidence,
            ))

    def get_relationships(self, rel_type: str = None) -> List[Dict[str, Any]]:
        """Get all relationships, optionally filtered by type."""
        with self._lock:
            rels = self._relationships
            if rel_type:
                rels = [r for r in rels if r.type == rel_type]
            return [r.to_dict() for r in rels]

    def get_related_endpoints(self, url: str) -> List[Dict[str, Any]]:
        """Get all endpoints related to the given URL."""
        with self._lock:
            norm = self._normalize_url(url)
            return [
                r.to_dict()
                for r in self._relationships
                if r.source_endpoint == norm or r.target_endpoint == norm
            ]

    def has_relationships(self) -> bool:
        """Check if any relationships exist — required for valid chain analysis."""
        with self._lock:
            return len(self._relationships) > 0

    # ── Convergence Support ─────────────────────────────────

    def take_snapshot(self) -> str:
        """
        Take a snapshot hash of the current graph state.
        Used by ConvergenceTracker to detect stability.
        """
        import hashlib
        with self._lock:
            state = f"{len(self._endpoints)}:{self._update_count}:{len(self._data_flows)}:{len(self._relationships)}"
            h = hashlib.md5(state.encode()).hexdigest()
            self._snapshot_hashes.append(h)
            return h

    def graph_change_rate(self, last_n: int = 3) -> float:
        """
        Calculate change rate over last N snapshots.
        Returns 0.0 if stable, 1.0 if every snapshot is different.
        """
        with self._lock:
            if len(self._snapshot_hashes) < 2:
                return 1.0
            recent = self._snapshot_hashes[-last_n:]
            if len(recent) < 2:
                return 1.0
            unique = len(set(recent))
            return (unique - 1) / max(len(recent) - 1, 1)

    # ── Utility ─────────────────────────────────────────────

    def _normalize_url(self, url: str) -> str:
        """Normalize URL for consistent lookup (strip trailing slash, lowercase path)."""
        url = url.rstrip("/")
        return url

    def endpoint_count(self) -> int:
        with self._lock:
            return len(self._endpoints)

    def stats(self) -> dict:
        with self._lock:
            return {
                "endpoints": len(self._endpoints),
                "data_flows": len(self._data_flows),
                "relationships": len(self._relationships),
                "auth_boundaries": len(self._auth_boundaries),
                "correlation_edges": len(self._correlation_edges),
                "signals": len(self._signals),
                "parameters": len(self._parameters),
                "responses": len(self._responses),
                "chains": len(self._chains),
                "clusters": len(self._endpoint_clusters),
                "observations": len(self._raw_observations),
                "updates": self._update_count,
            }

    def clear(self):
        """Reset the knowledge graph for a new scan."""
        with self._lock:
            self._endpoints.clear()
            self._data_flows.clear()
            self._auth_boundaries.clear()
            self._relationships.clear()
            self._correlation_edges.clear()
            self._signals.clear()
            self._parameters.clear()
            self._responses.clear()
            self._chains.clear()
            self._tech_profile.clear()
            self._endpoint_clusters.clear()
            self._raw_observations.clear()
            self._snapshot_hashes.clear()
            self._update_count = 0

    def to_dict(self) -> dict:
        """Serialize the entire knowledge graph for reporting."""
        with self._lock:
            return {
                "endpoints": [n.to_dict() for n in self._endpoints.values()],
                "data_flows": self.get_data_flows(),
                "relationships": self.get_relationships(),
                "auth_boundaries": self.get_auth_boundaries(),
                "tech_profile": self.get_tech_profile(),
                "clusters": self.get_clusters(),
                "correlation_graph": {
                    "edges": [e.to_dict() for e in self._correlation_edges],
                    "signals": self._signals,
                    "parameters": self._parameters,
                    "responses": self._responses,
                    "chains": self._chains,
                },
                "stats": self.stats(),
            }
