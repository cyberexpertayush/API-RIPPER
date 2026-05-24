"""
API RIPPER v2.0 — Schema & Data Exposure Agent
Infers response schemas from API responses, detects sensitive
data exposure, field-level inconsistencies, and over-fetching.

OBSERVE: Parse response bodies from cached/probed data
PROFILE: Infer JSON schemas with field types and sensitivity classification
DIFF:    Compare schemas across endpoint groups for inconsistencies
INFER:   Detect PII exposure, debug leaks, internal field leaks
"""

import asyncio
import json
import logging
import re
import time
from typing import Any, Dict, List, Optional

import aiohttp

from backend.agents.base_agent import BaseAgent, Finding

logger = logging.getLogger(__name__)

# Sensitive field patterns
SENSITIVE_PATTERNS = {
    "secret": re.compile(r'(password|passwd|pwd|secret|token|api.?key|private.?key|access.?key|auth.?token)', re.I),
    "pii": re.compile(r'(email|phone|mobile|ssn|social|credit.?card|dob|birth|address|zip.?code|postal)', re.I),
    "internal": re.compile(r'(internal|private|_id|__\w+|debug|trace|stack|raw|admin)', re.I),
    "financial": re.compile(r'(account.?number|routing|iban|swift|balance|payment|salary|income)', re.I),
    "location": re.compile(r'(latitude|longitude|lat|lng|geo|location|ip.?address|remote.?addr)', re.I),
}

# Value patterns (detect by value, not field name)
VALUE_PATTERNS = {
    "email": re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
    "phone": re.compile(r'^[\+]?[(]?[0-9]{1,4}[)]?[-\s\./0-9]{7,15}$'),
    "uuid": re.compile(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', re.I),
    "ip_address": re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$'),
    "jwt": re.compile(r'^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$'),
    "url": re.compile(r'^https?://'),
    "hash": re.compile(r'^[a-f0-9]{32,128}$', re.I),
    "base64": re.compile(r'^[A-Za-z0-9+/]{20,}={0,2}$'),
    # Advanced Secret Patterns
    "aws_access_key": re.compile(r'(?i)AKIA[0-9A-Z]{16}'),
    "stripe_key": re.compile(r'(?i)(sk_live_[0-9a-zA-Z]{24})'),
    "slack_token": re.compile(r'(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})'),
    "github_token": re.compile(r'(?i)gh[p|o|u|s|r]_[a-zA-Z0-9]{36}'),
    "google_api_key": re.compile(r'AIza[0-9A-Za-z-_]{35}'),
    "generic_api_key": re.compile(r'(?i)(api[_-]?key|secret|token)[\s:=]+["\']?([a-zA-Z0-9\-_]{16,})["\']?'),
}


class SchemaAgent(BaseAgent):
    """
    Schema & Data Exposure Agent.
    Infers API response schemas and detects sensitive data exposure.
    """

    name = "schema_agent"

    async def observe(self) -> Dict[str, Any]:
        """Step 1: Fetch responses from endpoints to analyze schemas."""
        endpoints = self.kg.get_all_endpoints()
        observations = {}

        if not endpoints:
            return observations

        auth_config = self.config.get("auth_config", {})
        headers = {"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
        if auth_config.get("bearer_token"):
            headers["Authorization"] = f"Bearer {auth_config['bearer_token']}"
        if auth_config.get("api_key"):
            headers["X-API-Key"] = auth_config["api_key"]

        timeout = aiohttp.ClientTimeout(total=10)
        connector = aiohttp.TCPConnector(ssl=False, limit=5)

        async with aiohttp.ClientSession(timeout=timeout, headers=headers, connector=connector) as session:
            for ep in endpoints[:40]:
                url = ep["url"]
                await self.rate_limited_delay()
                try:
                    async with session.get(url) as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="replace")
                            ct = resp.headers.get("content-type", "")
                            if "json" in ct:
                                try:
                                    data = json.loads(body)
                                    observations[url] = {
                                        "data": data,
                                        "headers": dict(resp.headers),
                                        "status": resp.status,
                                    }
                                except json.JSONDecodeError:
                                    pass
                            else:
                                # Check for leaked data in non-JSON responses
                                observations[url] = {
                                    "data": None,
                                    "body": body[:5000],
                                    "headers": dict(resp.headers),
                                    "status": resp.status,
                                }
                except Exception:
                    pass

        return observations

    async def profile(self, observations: Dict[str, Any]) -> Dict[str, Dict]:
        """Step 2: Infer schemas, classify sensitivity, and generate mutations."""
        from backend.agents.mutation_engine import ContextualMutationEngine
        mutator = ContextualMutationEngine()
        schemas = {}

        for url, obs in observations.items():
            data = obs.get("data")
            if data is None:
                # Non-JSON: check for sensitive data in raw body
                body = obs.get("body", "")
                leaked = self._scan_raw_body(body)
                if leaked:
                    schemas[url] = {"type": "raw", "leaked_patterns": leaked}
                continue

            schema = self._infer_schema(data)
            
            # Generate elite fuzzing payloads for this schema
            mutated_payloads = []
            if isinstance(data, dict):
                for field_path, field_info in schema.get("fields", {}).items():
                    # We only mutate top-level for now to avoid explosion, or we can use the engine
                    # Actually, the engine supports deep paths.
                    mutations = mutator.generate_mutations(
                        field_name=field_path.split('.')[-1], 
                        original_value=field_info.get("sample"), 
                        expected_type=field_info.get("type", "string")
                    )
                    # Create a few sample mutated payloads
                    for m in mutations[:5]: # Take top 5 to avoid explosion
                        try:
                            mutated_payloads.append({
                                "field": field_path,
                                "mutation": m,
                                "payload": mutator.apply_mutation_to_payload(data, field_path, m)
                            })
                        except Exception as e:
                            logger.debug(f"[schema] Mutation fail on {field_path}: {e}")

            schema["mutated_payloads"] = mutated_payloads
            schemas[url] = schema

            # Update Knowledge Graph
            self.kg.add_endpoint(
                url=url, method="GET", source_agent=self.name, confidence=0.8,
                response_schema=schema.get("fields", {}),
                sensitive_fields=schema.get("sensitive_fields", []),
                # Storing mutated payloads in KG for ExploitAgent
                mutated_payloads=mutated_payloads 
            )

            # Emit signals for sensitive exposure
            for field_info in schema.get("sensitive_fields", []):
                self.emit_signal("SENSITIVE_EXPOSURE", {
                    "url": url,
                    "field": field_info["name"],
                    "sensitivity": field_info["sensitivity"],
                    "reason": field_info["reason"],
                }, confidence=0.8, priority=2)

        return schemas

    async def differential_analyze(self, schemas: Dict[str, Dict]) -> List[Dict]:
        """Step 3: Compare schemas across endpoint groups."""
        diffs = []

        # Group endpoints by cluster
        clusters = self.kg.get_clusters()
        for cluster_name, urls in clusters.items():
            cluster_schemas = []
            for url in urls:
                if url in schemas and schemas[url].get("type") != "raw":
                    cluster_schemas.append((url, schemas[url]))

            # Compare field sets within same cluster
            if len(cluster_schemas) >= 2:
                for i in range(len(cluster_schemas)):
                    for j in range(i + 1, len(cluster_schemas)):
                        url_a, schema_a = cluster_schemas[i]
                        url_b, schema_b = cluster_schemas[j]
                        fields_a = set(schema_a.get("fields", {}).keys())
                        fields_b = set(schema_b.get("fields", {}).keys())

                        extra_in_b = fields_b - fields_a
                        extra_in_a = fields_a - fields_b

                        if extra_in_a or extra_in_b:
                            diffs.append({
                                "type": "schema_inconsistency",
                                "cluster": cluster_name,
                                "url_a": url_a,
                                "url_b": url_b,
                                "extra_in_a": list(extra_in_a),
                                "extra_in_b": list(extra_in_b),
                            })

        return diffs

    async def infer(self, diffs: Any) -> List[Finding]:
        """Step 4: Generate findings from schema analysis."""
        findings = []
        endpoints = self.kg.get_all_endpoints()

        for ep in endpoints:
            url = ep["url"]
            sensitive_fields = ep.get("sensitive_fields", [])
            schema = ep.get("response_schema", {})

            # Finding: PII exposure in public endpoints
            auth_required = ep.get("auth_required")
            if sensitive_fields and auth_required is False:
                for field_info in sensitive_fields:
                    if isinstance(field_info, dict):
                        sensitivity = field_info.get("sensitivity", "")
                        name = field_info.get("name", "")
                    else:
                        sensitivity = "sensitive"
                        name = str(field_info)

                    if sensitivity in ("secret", "pii", "financial"):
                        findings.append(Finding(
                            type="sensitive_data_exposure",
                            title=f"Sensitive Field Exposed: '{name}' on {url}",
                            description=f"Field '{name}' (classified as {sensitivity}) is exposed on a public endpoint without authentication. This constitutes a data exposure vulnerability.",
                            severity="high" if sensitivity in ("secret", "financial") else "medium",
                            confidence=0.7,
                            endpoint=url,
                            cwe="CWE-200",
                            owasp="API3:2023",
                            remediation=f"Remove or mask the '{name}' field from public responses. Require authentication for sensitive data.",
                            evidence=[{"type": "schema", "field": name, "sensitivity": sensitivity}],
                        ))

            # Finding: Over-fetching (too many fields)
            if len(schema) > 15:
                findings.append(Finding(
                    type="over_fetching",
                    title=f"Potential Over-Fetching: {url} returns {len(schema)} fields",
                    description=f"Endpoint returns {len(schema)} fields. APIs should return only necessary data. Excess fields increase attack surface and data exposure risk.",
                    severity="low",
                    confidence=0.5,
                    endpoint=url,
                    cwe="CWE-213",
                    owasp="API3:2023",
                    remediation="Implement field-level response filtering. Return only fields needed by the client.",
                    evidence=[{"type": "schema", "field_count": len(schema), "fields": list(schema.keys())[:20]}],
                ))

        # Findings from schema inconsistencies
        for diff in diffs:
            if diff["type"] == "schema_inconsistency":
                findings.append(Finding(
                    type="inconsistent_data_exposure",
                    title=f"Inconsistent Schema in '{diff['cluster']}' Cluster",
                    description=f"Endpoints {diff['url_a']} and {diff['url_b']} return different field sets. Extra in A: {diff['extra_in_a']}, Extra in B: {diff['extra_in_b']}. Inconsistent exposure suggests misconfigured serialization.",
                    severity="medium",
                    confidence=0.6,
                    endpoint=diff["url_a"],
                    cwe="CWE-200",
                    remediation="Standardize response schemas across similar endpoints.",
                    evidence=[{"type": "schema_diff", "data": diff}],
                ))
                self.emit_signal("SCHEMA_INCONSISTENCY", diff, confidence=0.6)

        return findings

    # ── Internal Methods ────────────────────────────────────

    def _infer_schema(self, data: Any, prefix: str = "") -> Dict:
        """Recursively infer JSON schema with sensitivity classification."""
        result = {"fields": {}, "sensitive_fields": [], "total_fields": 0}

        if isinstance(data, dict):
            for key, value in data.items():
                field_path = f"{prefix}.{key}" if prefix else key
                field_info = {
                    "type": self._detect_type(value),
                    "sensitivity": self._classify_sensitivity(key, value),
                    "sample": self._safe_sample(value),
                }
                result["fields"][field_path] = field_info
                result["total_fields"] += 1

                if field_info["sensitivity"] != "public":
                    result["sensitive_fields"].append({
                        "name": field_path,
                        "sensitivity": field_info["sensitivity"],
                        "reason": self._sensitivity_reason(key, value),
                    })

                # Recurse into nested objects
                if isinstance(value, dict):
                    nested = self._infer_schema(value, field_path)
                    result["fields"].update(nested["fields"])
                    result["sensitive_fields"].extend(nested["sensitive_fields"])
                    result["total_fields"] += nested["total_fields"]
                elif isinstance(value, list) and value and isinstance(value[0], dict):
                    nested = self._infer_schema(value[0], f"{field_path}[]")
                    result["fields"].update(nested["fields"])
                    result["sensitive_fields"].extend(nested["sensitive_fields"])

        elif isinstance(data, list) and data and isinstance(data[0], dict):
            return self._infer_schema(data[0], prefix)

        return result

    def _detect_type(self, value: Any) -> str:
        if isinstance(value, bool):
            return "boolean"
        if isinstance(value, int):
            return "integer"
        if isinstance(value, float):
            return "float"
        if isinstance(value, str):
            for vtype, pattern in VALUE_PATTERNS.items():
                if pattern.match(value):
                    return vtype
            return "string"
        if isinstance(value, list):
            return "array"
        if isinstance(value, dict):
            return "object"
        if value is None:
            return "null"
        return "unknown"

    def _classify_sensitivity(self, key: str, value: Any) -> str:
        for sensitivity, pattern in SENSITIVE_PATTERNS.items():
            if pattern.search(key):
                return sensitivity
        if isinstance(value, str):
            detected_type = self._detect_type(value)
            if detected_type in ("email", "phone", "jwt", "ip_address", "hash"):
                return "pii" if detected_type in ("email", "phone") else "internal"
        return "public"

    def _sensitivity_reason(self, key: str, value: Any) -> str:
        for sensitivity, pattern in SENSITIVE_PATTERNS.items():
            if pattern.search(key):
                return f"Field name matches {sensitivity} pattern: {pattern.pattern}"
        return "Value pattern detection"

    def _safe_sample(self, value: Any) -> str:
        if isinstance(value, str):
            if len(value) > 50:
                return value[:20] + "..." + value[-10:]
            return value
        return str(value)[:50]

    def _scan_raw_body(self, body: str) -> List[Dict]:
        leaked = []
        for vtype, pattern in VALUE_PATTERNS.items():
            matches = pattern.findall(body[:5000])
            if matches:
                leaked.append({"type": vtype, "count": len(matches)})
        return leaked
