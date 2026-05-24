"""
API RIPPER v2.0 — Base Agent
Abstract base class implementing the 7-step reasoning pipeline.
All agents inherit from this and implement each reasoning phase.

Reasoning Pipeline:
  1. OBSERVE    — Collect raw data without assumptions
  2. PROFILE    — Build behavioral/structural models
  3. DIFF       — Compare responses across controlled variations
  4. INFER      — Form hypotheses from multiple signals
  5. VALIDATE   — Check repeatability, assign confidence
  6. CONTEXT    — Map to API architecture
  7. PRIORITIZE — Score risk
"""

import asyncio
import hashlib
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

logger = logging.getLogger(__name__)


# ─── Exploitation Mode ──────────────────────────────────────

class ExploitMode(str, Enum):
    """
    STANDARD:  Safe analysis, non-destructive probes only.
               Used when no authorization is provided.
    FULL_AUTH: Owner-authorized deep exploitation.
               No restrictions, no filters, no boundaries.
               The framework thinks deep and exploits deep.
    """
    STANDARD = "standard"
    FULL_AUTH = "full_auth"


# ─── Confidence Thresholds ──────────────────────────────────

class ConfidenceLevel(str, Enum):
    WEAK = "weak"                # 0.0 – 0.3
    POSSIBLE = "possible"        # 0.4 – 0.6
    LIKELY = "likely"            # 0.7 – 0.85
    CONFIRMED = "confirmed"      # 0.9 – 1.0

    @classmethod
    def from_score(cls, score: float) -> "ConfidenceLevel":
        if score >= 0.9:
            return cls.CONFIRMED
        elif score >= 0.7:
            return cls.LIKELY
        elif score >= 0.4:
            return cls.POSSIBLE
        return cls.WEAK


# ─── Data Classes ───────────────────────────────────────────

@dataclass
class AgentHealth:
    """Health status reported by each agent."""
    status: str = "healthy"          # healthy | degraded | failed
    last_action: str = ""
    errors: List[str] = field(default_factory=list)
    actions_completed: int = 0
    started_at: float = field(default_factory=time.time)

    @property
    def uptime_seconds(self) -> float:
        return time.time() - self.started_at

    def degrade(self, reason: str):
        self.status = "degraded"
        self.errors.append(f"[{datetime.utcnow().isoformat()}] {reason}")

    def fail(self, reason: str):
        self.status = "failed"
        self.errors.append(f"[{datetime.utcnow().isoformat()}] FATAL: {reason}")

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "last_action": self.last_action,
            "errors": self.errors[-10:],  # Last 10 errors
            "actions_completed": self.actions_completed,
            "uptime_seconds": round(self.uptime_seconds, 2),
        }


@dataclass
class TraceEntry:
    """Execution trace for audit and debugging."""
    agent: str
    action: str
    input_data: Dict[str, Any] = field(default_factory=dict)
    output_data: Dict[str, Any] = field(default_factory=dict)
    signals_emitted: List[str] = field(default_factory=list)
    duration_ms: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "agent": self.agent,
            "action": self.action,
            "input": self.input_data,
            "output": self.output_data,
            "signals_emitted": self.signals_emitted,
            "duration_ms": round(self.duration_ms, 2),
            "timestamp": self.timestamp,
            "error": self.error,
        }


@dataclass
class Finding:
    """A structured finding produced by any agent."""
    id: str = field(default_factory=lambda: str(uuid4()))
    type: str = ""
    title: str = ""
    description: str = ""
    severity: str = "info"              # critical, high, medium, low, info
    confidence: float = 0.0
    confidence_level: str = "weak"
    endpoint: str = ""
    method: str = "GET"
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    supporting_signals: List[str] = field(default_factory=list)
    cwe: str = ""
    owasp: str = ""
    remediation: str = ""
    agent_source: str = ""
    chain_id: Optional[str] = None
    exploit_mode_required: str = "standard"  # standard or full_auth

    def to_dict(self) -> dict:
        # Establish formal Confidence Scoring Model (0-10) based on signals
        # Base confidence is out of 1.0, so multiply by 10. Boost by evidence count > 2.
        base_10_score = self.confidence * 10
        evidence_boost = max(0, (len(self.evidence) - 2) * 0.5) if hasattr(self, 'evidence') else 0
        signal_boost = max(0, (len(self.supporting_signals)) * 0.2) if hasattr(self, 'supporting_signals') else 0
        final_score_10 = min(10.0, round(base_10_score + evidence_boost + signal_boost, 1))

        return {
            "id": self.id,
            "type": self.type,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "confidence_score_10": final_score_10,
            "confidence_level": self.confidence_level,
            "endpoint": self.endpoint,
            "method": self.method,
            "evidence": self.evidence,
            "supporting_signals": self.supporting_signals,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "remediation": self.remediation,
            "agent_source": self.agent_source,
            "chain_id": self.chain_id,
            "exploit_mode_required": self.exploit_mode_required,
        }


# ─── Base Agent ─────────────────────────────────────────────

class BaseAgent(ABC):
    """
    Abstract base for all agents in the API RIPPER framework.

    Every agent follows the mandatory 7-step reasoning pipeline:
      OBSERVE → PROFILE → DIFFERENTIAL → INFER → VALIDATE → CONTEXTUALIZE → PRIORITIZE

    Agents communicate via the MessageBus and share state via the KnowledgeGraph.
    All actions are logged in the trace for full audit capability.
    """

    name: str = "base_agent"

    def __init__(self, knowledge_graph, message_bus, config: Dict[str, Any] = None):
        self.kg = knowledge_graph
        self.bus = message_bus
        self.config = config or {}
        self.exploit_mode = ExploitMode(self.config.get("exploit_mode", "standard"))
        self.health = AgentHealth()
        self.trace: List[TraceEntry] = []
        self.findings: List[Finding] = []
        self._request_cache: Dict[str, Any] = {}
        self._cache_ttl = 60  # seconds

        # Resource Governor (shared across agents)
        self.governor = self.config.get("governor", None)

        # WAF Bypass handler
        self.waf_bypass = None  # Set by ReconAgent after WAF detection

        # Rate limiting
        self._request_delay = self.config.get("request_delay_ms", 100) / 1000.0
        self._last_request_time = 0.0

        # Agent Metrics (observability)
        self._metrics = {
            "requests_made": 0,
            "requests_blocked": 0,
            "signals_emitted": 0,
            "execution_start": 0.0,
            "execution_time": 0.0,
        }

    # ── Main execution loop ─────────────────────────────────

    async def run(self) -> List[Finding]:
        """Execute the full 7-step reasoning pipeline."""
        logger.info(f"[{self.name}] Starting agent (mode={self.exploit_mode.value})")
        self.health.last_action = "starting"
        self._metrics["execution_start"] = time.time()

        try:
            # Step 1: OBSERVE
            self.health.last_action = "observe"
            observations = await self._traced("observe", self.observe)

            # Step 2: PROFILE
            self.health.last_action = "profile"
            profiles = await self._traced("profile", self.profile, observations)

            # Step 3: DIFFERENTIAL ANALYSIS
            self.health.last_action = "differential_analyze"
            diffs = await self._traced("differential_analyze", self.differential_analyze, profiles)

            # Step 4: INFER
            self.health.last_action = "infer"
            hypotheses = await self._traced("infer", self.infer, diffs)

            # Step 5: VALIDATE
            self.health.last_action = "validate"
            validated = await self._traced("validate", self.validate, hypotheses)

            # Step 6: CONTEXTUALIZE
            self.health.last_action = "contextualize"
            contextualized = await self._traced("contextualize", self.contextualize, validated)

            # Step 7: PRIORITIZE
            self.health.last_action = "prioritize"
            prioritized = await self._traced("prioritize", self.prioritize, contextualized)

            self.findings = prioritized if isinstance(prioritized, list) else []
            self.health.last_action = "completed"
            self._metrics["execution_time"] = round(time.time() - self._metrics["execution_start"], 3)
            logger.info(f"[{self.name}] Completed — {len(self.findings)} findings | {self._metrics['requests_made']} reqs | {self._metrics['signals_emitted']} signals | {self._metrics['execution_time']}s")
            return self.findings

        except Exception as e:
            self.health.fail(str(e))
            self._metrics["execution_time"] = round(time.time() - self._metrics["execution_start"], 3)
            logger.error(f"[{self.name}] Failed: {e}", exc_info=True)
            return self.findings  # Return partial results

    # ── Abstract methods (each agent implements these) ───────

    @abstractmethod
    async def observe(self) -> Any:
        """Step 1: Collect raw data without assumptions."""
        ...

    @abstractmethod
    async def profile(self, observations: Any) -> Any:
        """Step 2: Build behavioral/structural models."""
        ...

    @abstractmethod
    async def differential_analyze(self, profiles: Any) -> Any:
        """Step 3: Compare responses across controlled variations."""
        ...

    @abstractmethod
    async def infer(self, diffs: Any) -> List[Finding]:
        """Step 4: Form hypotheses from multiple signals."""
        ...

    async def validate(self, hypotheses: List[Finding]) -> List[Finding]:
        """
        Step 5: Check repeatability, assign confidence.
        Default implementation applies self-critique.
        Agents can override for custom validation.
        """
        validated = []
        for finding in hypotheses:
            finding = self.self_critique(finding)
            finding.confidence_level = ConfidenceLevel.from_score(finding.confidence).value
            if finding.confidence >= 0.1:  # Drop truly noise-level findings
                validated.append(finding)
        return validated

    async def contextualize(self, findings: List[Finding]) -> List[Finding]:
        """
        Step 6: Map findings to API architecture.
        Default implementation enriches with KG data.
        """
        for finding in findings:
            endpoint_data = self.kg.get_endpoint(finding.endpoint)
            if endpoint_data:
                # Enrich with knowledge graph context
                if not finding.method and endpoint_data.get("methods"):
                    finding.method = endpoint_data["methods"][0]
            finding.agent_source = self.name
        return findings

    async def prioritize(self, findings: List[Finding]) -> List[Finding]:
        """
        Step 7: Score risk and sort by priority.
        Default implementation sorts by confidence × severity weight.
        """
        severity_weights = {
            "critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1
        }
        for f in findings:
            f._priority = f.confidence * severity_weights.get(f.severity, 1)
        findings.sort(key=lambda f: getattr(f, "_priority", 0), reverse=True)
        return findings

    # ── Self-Critique Loop ──────────────────────────────────

    def self_critique(self, finding: Finding) -> Finding:
        """
        Mandatory self-evaluation before finalizing any finding.
        Downgrades confidence if evidence is insufficient.
        """
        original = finding.confidence

        # Check 1: Is this based on ≥ 2 independent evidence points?
        if len(finding.evidence) < 2:
            finding.confidence -= 0.2

        # Check 2: Are there supporting signals from other agents?
        if len(finding.supporting_signals) < 1:
            finding.confidence -= 0.1

        # Check 3: Repeatability implied by evidence count
        if len(finding.evidence) < 3:
            finding.confidence -= 0.05

        # Floor at 0.0
        finding.confidence = max(0.0, round(finding.confidence, 3))

        if finding.confidence < original:
            logger.debug(
                f"[{self.name}] Self-critique: {finding.type} "
                f"confidence {original:.2f} → {finding.confidence:.2f}"
            )

        return finding

    # ── Signal Emission ─────────────────────────────────────

    def emit_signal(
        self,
        signal_type: str,
        data: Dict[str, Any],
        confidence: float,
        target: str = "*",
        priority: int = 5,
    ):
        """Emit a weighted signal to the message bus."""
        from backend.agents.message_bus import Signal, SIGNAL_WEIGHTS

        dedup_key = f"{signal_type}:{self.name}:{hashlib.sha256(str(sorted(data.items()) if isinstance(data, dict) else str(data)).encode()).hexdigest()[:16]}"

        # Auto-assign weight from SIGNAL_WEIGHTS
        weight = SIGNAL_WEIGHTS.get(signal_type, 1.0)

        signal = Signal(
            id=str(uuid4()),
            type=signal_type,
            source=self.name,
            target=target,
            data=data,
            confidence=confidence,
            weight=weight,
            priority=priority,
            dedup_hash=dedup_key,
            ttl=5,
        )
        if self.bus.emit(signal):
            self._metrics["signals_emitted"] += 1

    def consume_signals(self, signal_types: List[str] = None) -> list:
        """Consume signals from the message bus targeted at this agent."""
        return self.bus.consume(self.name, signal_types)

    # ── Request Helpers (Governor-Aware) ─────────────────────

    async def governed_request(self, url: str, method: str = "GET", **kwargs) -> Optional[Any]:
        """
        Make an HTTP request with governor + WAF bypass enforcement.
        Returns None if blocked by governor or WAF.
        """
        import aiohttp

        # Governor check
        if self.governor and not self.governor.can_request(url, self.name):
            self._metrics["requests_blocked"] += 1
            return None

        # Rate limiting
        await self.rate_limited_delay()

        # WAF bypass headers
        headers = kwargs.pop("headers", {})
        if self.waf_bypass:
            headers.update(self.waf_bypass.get_bypass_headers())

        try:
            async with aiohttp.ClientSession() as session:
                req_method = getattr(session, method.lower(), session.get)
                async with req_method(url, headers=headers, timeout=aiohttp.ClientTimeout(total=30), ssl=False, **kwargs) as resp:
                    body = await resp.text()
                    result = {
                        "status": resp.status,
                        "headers": dict(resp.headers),
                        "body": body,
                        "url": str(resp.url),
                    }

                    # Record with governor
                    if self.governor:
                        self.governor.record_request(url, self.name)
                    self._metrics["requests_made"] += 1

                    # WAF response analysis
                    if self.waf_bypass:
                        if resp.status in (403, 429, 503):
                            self.waf_bypass.on_block_detected()
                        else:
                            self.waf_bypass.on_success()

                    return result

        except Exception as e:
            logger.debug(f"[{self.name}] Request failed: {url} — {e}")
            return None

    async def rate_limited_delay(self):
        """Enforce rate limiting between requests."""
        # WAF adaptive delay takes priority
        if self.waf_bypass:
            await self.waf_bypass.adaptive_delay()
            return

        now = time.time()
        elapsed = now - self._last_request_time
        if elapsed < self._request_delay:
            await asyncio.sleep(self._request_delay - elapsed)
        self._last_request_time = time.time()

    def cache_response(self, cache_key: str, response: Any):
        """Cache a response with TTL."""
        self._request_cache[cache_key] = {
            "data": response,
            "expires": time.time() + self._cache_ttl,
        }

    def get_cached(self, cache_key: str) -> Optional[Any]:
        """Retrieve cached response if not expired."""
        entry = self._request_cache.get(cache_key)
        if entry and time.time() < entry["expires"]:
            return entry["data"]
        if entry:
            del self._request_cache[cache_key]
        return None

    @property
    def metrics(self) -> dict:
        """Agent-level observability metrics."""
        return {
            "agent": self.name,
            "requests_made": self._metrics["requests_made"],
            "requests_blocked": self._metrics["requests_blocked"],
            "signals_emitted": self._metrics["signals_emitted"],
            "execution_time": self._metrics["execution_time"],
            "findings_count": len(self.findings),
            "health": self.health.status,
        }

    # ── Tracing ─────────────────────────────────────────────

    async def _traced(self, action: str, func, *args) -> Any:
        """Execute a function with full trace logging."""
        start = time.time()
        entry = TraceEntry(agent=self.name, action=action)

        try:
            if asyncio.iscoroutinefunction(func):
                result = await func(*args)
            else:
                result = func(*args)

            entry.duration_ms = (time.time() - start) * 1000
            self.health.actions_completed += 1

            # Summarize output for trace (avoid huge payloads)
            if isinstance(result, list):
                entry.output_data = {"count": len(result), "type": "list"}
            elif isinstance(result, dict):
                entry.output_data = {"keys": list(result.keys())[:10]}
            else:
                entry.output_data = {"type": type(result).__name__}

            self.trace.append(entry)
            return result

        except Exception as e:
            entry.error = str(e)
            entry.duration_ms = (time.time() - start) * 1000
            self.trace.append(entry)
            self.health.degrade(f"{action}: {e}")
            raise

    # ── Exploit Mode Helpers ────────────────────────────────

    @property
    def is_full_auth(self) -> bool:
        """Check if we're in full-authorization deep exploitation mode."""
        return self.exploit_mode == ExploitMode.FULL_AUTH

    @property
    def is_standard(self) -> bool:
        """Check if we're in standard safe-analysis mode."""
        return self.exploit_mode == ExploitMode.STANDARD

    def require_full_auth(self, action: str) -> bool:
        """
        Check if an action is allowed under the current exploit mode.
        In STANDARD mode: returns False (action blocked).
        In FULL_AUTH mode: returns True (no restrictions).
        """
        if self.is_full_auth:
            return True
        logger.info(f"[{self.name}] Action '{action}' blocked — requires FULL_AUTH mode")
        return False
