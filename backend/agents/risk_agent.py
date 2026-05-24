"""
API RIPPER v2.0 — Risk Scoring Agent
Evaluates every endpoint and finding by real-world risk using
a multi-factor heuristic model: exposure, sensitivity, behavioral
anomalies, consistency, and exploitability.
"""

import logging
from typing import Any, Dict, List

from backend.agents.base_agent import BaseAgent, Finding

logger = logging.getLogger(__name__)

# Risk factor weights
WEIGHTS = {
    "public_access": 2,
    "no_auth": 3,
    "exposes_pii": 3,
    "exposes_secrets": 5,
    "fragile": 2,
    "error_leak": 1,
    "inconsistent_auth": 3,
    "inconsistent_schema": 2,
    "in_exploit_chain": 3,
    "high_confidence": 2,
}


class RiskAgent(BaseAgent):
    """
    Risk Scoring Agent.
    Scores every endpoint and finding by real-world exploitability and impact.
    """

    name = "risk_agent"

    async def observe(self) -> Dict[str, Any]:
        """Step 1: Gather all data from Knowledge Graph and signals."""
        signals = self.consume_signals(["CHAIN_CONSTRUCTED", "HYPOTHESIS_VALIDATED"])
        endpoints = self.kg.get_all_endpoints()

        return {
            "endpoints": endpoints,
            "signals": signals,
            "chains": [s.data for s in signals if s.type == "CHAIN_CONSTRUCTED"],
            "hypotheses": [s.data for s in signals if s.type == "HYPOTHESIS_VALIDATED"],
        }

    async def profile(self, data: Dict) -> Dict[str, Dict]:
        """Step 2: Score each endpoint."""
        scored_endpoints = {}

        chain_endpoints = set()
        for chain in data.get("chains", []):
            for ep in chain.get("endpoints_involved", []):
                chain_endpoints.add(ep)

        hypothesis_endpoints = {}
        for hyp in data.get("hypotheses", []):
            ep = hyp.get("endpoint", "")
            if ep:
                hypothesis_endpoints.setdefault(ep, []).append(hyp)

        for ep in data["endpoints"]:
            url = ep["url"]
            factors = []

            # 1. IMPACT (1-10)
            # Driven by data sensitivity and business logic importance
            impact = 3.0 # Base impact
            sensitive = ep.get("sensitive_fields", [])
            has_pii = any((f.get("sensitivity") if isinstance(f, dict) else "") in ("pii", "financial", "location") for f in sensitive)
            has_secrets = any((f.get("sensitivity") if isinstance(f, dict) else "") == "secret" for f in sensitive)

            if has_secrets:
                impact = 10.0
                factors.append("exposes_secrets")
            elif has_pii:
                impact = 8.0
                factors.append("exposes_pii")
            elif ep.get("classification") == "admin":
                impact = 9.0
                factors.append("admin_function")

            # 2. LIKELIHOOD (0.1 - 1.0)
            # Driven by stability, errors, and hypothesis confidence
            likelihood = 0.5 # Base likelihood
            stability = ep.get("stability_score", 1.0)
            if stability < 0.5:
                likelihood += 0.2
                factors.append("fragile_endpoint")

            if ep.get("behavior_profile", {}).get("error_triggers"):
                likelihood += 0.1
                factors.append("error_information_leak")

            if url in hypothesis_endpoints:
                max_conf = max(h.get("confidence", 0) for h in hypothesis_endpoints[url])
                likelihood = max(likelihood, max_conf)
                factors.append("high_confidence_finding")

            likelihood = min(1.0, likelihood)

            # 3. EXPLOITABILITY (0.1 - 1.0)
            # Driven by chain involvement and missing mitigations
            exploitability = 0.4 # Base exploitability
            if url in chain_endpoints:
                exploitability = 0.9
                factors.append("in_exploit_chain")
            if ep.get("classification") == "upload":
                exploitability += 0.3
                factors.append("upload_functionality")
            
            exploitability = min(1.0, exploitability)

            # 4. EXPOSURE (0.1 - 1.0)
            # Driven by auth boundaries and public access
            exposure = 0.2 # Base internal exposure
            if ep.get("auth_required") is False:
                exposure = 1.0
                factors.append("no_authentication_required")
            elif ep.get("classification") == "public":
                exposure = 0.8
                factors.append("publicly_accessible")
            
            exposure = min(1.0, exposure)

            # CALCULATION: Risk = Impact × Likelihood × Exploitability × Exposure
            # Max possible: 10 * 1 * 1 * 1 = 10
            raw_risk = impact * likelihood * exploitability * exposure
            
            # Normalize and cap
            risk_score = min(10.0, max(0.0, raw_risk))
            
            # Boost if it's explicitly in an exploit chain (minimum 7.0 if in a chain)
            if url in chain_endpoints and risk_score < 7.0:
                risk_score = 7.5
                
            risk_level = self._score_to_level(risk_score)

            scored_endpoints[url] = {
                "risk_score": round(risk_score, 2),
                "risk_level": risk_level,
                "factors": list(set(factors)),
            }

            # Update Knowledge Graph
            self.kg.add_endpoint(
                url=url, method="GET", source_agent=self.name,
                confidence=0.9,
                risk_score=risk_score,
                risk_factors=list(set(factors)),
            )

            # Emit high-risk signals
            if risk_score >= 7.0:
                self.emit_signal("HIGH_RISK_ENDPOINT", {
                    "url": url,
                    "risk_score": round(risk_score, 2),
                    "risk_level": risk_level,
                    "factors": list(set(factors)),
                }, confidence=0.9, priority=1)

        return scored_endpoints

    async def differential_analyze(self, scored: Dict[str, Dict]) -> List:
        """Step 3: Not applicable for risk agent."""
        return []

    async def infer(self, diffs: Any) -> List[Finding]:
        """Step 4: Generate risk summary findings."""
        findings = []
        endpoints = self.kg.get_all_endpoints()

        # Find highest-risk endpoints
        high_risk = [
            ep for ep in endpoints
            if ep.get("risk_score", 0) >= 7
        ]

        if high_risk:
            high_risk.sort(key=lambda e: e.get("risk_score", 0), reverse=True)
            top = high_risk[:5]

            endpoint_list = "\n".join(
                f"  - {ep['url']} (score: {ep.get('risk_score', 0):.1f}/10, factors: {', '.join(ep.get('risk_factors', []))})"
                for ep in top
            )

            findings.append(Finding(
                type="risk_assessment",
                title=f"High-Risk Endpoints Identified: {len(high_risk)} endpoints above threshold",
                description=(
                    f"Risk analysis identified {len(high_risk)} endpoints with risk score ≥ 7.0/10.\n\n"
                    f"Top 5 highest-risk endpoints:\n{endpoint_list}\n\n"
                    f"These endpoints should be prioritized for remediation."
                ),
                severity="critical" if any(e.get("risk_score", 0) >= 9 for e in high_risk) else "high",
                confidence=0.9,
                endpoint=top[0]["url"] if top else "",
                remediation="Address risk factors for each endpoint: implement authentication, remove sensitive data from responses, fix input validation, and add rate limiting.",
                evidence=[{"type": "risk_matrix", "high_risk_endpoints": [e["url"] for e in top]}],
            ))

        # Overall risk score
        all_scores = [ep.get("risk_score", 0) for ep in endpoints if ep.get("risk_score", 0) > 0]
        if all_scores:
            avg_risk = sum(all_scores) / len(all_scores)
            max_risk = max(all_scores)

            findings.append(Finding(
                type="overall_risk_posture",
                title=f"API Security Posture: {self._score_to_level(avg_risk).upper()} (avg: {avg_risk:.1f}/10)",
                description=(
                    f"Overall API security risk assessment:\n"
                    f"  Average risk score: {avg_risk:.1f}/10\n"
                    f"  Maximum risk score: {max_risk:.1f}/10\n"
                    f"  Total endpoints analyzed: {len(all_scores)}\n"
                    f"  High-risk endpoints (≥7): {len(high_risk)}\n"
                ),
                severity="info",
                confidence=0.95,
                evidence=[{"type": "posture", "avg": avg_risk, "max": max_risk, "total": len(all_scores)}],
            ))

        return findings

    def _score_to_level(self, score: float) -> str:
        if score >= 9:
            return "critical"
        if score >= 7:
            return "high"
        if score >= 4:
            return "medium"
        if score >= 2:
            return "low"
        return "info"
