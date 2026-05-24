"""
API RIPPER v2.0 — Chain Analysis Agent (Elite Level)
Builds multi-step attack paths from validated hypotheses using
the standardized AttackPattern library, creating executable chains.
"""

import logging
from typing import Any, Dict, List
from uuid import uuid4

from backend.agents.base_agent import BaseAgent, Finding
from backend.agents.attack_patterns import ATTACK_PATTERNS, AttackPattern

logger = logging.getLogger(__name__)

class ChainAgent(BaseAgent):
    """
    Chain Analysis Agent.
    Builds executable multi-step attack paths from validated hypotheses.
    """

    name = "chain_agent"

    async def observe(self) -> List:
        """Step 1: Collect validated hypotheses and logic bypasses."""
        signals = self.consume_signals(["HYPOTHESIS_VALIDATED", "WORKFLOW_BYPASS"])
        logger.info(f"[chain] Collected {len(signals)} validated signals")
        return signals

    async def profile(self, signals: List) -> Dict[str, List]:
        """Step 2: Organize hypotheses by type and endpoint."""
        organized = {"by_type": {}, "by_endpoint": {}, "all": []}

        for signal in signals:
            data = signal.data
            ftype = data.get("type", "")
            if not ftype: # fallback for workflow bypasses
                ftype = signal.type.lower()
            endpoint = data.get("endpoint", "")

            organized["by_type"].setdefault(ftype, []).append(data)
            organized["by_endpoint"].setdefault(endpoint, []).append(data)
            organized["all"].append(data)

        return organized

    async def differential_analyze(self, organized: Dict) -> List[Dict]:
        """Step 3: Match hypotheses against ATTACK_PATTERNS to build executable chains."""
        chains = []
        by_type = organized.get("by_type", {})
        all_findings = organized.get("all", [])

        if not all_findings:
            return chains

        for pattern_id, pattern in ATTACK_PATTERNS.items():
            # Check required types
            has_required = all(
                ftype in by_type for ftype in pattern.required_signals
            )
            if not has_required:
                continue

            # Collect matching findings
            chain_findings = []
            for ftype in pattern.required_signals + pattern.optional_signals:
                for finding in by_type.get(ftype, []):
                    chain_findings.append(finding)

            if not chain_findings:
                continue

            # Calculate chain confidence
            confidences = [f.get("confidence", 0.5) for f in chain_findings]
            avg_conf = sum(confidences) / len(confidences)
            chain_confidence = min(1.0, avg_conf + 0.05 * (len(chain_findings) - 1))

            chain = {
                "id": str(uuid4()),
                "pattern_id": pattern.id,
                "name": pattern.name,
                "description": pattern.description,
                "total_confidence": round(chain_confidence, 3),
                "impact": pattern.impact,
                "execution_steps": pattern.execution_steps,
                "finding_ids": [f.get("finding_id") for f in chain_findings if f.get("finding_id")],
                "endpoints_involved": list(set(f.get("endpoint", "") for f in chain_findings if f.get("endpoint"))),
            }
            chains.append(chain)

        # Sort by impact × confidence
        impact_weight = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        chains.sort(
            key=lambda c: impact_weight.get(c["impact"], 1) * c["total_confidence"],
            reverse=True,
        )

        return chains

    async def infer(self, chains: List[Dict]) -> List[Finding]:
        """Step 4: Convert executable chains into findings."""
        findings = []

        for chain in chains:
            steps_desc = "\n".join(
                f"  Step {i+1}: {s['action']} - {s['description']}"
                for i, s in enumerate(chain["execution_steps"])
            )

            finding = Finding(
                type=f"exploit_chain_{chain['pattern_id']}",
                title=f"Executable Attack Chain: {chain['name']}",
                description=(
                    f"Executable multi-step attack path identified with {chain['total_confidence']:.0%} confidence.\n\n"
                    f"{chain['description']}\n\n"
                    f"Impact: {chain['impact'].upper()}\n"
                    f"Endpoints: {', '.join(chain['endpoints_involved'])}\n\n"
                    f"Execution Blueprint:\n{steps_desc}"
                ),
                severity=chain["impact"],
                confidence=chain["total_confidence"],
                endpoint=chain["endpoints_involved"][0] if chain["endpoints_involved"] else "",
                chain_id=chain["id"],
                supporting_signals=chain["finding_ids"],
                remediation="Address the underlying vulnerabilities that allow this chain to execute.",
                evidence=[{
                    "type": "executable_chain",
                    "chain": chain,
                }],
            )
            findings.append(finding)

            # Emit chain signal for ExploitAgent (it will actually execute these steps)
            self.emit_signal("CHAIN_CONSTRUCTED", chain, confidence=chain["total_confidence"], priority=1)

        return findings
