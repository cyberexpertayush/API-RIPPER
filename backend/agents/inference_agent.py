"""
API RIPPER v2.0 — Inference Agent (Decision Maker)
The brain of the system. Receives signals from all agents,
correlates them, forms hypotheses, applies self-critique,
and outputs validated findings with confidence scores.

This agent does NOT make HTTP requests. It reasons over
signals and knowledge graph data produced by other agents.
"""

import logging
from typing import Any, Dict, List
from uuid import uuid4

from backend.agents.base_agent import BaseAgent, Finding, ConfidenceLevel

logger = logging.getLogger(__name__)

# Inference rules: (signal_combination → hypothesis)
INFERENCE_RULES = [
    {
        "name": "unauthenticated_idor",
        "required_signals": ["DIFF_POTENTIAL_IDOR"],
        "optional_signals": ["SENSITIVE_EXPOSURE"],
        "hypothesis_type": "broken_object_level_authorization",
        "base_confidence": 0.65,
        "boost_per_optional": 0.1,
        "severity": "critical",
        "cwe": "CWE-639",
        "owasp": "API1:2023",
    },
    {
        "name": "missing_auth_with_sensitive_data",
        "required_signals": ["DIFF_MISSING_AUTH", "SENSITIVE_EXPOSURE"],
        "optional_signals": ["SCHEMA_INCONSISTENCY"],
        "hypothesis_type": "broken_authentication_with_data_leak",
        "base_confidence": 0.75,
        "boost_per_optional": 0.05,
        "severity": "critical",
        "cwe": "CWE-306",
        "owasp": "API2:2023",
    },
    {
        "name": "fragile_endpoint_with_injection",
        "required_signals": ["FRAGILE_ENDPOINT"],
        "optional_signals": ["LATENCY_ANOMALY", "DIFF_HIDDEN_PARAMETER"],
        "hypothesis_type": "input_validation_weakness",
        "base_confidence": 0.5,
        "boost_per_optional": 0.1,
        "severity": "high",
        "cwe": "CWE-20",
        "owasp": "API8:2023",
    },
    {
        "name": "schema_exposure_chain",
        "required_signals": ["SCHEMA_INCONSISTENCY"],
        "optional_signals": ["SENSITIVE_EXPOSURE", "BEHAVIOR_INCONSISTENCY"],
        "hypothesis_type": "excessive_data_exposure",
        "base_confidence": 0.5,
        "boost_per_optional": 0.1,
        "severity": "medium",
        "cwe": "CWE-200",
        "owasp": "API3:2023",
    },
    {
        "name": "method_tampering_risk",
        "required_signals": ["DIFF_METHOD_TAMPERING"],
        "optional_signals": ["FRAGILE_ENDPOINT"],
        "hypothesis_type": "security_misconfiguration",
        "base_confidence": 0.55,
        "boost_per_optional": 0.1,
        "severity": "medium",
        "cwe": "CWE-650",
        "owasp": "API5:2023",
    },
    {
        "name": "latency_injection_signal",
        "required_signals": ["LATENCY_ANOMALY"],
        "optional_signals": ["FRAGILE_ENDPOINT"],
        "hypothesis_type": "potential_injection",
        "base_confidence": 0.4,
        "boost_per_optional": 0.15,
        "severity": "high",
        "cwe": "CWE-89",
        "owasp": "API8:2023",
    },
    {
        "name": "nosql_injection",
        "required_signals": ["nosql_probe_signal"],
        "optional_signals": ["FRAGILE_ENDPOINT", "LATENCY_ANOMALY"],
        "hypothesis_type": "nosql_injection",
        "base_confidence": 0.7,
        "boost_per_optional": 0.1,
        "severity": "critical",
        "cwe": "CWE-943",
        "owasp": "API8:2023",
    },
    {
        "name": "ssrf_vulnerability",
        "required_signals": ["ssrf_probe_signal"],
        "optional_signals": ["LATENCY_ANOMALY"],
        "hypothesis_type": "server_side_request_forgery",
        "base_confidence": 0.7,
        "boost_per_optional": 0.1,
        "severity": "critical",
        "cwe": "CWE-918",
        "owasp": "API10:2023",
    },
    {
        "name": "parameter_pollution",
        "required_signals": ["DIFF_PARAMETER_POLLUTION"],
        "optional_signals": ["FRAGILE_ENDPOINT"],
        "hypothesis_type": "http_parameter_pollution",
        "base_confidence": 0.6,
        "boost_per_optional": 0.1,
        "severity": "medium",
        "cwe": "CWE-235",
        "owasp": "API8:2023",
    },
    {
        "name": "version_manipulation_bypass",
        "required_signals": ["DIFF_VERSION_MANIPULATION"],
        "optional_signals": ["SCHEMA_INCONSISTENCY"],
        "hypothesis_type": "improper_assets_management",
        "base_confidence": 0.65,
        "boost_per_optional": 0.1,
        "severity": "high",
        "cwe": "CWE-1059",
        "owasp": "API9:2023",
    },
    {
        "name": "lfi_vulnerability",
        "required_signals": ["path_traversal_signal"],
        "optional_signals": ["FRAGILE_ENDPOINT"],
        "hypothesis_type": "local_file_inclusion",
        "base_confidence": 0.75,
        "boost_per_optional": 0.1,
        "severity": "critical",
        "cwe": "CWE-22",
        "owasp": "API8:2023",
    },
    {
        "name": "rce_vulnerability",
        "required_signals": ["cmd_injection_signal"],
        "optional_signals": ["LATENCY_ANOMALY"],
        "hypothesis_type": "remote_code_execution",
        "base_confidence": 0.8,
        "boost_per_optional": 0.1,
        "severity": "critical",
        "cwe": "CWE-78",
        "owasp": "API8:2023",
    },
    {
        "name": "ssti_vulnerability",
        "required_signals": ["ssti_probe_signal"],
        "optional_signals": ["FRAGILE_ENDPOINT"],
        "hypothesis_type": "server_side_template_injection",
        "base_confidence": 0.7,
        "boost_per_optional": 0.1,
        "severity": "critical",
        "cwe": "CWE-1336",
        "owasp": "API8:2023",
    },
    {
        "name": "xxe_vulnerability",
        "required_signals": ["xxe_probe_signal"],
        "optional_signals": ["LATENCY_ANOMALY"],
        "hypothesis_type": "xml_external_entity",
        "base_confidence": 0.7,
        "boost_per_optional": 0.1,
        "severity": "critical",
        "cwe": "CWE-611",
        "owasp": "API8:2023",
    },
    {
        "name": "xss_vulnerability",
        "required_signals": ["xss_probe_signal"],
        "optional_signals": [],
        "hypothesis_type": "cross_site_scripting",
        "base_confidence": 0.6,
        "boost_per_optional": 0.1,
        "severity": "medium",
        "cwe": "CWE-79",
        "owasp": "API8:2023",
    },
]


class InferenceAgent(BaseAgent):
    """
    Inference Agent — The Decision Maker.
    Correlates signals from all other agents to form validated hypotheses.
    """

    name = "inference_agent"

    async def observe(self) -> List:
        """Step 1: Collect all signals from the message bus."""
        signals = self.consume_signals()
        logger.info(f"[inference] Collected {len(signals)} signals")
        return signals

    async def profile(self, signals: List) -> Dict[str, List]:
        """Step 2: Organize signals by type and endpoint."""
        organized = {
            "by_type": {},
            "by_endpoint": {},
        }

        for signal in signals:
            stype = signal.type
            organized["by_type"].setdefault(stype, []).append(signal)

            endpoint = signal.data.get("url", signal.data.get("endpoint", ""))
            if endpoint:
                organized["by_endpoint"].setdefault(endpoint, []).append(signal)

        logger.info(f"[inference] Signal types: {list(organized['by_type'].keys())}")
        return organized

    async def differential_analyze(self, organized: Dict) -> List[Dict]:
        """Step 3: Predictive Attack Engine — rank targets proactively."""
        candidates = []
        by_type = organized.get("by_type", {})
        by_endpoint = organized.get("by_endpoint", {})
        
        endpoints = self.kg.get_all_endpoints()
        data_flows = self.kg.get_data_flows()
        auth_boundaries = self.kg.get_auth_boundaries()

        # Check each inference rule (legacy fallback)
        for rule in INFERENCE_RULES:
            required = rule["required_signals"]
            optional = rule["optional_signals"]

            has_required = all(stype in by_type for stype in required)
            if not has_required:
                continue

            matching_endpoints = set()
            for stype in required:
                for signal in by_type.get(stype, []):
                    ep = signal.data.get("url", signal.data.get("endpoint", ""))
                    if ep:
                        matching_endpoints.add(ep)

            base_conf = rule["base_confidence"]
            optional_count = sum(1 for s in optional if s in by_type)
            confidence = min(1.0, base_conf + optional_count * rule["boost_per_optional"])

            for endpoint in matching_endpoints:
                ep_signals = by_endpoint.get(endpoint, [])
                ep_signal_types = set(s.type for s in ep_signals)

                cross_types = len(ep_signal_types.intersection(set(required + optional)))
                if cross_types >= 2:
                    confidence = min(1.0, confidence + 0.1)

                candidates.append({
                    "rule": rule["name"],
                    "hypothesis_type": rule["hypothesis_type"],
                    "endpoint": endpoint,
                    "confidence": round(confidence, 3),
                    "severity": rule["severity"],
                    "cwe": rule["cwe"],
                    "owasp": rule["owasp"],
                    "supporting_signals": [s.id for s in ep_signals],
                    "signal_types_matched": list(ep_signal_types),
                })

        # Phase 3: Proactive Prediction via Data Flows and Auth Boundaries
        # Predict IDOR / BOLA directly from data flows crossing auth boundaries
        for flow in data_flows:
            # Step 1: Validate Data Flow Tracking (CRITICAL)
            flow_conf = flow.get("confidence", 0.0)
            if flow_conf < 0.6:
                continue # Do not use in prediction if fragile/unrelated
                
            source = flow.get("source")
            target = flow.get("target")
            shared_fields = flow.get("shared_fields", [])
            
            # Look up endpoint objects
            src_ep = next((e for e in endpoints if e["url"] == source), None)
            tgt_ep = next((e for e in endpoints if e["url"] == target), None)
            
            if not src_ep or not tgt_ep:
                continue
                
            # If target requires auth and takes an ID from a public/lower-auth source
            if tgt_ep.get("auth_required") and not src_ep.get("auth_required"):
                # Potential BOLA/IDOR
                candidates.append({
                    "rule": "predictive_bola_flow",
                    "hypothesis_type": "broken_object_level_authorization",
                    "endpoint": target,
                    "confidence": 0.8,
                    "severity": "high",
                    "cwe": "CWE-639",
                    "owasp": "API1:2023",
                    "supporting_signals": [],
                    "signal_types_matched": ["DATA_FLOW_AUTH_CROSSING"],
                    # Step 5: Prediction Evidence Link
                    "supporting_data_flows": [flow],
                    "confidence_breakdown": {"base": 0.8, "flow_confidence": flow_conf}
                })

            # If target is highly sensitive (admin) and data flows from user-controlled endpoint
            if tgt_ep.get("classification") == "admin" and src_ep.get("classification") != "admin":
                candidates.append({
                    "rule": "predictive_privilege_escalation",
                    "hypothesis_type": "broken_function_level_authorization",
                    "endpoint": target,
                    "confidence": 0.85,
                    "severity": "critical",
                    "cwe": "CWE-285",
                    "owasp": "API5:2023",
                    "supporting_signals": [],
                    "signal_types_matched": ["DATA_FLOW_PRIVILEGE_CROSSING"],
                    # Step 5: Prediction Evidence Link
                    "supporting_data_flows": [flow],
                    "confidence_breakdown": {"base": 0.85, "flow_confidence": flow_conf}
                })

        # Rank candidates (highest confidence + severity first)
        severity_weight = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        candidates.sort(key=lambda x: (x["confidence"] * severity_weight.get(x["severity"], 1)), reverse=True)
        
        # Deduplicate on endpoint + hypothesis
        seen = set()
        ranked_candidates = []
        for c in candidates:
            key = f"{c['endpoint']}_{c['hypothesis_type']}"
            if key not in seen:
                seen.add(key)
                ranked_candidates.append(c)

        return ranked_candidates

    async def infer(self, correlations: List[Dict]) -> List[Finding]:
        """Step 4: Convert correlations into validated hypotheses."""
        findings = []

        for corr in correlations:
            # Build detailed description
            desc = self._build_description(corr)

            finding = Finding(
                type=corr["hypothesis_type"],
                title=f"[Inferred] {corr['hypothesis_type'].replace('_', ' ').title()} — {corr['endpoint']}",
                description=desc,
                severity=corr["severity"],
                confidence=corr["confidence"],
                endpoint=corr["endpoint"],
                cwe=corr["cwe"],
                owasp=corr["owasp"],
                supporting_signals=corr.get("supporting_signals", []),
                remediation=self._get_remediation(corr["hypothesis_type"]),
                evidence=[{
                    "type": "inference",
                    "rule": corr["rule"],
                    "signal_types": corr.get("signal_types_matched", []),
                    "confidence_calculation": corr.get("confidence_breakdown", f"base={INFERENCE_RULES[0]['base_confidence']}, boosted by {len(corr.get('signal_types_matched', []))} corroborating signals"),
                    "supporting_data_flows": corr.get("supporting_data_flows", [])
                }],
            )
            findings.append(finding)

            # Emit validated hypothesis signal
            if finding.confidence >= 0.5:
                self.emit_signal("HYPOTHESIS_VALIDATED", {
                    "finding_id": finding.id,
                    "type": finding.type,
                    "endpoint": finding.endpoint,
                    "confidence": finding.confidence,
                    "severity": finding.severity,
                }, confidence=finding.confidence, target="chain_agent", priority=2)

                # Step 6: Prediction Gate Before Exploitation
                # Only signal exploit_agent if confidence >= 0.65 AND we have >= 2 independent signal types (or data flows)
                signal_types_count = len(corr.get("signal_types_matched", []))
                has_data_flow = len(corr.get("supporting_data_flows", [])) > 0
                
                # Treat a validated data flow as an independent signal type
                effective_signal_count = signal_types_count + (1 if has_data_flow else 0)

                if finding.confidence >= 0.65 and effective_signal_count >= 2:
                    self.emit_signal("HYPOTHESIS_VALIDATED", {
                        "finding_id": finding.id,
                        "type": finding.type,
                        "endpoint": finding.endpoint,
                        "confidence": finding.confidence,
                        "severity": finding.severity,
                    }, confidence=finding.confidence, target="exploit_agent", priority=1)
                else:
                    logger.info(f"[Prediction Gate] Blocked {finding.type} on {finding.endpoint} from reaching exploit_agent (conf={finding.confidence}, signals={effective_signal_count})")

        return findings

    def _build_description(self, corr: Dict) -> str:
        lines = [
            f"Multi-signal inference detected {corr['hypothesis_type'].replace('_', ' ')} on {corr['endpoint']}.",
            f"",
            f"Evidence basis: {len(corr['supporting_signals'])} supporting signals across {len(corr['signal_types_matched'])} detection categories.",
            f"Signal categories: {', '.join(corr['signal_types_matched'])}.",
            f"Confidence: {corr['confidence']:.0%} ({ConfidenceLevel.from_score(corr['confidence']).value}).",
            f"",
            f"This finding was NOT based on a single test. It was inferred from correlated observations across multiple analysis agents.",
        ]
        return "\n".join(lines)

    def _get_remediation(self, hypothesis_type: str) -> str:
        remediations = {
            "broken_object_level_authorization": "Implement object-level authorization checks. Verify the requesting user owns the resource. Use UUIDs instead of sequential IDs.",
            "broken_authentication_with_data_leak": "Enforce authentication on all data endpoints. Audit which endpoints expose sensitive data. Implement token validation middleware.",
            "input_validation_weakness": "Implement strict input validation. Use allowlists for expected values. Return 400 for invalid input, never 500.",
            "excessive_data_exposure": "Standardize response schemas. Use DTOs/serializers. Implement field-level access control.",
            "security_misconfiguration": "Explicitly whitelist allowed HTTP methods. Enable CORS only for required origins. Remove debug endpoints.",
            "potential_injection": "Use parameterized queries. Implement input sanitization. Deploy WAF rules for injection patterns.",
            "nosql_injection": "Use parameterized queries for NoSQL databases. Avoid passing user input to query operators ($gt, $ne, $where). Validate input types strictly.",
            "server_side_request_forgery": "Validate and sanitize all URLs. Use allowlists for permitted domains. Block requests to internal/private IP ranges (127.0.0.1, 169.254.x.x, 10.x.x.x).",
            "local_file_inclusion": "Never pass user input to file operations. Use allowlists for permitted files. Disable directory traversal sequences. Chroot file access.",
            "remote_code_execution": "Never pass user input to system commands. Use safe APIs instead of shell execution. Implement strict input validation and sandboxing.",
            "server_side_template_injection": "Never pass user input into template engines. Use sandboxed template environments. Escape all dynamic content before rendering.",
            "xml_external_entity": "Disable external entity processing in XML parsers. Use JSON instead of XML where possible. Configure parsers with XXE protection.",
            "cross_site_scripting": "Encode all output. Implement Content-Security-Policy headers. Use context-aware output encoding. Sanitize HTML input.",
            "http_parameter_pollution": "Implement strict parameter parsing. Reject duplicate parameters. Use framework-level parameter validation.",
            "improper_assets_management": "Remove or restrict access to old API versions. Implement API versioning governance. Monitor for deprecated endpoint access.",
            "broken_function_level_authorization": "Implement role-based access control (RBAC). Deny by default. Verify user roles on every admin endpoint request.",
        }
        return remediations.get(hypothesis_type, "Review and remediate the identified weakness.")
