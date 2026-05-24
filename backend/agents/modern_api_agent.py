"""
API RIPPER v3.0 — Modern API Attack Agent
Orchestrates all modern vulnerability scanners as a unified agent
in the multi-agent pipeline.

Covers 30+ modern API attack classes including:
- JWT attacks (alg:none, weak HMAC, kid/jku injection)
- BOLA/BFLA/IDOR
- Race conditions
- Mass assignment
- Prototype pollution
- Deserialization
- Request smuggling
- CORS misconfiguration
- File upload attacks
- WebSocket attacks
- Webhook SSRF
- LLM/AI prompt injection
- Hidden/internal APIs
- API versioning issues
- XXE attacks
- CRLF injection
- Parameter pollution
- Advanced SSRF
"""

import asyncio
import logging
import time
from typing import Any, Dict, List

from backend.agents.base_agent import BaseAgent, Finding

logger = logging.getLogger(__name__)

# Each scanner gets a budget that fits within the orchestrator's 300s AGENT_TIMEOUT
# Total: 60 + 60 + 60 + 60 = 240s max, leaving 60s buffer for agent overhead
SCANNER_TIMEOUT = 60


class ModernApiAgent(BaseAgent):
    """
    Modern API Attack Surface Agent.
    Runs all modern API vulnerability scanners and produces findings.
    """
    name = "modern_api_agent"

    async def observe(self) -> Dict[str, Any]:
        """Collect signals from previous agents about the target."""
        signals = self.consume_signals([
            "ENDPOINT_DISCOVERED", "TECH_PROFILE", "OPENAPI_DISCOVERED",
            "BEHAVIORAL_ANOMALY", "INJECTION_DETECTED",
        ])
        
        endpoints = []
        tech_profile = {}
        
        for s in signals:
            if s.type == "ENDPOINT_DISCOVERED":
                endpoints.append(s.data.get("url", ""))
            elif s.type == "TECH_PROFILE":
                tech_profile.update(s.data)
        
        # Also get endpoints from knowledge graph
        kg_endpoints = self.kg.get_all_endpoints()
        for ep in kg_endpoints:
            url = ep.get("url", "")
            if url and url not in endpoints:
                endpoints.append(url)
        
        return {
            "target": self.config["target_url"],
            "endpoints": endpoints[:50],
            "tech_profile": tech_profile,
            "has_jwt": bool(self.config.get("auth_config", {}).get("bearer_token")),
        }

    async def profile(self, observations: Dict) -> Dict[str, Any]:
        """Determine which modern attack modules to run."""
        target = observations["target"]
        tech = observations.get("tech_profile", {})
        
        modules_to_run = [
            "jwt_attacks",
            "bola_bfla",
            "modern_vulns",
            "advanced_attacks",
        ]
        
        # Tech-specific modules
        server = str(tech.get("server", "")).lower()
        framework = str(tech.get("framework", "")).lower()
        
        if "node" in server or "express" in framework or "next" in framework:
            modules_to_run.append("prototype_pollution_focus")
        
        return {
            "target": target,
            "modules": modules_to_run,
            "auth_config": self.config.get("auth_config", {}),
            "tech_profile": tech,
        }

    async def differential_analyze(self, profile: Dict) -> Dict:
        """Pass through — actual analysis happens in infer."""
        return profile

    async def infer(self, profile: Dict) -> List[Finding]:
        """Run all modern API vulnerability scanners."""
        findings = []
        target = profile["target"]
        auth_config = profile.get("auth_config", {})
        options = {
            "timeout": 10,
            "delay_ms": self.config.get("request_delay_ms", 100),
        }

        scanners = [
            ("Advanced JWT Scanner", "backend.arsec_modules.vuln_db.advanced_jwt_attacks", "advanced_jwt_scan"),
            ("BOLA/BFLA Scanner", "backend.arsec_modules.vuln_db.bola_bfla_scanner", "bola_bfla_scan"),
            ("Modern Vulnerability Scanner", "backend.arsec_modules.vuln_db.modern_api_scanner", "modern_vuln_scan"),
            ("Advanced Attack Scanner", "backend.arsec_modules.vuln_db.advanced_attack_scanner", "advanced_attack_scan"),
        ]

        for label, module_path, func_name in scanners:
            try:
                logger.info(f"[{self.name}] Running {label}...")
                module = __import__(module_path, fromlist=[func_name])
                scan_func = getattr(module, func_name)

                results = await asyncio.wait_for(
                    scan_func(target, auth_config, options),
                    timeout=SCANNER_TIMEOUT,
                )
                for r in results:
                    findings.append(self._to_finding(r))
                logger.info(f"[{self.name}] {label}: {len(results)} findings")

            except asyncio.TimeoutError:
                logger.warning(f"[{self.name}] {label} timed out after {SCANNER_TIMEOUT}s")
            except asyncio.CancelledError:
                logger.warning(f"[{self.name}] {label} cancelled (orchestrator timeout)")
                break  # Stop running more scanners — phase is being killed
            except Exception as e:
                logger.error(f"[{self.name}] {label} error: {e}")

        # Emit signals for downstream agents
        for f in findings:
            if f.confidence >= 0.6:
                self.emit_signal("MODERN_VULN_DETECTED", {
                    "type": f.type,
                    "endpoint": f.endpoint,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "category": f.cwe,
                }, confidence=f.confidence)

        return findings

    def _to_finding(self, result: Dict) -> Finding:
        """Convert scanner result dict to Finding dataclass."""
        return Finding(
            type=result.get("type", "unknown"),
            title=result.get("title", ""),
            description=result.get("description", ""),
            severity=result.get("severity", "info"),
            confidence=result.get("confidence", 0.5),
            endpoint=result.get("endpoint", self.config["target_url"]),
            method=result.get("method", "GET"),
            evidence=result.get("evidence", []),
            cwe=result.get("cwe", ""),
            owasp=result.get("owasp", ""),
            remediation=result.get("remediation", ""),
            agent_source=self.name,
        )
