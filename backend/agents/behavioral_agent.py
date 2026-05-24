"""
API RIPPER v2.0 — Behavioral Analysis Agent
Builds per-endpoint behavioral models, detects anomalies, maps error surfaces.

OBSERVE: Send controlled probes to every discovered endpoint
PROFILE: Build status/latency/size distributions per endpoint
DIFF:    Detect behavioral anomalies (error spikes, latency shifts)
INFER:   Identify fragile endpoints, poor input validation, hidden logic
"""

import asyncio
import logging
import statistics
import time
from typing import Any, Dict, List
from uuid import uuid4

import aiohttp

from backend.agents.base_agent import BaseAgent, Finding

logger = logging.getLogger(__name__)

# Base Probe inputs to test endpoint stability
BASE_PROBE_INPUTS = [
    {"type": "normal", "params": {}},
    {"type": "empty_string", "params": {"id": ""}},
    {"type": "zero", "params": {"id": "0"}},
    {"type": "negative", "params": {"id": "-1"}},
    {"type": "large_number", "params": {"id": "99999999999999999999"}},
    {"type": "string_in_int", "params": {"id": "abc"}},
    {"type": "special_chars", "params": {"id": "<>'\"%00{}[]()$&"}},
    {"type": "long_string", "params": {"id": "A" * 5000}},
    {"type": "null_byte", "params": {"id": "%00"}},
    {"type": "mass_assignment", "params": {"id": "1", "admin": "true", "role": "admin", "is_admin": True}},
]

class BehavioralAgent(BaseAgent):
    """
    Analyzes how endpoints respond to various inputs.
    Dynamically loads weaponized payloads based on tech profile.
    """
    name = "behavioral_agent"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.dynamic_probes = []

    async def _load_dynamic_probes(self):
        """Load targeted payloads via PayloadManager."""
        from backend.agents.payload_manager import PayloadManager
        
        tech_profile = {}
        if hasattr(self, 'kg'):
            tech_profile = self.kg.get_global_context().get("technology_profile", {})
        pm = PayloadManager(tech_profile)
        
        self.dynamic_probes = list(BASE_PROBE_INPUTS)
        
        # Load small sets for behavior phase to avoid overloading
        for p in await pm.get_payloads("sqli", limit=5): self.dynamic_probes.append({"type": "sql_probe", "params": {"id": p}})
        for p in await pm.get_payloads("nosqli", limit=3): self.dynamic_probes.append({"type": "nosql_probe", "params": {"id": p}})
        for p in await pm.get_payloads("ssrf", limit=3): self.dynamic_probes.append({"type": "ssrf_probe", "params": {"id": p}})
        for p in await pm.get_payloads("lfi", limit=3): self.dynamic_probes.append({"type": "path_traversal", "params": {"id": p}})
        for p in await pm.get_payloads("cmd_injection", limit=3): self.dynamic_probes.append({"type": "cmd_injection", "params": {"id": p}})
        for p in await pm.get_payloads("ssti", limit=3): self.dynamic_probes.append({"type": "ssti_probe", "params": {"id": p}})
        for p in await pm.get_payloads("xxe", limit=2): self.dynamic_probes.append({"type": "xxe_probe", "params": {"id": p}})
        for p in await pm.get_payloads("xss", limit=3): self.dynamic_probes.append({"type": "xss_probe", "params": {"id": p}})
        
    async def observe(self) -> Dict[str, List[Dict]]:
        """Step 1: Send controlled probes to all discovered endpoints using dynamic payloads."""
        endpoints = self.kg.get_all_endpoints()
        observations = {}
        await self._load_dynamic_probes()

        if not endpoints:
            logger.info("[behavioral] No endpoints to profile")
            return observations

        target = self.config["target_url"]
        auth_config = self.config.get("auth_config", {})
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        if auth_config.get("bearer_token"):
            headers["Authorization"] = f"Bearer {auth_config['bearer_token']}"
        if auth_config.get("api_key"):
            headers["X-API-Key"] = auth_config["api_key"]

        timeout = aiohttp.ClientTimeout(sock_read=10, sock_connect=5)
        connector = aiohttp.TCPConnector(ssl=False, limit=5)
        semaphore = asyncio.Semaphore(5)  # Limit concurrent endpoint profiling

        async def _profile_endpoint(session, ep):
            url = ep["url"]
            probes = []
            consecutive_failures = 0

            async with semaphore:
                # Send baseline probes
                for i in range(3):
                    await self.rate_limited_delay()
                    result = await self._probe_endpoint(session, url, {})
                    if result:
                        result["probe_type"] = "baseline"
                        probes.append(result)
                        if result.get("status") in (404, 0):
                            consecutive_failures += 1

                # F15: Skip dead endpoints early
                if consecutive_failures >= 3:
                    logger.debug(f"[behavioral] Skipping dead endpoint {url} (3 consecutive failures)")
                    return url, probes

                # F10: Use KG-discovered parameter names instead of hardcoded 'id'
                endpoint_data = self.kg.get_endpoint(url) or {}
                kg_params = endpoint_data.get("parameters", {})
                real_param_names = list(kg_params.keys()) if kg_params else ["id"]
                primary_param = real_param_names[0] if real_param_names else "id"

                # Remap dynamic probes to use real parameter names
                adapted_probes = []
                for probe_input in self.dynamic_probes:
                    adapted = dict(probe_input)
                    if "params" in adapted and "id" in adapted["params"]:
                        # Replace 'id' with real param name
                        new_params = {}
                        for k, v in adapted["params"].items():
                            if k == "id":
                                new_params[primary_param] = v
                            else:
                                new_params[k] = v
                        adapted["params"] = new_params
                    adapted_probes.append(adapted)

                # Send variation probes with KG-aware params
                for probe_input in adapted_probes:
                    await self.rate_limited_delay()
                    result = await self._probe_endpoint(session, url, probe_input["params"])
                    if result:
                        result["probe_type"] = probe_input["type"]
                        # F9: Track which specific payload caused crashes
                        if result.get("status") == 500:
                            result["crash_payload"] = probe_input["params"]
                            result["crash_type"] = probe_input["type"]
                        probes.append(result)

            return url, probes

        async with aiohttp.ClientSession(timeout=timeout, headers=headers, connector=connector) as session:
            tasks = [_profile_endpoint(session, ep) for ep in endpoints[:50]]
            results = await asyncio.gather(*tasks)
            
            for url, probes in results:
                if probes:
                    observations[url] = probes

        return observations

    async def profile(self, observations: Dict[str, List[Dict]]) -> Dict[str, Dict]:
        """Step 2: Build behavioral profiles from probe results."""
        profiles = {}

        for url, probes in observations.items():
            if not probes:
                continue

            statuses = [p["status"] for p in probes if "status" in p]
            latencies = [p["latency_ms"] for p in probes if "latency_ms" in p]
            sizes = [p["body_length"] for p in probes if "body_length" in p]
            error_probes = [p for p in probes if p.get("status", 200) >= 400]

            # Status distribution
            status_dist = {}
            for s in statuses:
                status_dist[str(s)] = status_dist.get(str(s), 0) + 1
            total = len(statuses) or 1
            status_pct = {k: round(v / total, 2) for k, v in status_dist.items()}

            # Latency stats
            avg_latency = statistics.mean(latencies) if latencies else 0
            latency_std = statistics.stdev(latencies) if len(latencies) > 1 else 0

            # Size stats
            size_range = [min(sizes), max(sizes)] if sizes else [0, 0]

            # Stability score (0.0 = very unstable, 1.0 = perfectly stable)
            error_rate = len(error_probes) / total
            stability = max(0.0, 1.0 - error_rate)

            # Error triggers
            error_triggers = [
                p["probe_type"] for p in probes
                if p.get("status", 200) >= 500 and p.get("probe_type") != "baseline"
            ]

            # F9: Map specific payloads to 500 crashes (evidence for injection signals)
            crash_payloads = [
                {"type": p.get("crash_type", p["probe_type"]), "payload": p.get("crash_payload", {}), "status": p["status"]}
                for p in probes
                if p.get("status", 200) >= 500 and p.get("probe_type") != "baseline"
            ]

            profile = {
                "status_distribution": status_pct,
                "avg_latency_ms": round(avg_latency, 2),
                "latency_stddev_ms": round(latency_std, 2),
                "response_size_range": size_range,
                "stability_score": round(stability, 3),
                "error_rate": round(error_rate, 3),
                "error_triggers": list(set(error_triggers)),
                "crash_payloads": crash_payloads,
                "total_probes": len(probes),
                "error_probes": len(error_probes),
            }

            profiles[url] = profile

            # Update Knowledge Graph
            self.kg.add_endpoint(
                url=url, method="GET", source_agent=self.name, confidence=0.8,
                behavior_profile=profile,
                stability_score=stability,
                error_triggers=error_triggers,
            )

            # Emit signals for unstable endpoints
            if stability < 0.5:
                self.emit_signal("FRAGILE_ENDPOINT", {
                    "url": url,
                    "stability_score": stability,
                    "error_triggers": error_triggers,
                    "error_rate": error_rate,
                }, confidence=0.8, priority=3)

            # Emit latency anomaly signals
            baseline_probes = [p for p in probes if p.get("probe_type") == "baseline"]
            baseline_latency = statistics.mean([p["latency_ms"] for p in baseline_probes]) if baseline_probes else avg_latency

            for p in probes:
                if p.get("probe_type") != "baseline" and p.get("latency_ms", 0) > baseline_latency * 3:
                    self.emit_signal("LATENCY_ANOMALY", {
                        "url": url,
                        "probe_type": p["probe_type"],
                        "latency_ms": p["latency_ms"],
                        "baseline_ms": round(baseline_latency, 2),
                        "multiplier": round(p["latency_ms"] / max(baseline_latency, 1), 2),
                    }, confidence=0.6, priority=4)

        return profiles

    async def differential_analyze(self, profiles: Dict[str, Dict]) -> List[Dict]:
        """Step 3: Detect behavioral anomalies across endpoint groups."""
        diffs = []

        # Compare stability across endpoint clusters
        clusters = self.kg.get_clusters()
        for cluster_name, urls in clusters.items():
            cluster_stabilities = []
            for url in urls:
                ep = self.kg.get_endpoint(url)
                if ep and ep.get("stability_score") is not None:
                    cluster_stabilities.append((url, ep["stability_score"]))

            if len(cluster_stabilities) >= 2:
                scores = [s for _, s in cluster_stabilities]
                if max(scores) - min(scores) > 0.4:
                    diffs.append({
                        "type": "stability_inconsistency",
                        "cluster": cluster_name,
                        "endpoints": cluster_stabilities,
                        "variance": round(max(scores) - min(scores), 3),
                    })

                    self.emit_signal("BEHAVIOR_INCONSISTENCY", {
                        "cluster": cluster_name,
                        "endpoints": cluster_stabilities,
                    }, confidence=0.6)

        return diffs

    async def infer(self, diffs: Any) -> List[Finding]:
        """Step 4: Generate findings from behavioral analysis."""
        findings = []

        for ep in self.kg.get_all_endpoints():
            url = ep["url"]
            profile = ep.get("behavior_profile", {})
            if not profile:
                continue

            stability = profile.get("stability_score", 1.0)
            error_triggers = profile.get("error_triggers", [])

            # Finding: Fragile endpoint (high error rate)
            if stability < 0.4:
                findings.append(Finding(
                    type="fragile_endpoint",
                    title=f"Fragile Endpoint: {url}",
                    description=f"Endpoint has stability score of {stability:.0%}. Error triggers: {', '.join(error_triggers) or 'various inputs'}. Poor input validation creates attack surface.",
                    severity="medium",
                    confidence=0.7,
                    endpoint=url,
                    cwe="CWE-20",
                    owasp="API8:2023",
                    remediation="Implement proper input validation. Return 400 for invalid input instead of 500.",
                    evidence=[{"type": "behavior_profile", "profile": profile}],
                ))

            # Finding: Injection probes cause error
            injection_types = {
                "sql_probe": ("SQL Injection", "CWE-89"),
                "sql_probe_err": ("SQL Injection (Error Based)", "CWE-89"),
                "nosql_probe": ("NoSQL Injection", "CWE-943"),
                "cmd_injection": ("Command Injection", "CWE-78"),
                "ssti_probe": ("Server-Side Template Injection", "CWE-1336"),
                "path_traversal": ("Path Traversal", "CWE-22"),
                "ssrf_probe": ("Server-Side Request Forgery", "CWE-918"),
                "xxe_probe": ("XML External Entity", "CWE-611"),
                "xss_probe": ("Cross-Site Scripting", "CWE-79"),
            }
            
            for trigger, (vuln_name, cwe) in injection_types.items():
                if trigger in error_triggers:
                    findings.append(Finding(
                        type=f"{trigger}_signal",
                        title=f"{vuln_name} Signal: {url}",
                        description=f"Endpoint returns 500 error when {vuln_name} payload is injected. This is a strong signal for {vuln_name} vulnerability.",
                        severity="high",
                        confidence=0.6,
                        endpoint=url,
                        cwe=cwe,
                        owasp="API8:2023",
                        remediation=f"Implement strict input validation and use safe APIs for {vuln_name} prevention.",
                        evidence=[{"type": "error_trigger", "trigger": trigger}],
                    ))
                    # CRITICAL: Emit signal so InferenceAgent can correlate it
                    self.emit_signal(f"{trigger}_signal", {
                        "url": url,
                        "type": f"{trigger}_signal",
                        "trigger": trigger,
                        "vulnerability": vuln_name,
                        "cwe": cwe,
                        "crash_payloads": profile.get("crash_payloads", []),
                    }, confidence=0.6, priority=2)

            # Finding: Latency anomaly on special input
            if profile.get("latency_stddev_ms", 0) > 500:
                findings.append(Finding(
                    type="latency_anomaly",
                    title=f"High Latency Variance: {url}",
                    description=f"Endpoint shows high latency variance ({profile['latency_stddev_ms']:.0f}ms stddev). May indicate backend processing differences based on input.",
                    severity="low",
                    confidence=0.4,
                    endpoint=url,
                    evidence=[{"type": "latency", "avg": profile["avg_latency_ms"], "stddev": profile["latency_stddev_ms"]}],
                ))

        # Findings from differential analysis
        for diff in diffs:
            if diff["type"] == "stability_inconsistency":
                findings.append(Finding(
                    type="inconsistent_stability",
                    title=f"Inconsistent Stability in '{diff['cluster']}' cluster",
                    description=f"Endpoints in the same cluster show different stability ({diff['variance']:.0%} variance). May indicate inconsistent error handling or different backend services.",
                    severity="low",
                    confidence=0.5,
                    evidence=[{"type": "cluster_diff", "data": diff}],
                ))

        return findings

    # ── Internal Methods ────────────────────────────────────

    async def _probe_endpoint(self, session, url: str, params: dict) -> dict:
        """Send a single probe and capture response details."""
        try:
            start = time.time()
            async with session.get(url, params=params if params else None) as resp:
                body = await resp.text(errors="replace")
                latency = (time.time() - start) * 1000
                return {
                    "status": resp.status,
                    "latency_ms": round(latency, 2),
                    "body_length": len(body),
                    "content_type": resp.headers.get("content-type", ""),
                    "has_error_body": any(kw in body.lower() for kw in ["error", "exception", "traceback", "stack"]),
                }
        except asyncio.TimeoutError:
            return {"status": 0, "latency_ms": 10000, "body_length": 0, "error": "timeout"}
        except Exception as e:
            return {"status": 0, "latency_ms": 0, "body_length": 0, "error": str(e)}
