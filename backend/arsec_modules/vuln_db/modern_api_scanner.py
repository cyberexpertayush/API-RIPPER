"""
API RIPPER v3.0 — Prototype Pollution + Deserialization + CORS Advanced Scanner
"""
import asyncio, json, logging, time, re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
import aiohttp

logger = logging.getLogger(__name__)

async def modern_vuln_scan(target_url: str, auth_config: dict = None, options: dict = None) -> List[Dict]:
    scanner = ModernVulnScanner(target_url, auth_config or {}, options or {})
    return await scanner.scan()

class ModernVulnScanner:
    def __init__(self, target_url, auth_config, options):
        self.target_url = target_url.rstrip('/')
        self.auth_config = auth_config
        self.findings = []
        self.timeout = aiohttp.ClientTimeout(total=options.get("timeout", 15))
        self._delay = options.get("delay_ms", 100) / 1000.0

    def _headers(self):
        h = {"User-Agent": "Mozilla/5.0", "Accept": "application/json, */*"}
        if self.auth_config.get("bearer_token"): h["Authorization"] = f"Bearer {self.auth_config['bearer_token']}"
        if self.auth_config.get("api_key"): h["X-API-Key"] = self.auth_config["api_key"]
        return h

    async def scan(self):
        connector = aiohttp.TCPConnector(ssl=False, limit=5)
        try:
            async with aiohttp.ClientSession(timeout=self.timeout, headers=self._headers(), connector=connector) as s:
                await self._test_prototype_pollution(s)
                await self._test_cors_advanced(s)
                await self._test_deserialization(s)
                await self._test_parameter_pollution(s)
                await self._test_http_method_attacks(s)
                await self._test_crlf_injection(s)
                await self._test_ssrf_advanced(s)
        except asyncio.CancelledError:
            logger.warning("[modern_scanner] Cancelled — returning partial results")
        except Exception as e:
            logger.error(f"[modern_scanner] Error: {e}")
        return self.findings

    async def _req(self, session, method, url, headers=None, body=None, ct=None):
        try:
            kw = {}
            if headers: kw["headers"] = headers
            if body:
                kw["data"] = body
                if ct: kw["headers"] = {**kw.get("headers", {}), "Content-Type": ct}
            start = time.time()
            fn = getattr(session, method.lower(), session.get)
            async with fn(url, **kw) as r:
                b = await r.text(errors="replace")
                return {"status": r.status, "body": b[:500], "body_length": len(b), "headers": dict(r.headers), "latency_ms": round((time.time()-start)*1000,2)}
        except: return None

    async def _test_prototype_pollution(self, session):
        """Test Node.js prototype pollution via __proto__ and constructor."""
        from backend.agents.modern_payloads import PROTOTYPE_POLLUTION_PAYLOADS, PROTOTYPE_POLLUTION_QUERY_PARAMS
        evidence = []
        parsed = urlparse(self.target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        test_endpoints = [self.target_url, f"{base}/api/v1/users", f"{base}/api/v1/settings", f"{base}/api/v1/profile"]

        for ep in test_endpoints:
            # JSON body pollution
            for payload in PROTOTYPE_POLLUTION_PAYLOADS[:6]:
                await asyncio.sleep(self._delay)
                r = await self._req(session, "POST", ep, body=json.dumps(payload), ct="application/json")
                if r and r["status"] in (200, 201):
                    body = r["body"].lower()
                    if "polluted" in body or "prototype_pollution_detected" in body:
                        evidence.append({"technique": "json_body_pollution", "payload": str(payload)[:100], "endpoint": ep, "status": r["status"]})
                        break
                    # Check if server error reveals pollution
                    if r["status"] == 500 and any(x in body for x in ["__proto__", "prototype", "constructor"]):
                        evidence.append({"technique": "pollution_error", "payload": str(payload)[:100], "endpoint": ep})

            # Query param pollution
            for qp in PROTOTYPE_POLLUTION_QUERY_PARAMS[:3]:
                sep = "&" if "?" in ep else "?"
                await asyncio.sleep(self._delay)
                r = await self._req(session, "GET", f"{ep}{sep}{qp}")
                if r and r["status"] == 200 and "polluted" in r["body"].lower():
                    evidence.append({"technique": "query_param_pollution", "param": qp, "endpoint": ep})

            # Merge pollution (common in Express.js)
            merge_payload = json.dumps({"__proto__": {"isAdmin": True}, "constructor": {"prototype": {"polluted": True}}})
            await asyncio.sleep(self._delay)
            r = await self._req(session, "PUT", ep, body=merge_payload, ct="application/json")
            if r and r["status"] in (200, 201):
                # Re-fetch to check if pollution persisted
                await asyncio.sleep(self._delay)
                r2 = await self._req(session, "GET", ep)
                if r2 and ("isadmin" in r2["body"].lower() or "polluted" in r2["body"].lower()):
                    evidence.append({"technique": "merge_pollution_persisted", "endpoint": ep})

        if evidence:
            self.findings.append({
                "type": "prototype_pollution", "title": "Prototype Pollution Vulnerability",
                "description": f"Prototype pollution detected via {len(evidence)} vectors. Node.js APIs are especially vulnerable.",
                "severity": "high", "confidence": 0.75, "endpoint": evidence[0]["endpoint"],
                "cwe": "CWE-1321", "owasp": "API8:2023",
                "remediation": "Sanitize JSON input. Use Object.create(null). Block __proto__ and constructor.prototype in input. Use schema validation.",
                "evidence": evidence, "category": "Prototype Pollution",
            })

    async def _test_cors_advanced(self, session):
        """Advanced CORS misconfiguration testing."""
        from backend.agents.modern_payloads import CORS_ORIGINS
        evidence = []
        parsed = urlparse(self.target_url)
        domain = parsed.netloc

        # Additional domain-specific bypasses
        origins = CORS_ORIGINS + [
            f"https://{domain}.evil.com", f"https://evil-{domain}", f"https://{domain}%60.evil.com",
        ]

        for origin in origins:
            await asyncio.sleep(self._delay)
            r = await self._req(session, "GET", self.target_url, headers={"Origin": origin})
            if not r: continue
            acao = r["headers"].get("access-control-allow-origin", "")
            acac = r["headers"].get("access-control-allow-credentials", "").lower()

            dangerous = False
            if acao == origin: dangerous = True
            elif acao == "*": dangerous = True
            elif origin == "null" and acao == "null": dangerous = True

            if dangerous:
                sev = "critical" if acac == "true" else "high"
                evidence.append({
                    "origin": origin, "acao": acao, "credentials": acac == "true", "severity": sev,
                })

        if evidence:
            worst = max(evidence, key=lambda e: {"critical": 2, "high": 1}.get(e["severity"], 0))
            self.findings.append({
                "type": "cors_misconfiguration", "title": "CORS Misconfiguration — Credential Theft Risk",
                "description": f"Dangerous CORS policy detected. {len(evidence)} origins reflected. Credentials allowed: {worst['credentials']}.",
                "severity": worst["severity"], "confidence": 0.9, "endpoint": self.target_url,
                "cwe": "CWE-942", "owasp": "API7:2023",
                "remediation": "Whitelist specific origins. Never reflect arbitrary origins with credentials. Use Access-Control-Allow-Origin with specific domains only.",
                "evidence": evidence, "category": "CORS Misconfiguration",
            })

    async def _test_deserialization(self, session):
        """Test deserialization vulnerabilities (Java, YAML, PHP, .NET)."""
        from backend.agents.modern_payloads import PHP_SERIALIZE_PAYLOADS, YAML_PAYLOADS, DOTNET_PAYLOADS
        evidence = []
        parsed = urlparse(self.target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        eps = [self.target_url, f"{base}/api/v1/import", f"{base}/api/v1/upload", f"{base}/api/v1/data"]

        for ep in eps:
            # PHP deserialization
            for payload in PHP_SERIALIZE_PAYLOADS[:2]:
                await asyncio.sleep(self._delay)
                r = await self._req(session, "POST", ep, body=payload, ct="application/x-www-form-urlencoded")
                if r and r["status"] in (200, 500):
                    if any(x in r["body"].lower() for x in ["unserialize", "object injection", "stdclass"]):
                        evidence.append({"technique": "php_deserialize", "endpoint": ep, "status": r["status"]})

            # YAML deserialization
            for payload in YAML_PAYLOADS[:2]:
                await asyncio.sleep(self._delay)
                r = await self._req(session, "POST", ep, body=payload, ct="application/x-yaml")
                if r:
                    if r["status"] == 500 and any(x in r["body"].lower() for x in ["yaml", "constructor", "unsafe_load"]):
                        evidence.append({"technique": "yaml_deserialize", "endpoint": ep, "payload": payload[:50]})
                    elif r["status"] == 200 and ("uid=" in r["body"] or "root:" in r["body"]):
                        evidence.append({"technique": "yaml_rce", "endpoint": ep, "severity": "critical"})

            # JSON .NET TypeNameHandling
            for payload in DOTNET_PAYLOADS[:1]:
                await asyncio.sleep(self._delay)
                r = await self._req(session, "POST", ep, body=payload, ct="application/json")
                if r and r["status"] == 500 and any(x in r["body"].lower() for x in ["typeload", "deserialization", "system.runtime"]):
                    evidence.append({"technique": "dotnet_deserialize", "endpoint": ep})

        if evidence:
            sev = "critical" if any(e.get("severity") == "critical" or e["technique"] == "yaml_rce" for e in evidence) else "high"
            self.findings.append({
                "type": "deserialization_vuln", "title": "Insecure Deserialization Detected",
                "description": f"Deserialization vulnerability found via {len(evidence)} vectors. Potential for RCE.",
                "severity": sev, "confidence": 0.7, "endpoint": evidence[0]["endpoint"],
                "cwe": "CWE-502", "owasp": "API8:2023",
                "remediation": "Never deserialize untrusted data. Use safe parsers (json.loads, yaml.safe_load). Disable TypeNameHandling in .NET. Validate input schemas.",
                "evidence": evidence, "category": "Deserialization",
            })

    async def _test_parameter_pollution(self, session):
        """HTTP Parameter Pollution testing."""
        from backend.agents.modern_payloads import HPP_PAYLOADS
        evidence = []
        for dup in HPP_PAYLOADS["duplicate_params"][:3]:
            sep = "&" if "?" in self.target_url else "?"
            await asyncio.sleep(self._delay)
            r = await self._req(session, "GET", f"{self.target_url}{sep}{dup}")
            if r and r["status"] == 200:
                evidence.append({"technique": "hpp", "params": dup, "status": r["status"]})

        for override in HPP_PAYLOADS["method_override"][:3]:
            if isinstance(override, dict):
                await asyncio.sleep(self._delay)
                r = await self._req(session, "POST", self.target_url, headers=override)
                if r and r["status"] in (200, 204):
                    evidence.append({"technique": "method_override", "header": override, "status": r["status"]})

        if evidence:
            self.findings.append({
                "type": "parameter_pollution", "title": "HTTP Parameter Pollution",
                "description": f"Parameter pollution accepted. {len(evidence)} vectors confirmed.",
                "severity": "medium", "confidence": 0.6, "endpoint": self.target_url,
                "cwe": "CWE-235", "owasp": "API8:2023",
                "remediation": "Use strict parameter parsing. Reject duplicate parameters. Block method override headers.",
                "evidence": evidence, "category": "Parameter Pollution",
            })

    async def _test_http_method_attacks(self, session):
        """Test dangerous HTTP methods."""
        evidence = []
        for method in ["TRACE", "TRACK", "DEBUG", "CONNECT"]:
            await asyncio.sleep(self._delay)
            try:
                async with session.request(method, self.target_url) as r:
                    if r.status in (200, 405) and method in ["TRACE", "TRACK"]:
                        body = await r.text(errors="replace")
                        if r.status == 200 and ("TRACE" in body or "TRACK" in body):
                            evidence.append({"method": method, "status": r.status, "reflected": True})
            except: continue

        if evidence:
            self.findings.append({
                "type": "dangerous_http_methods", "title": "Dangerous HTTP Methods Enabled",
                "description": f"TRACE/TRACK methods enabled — vulnerable to XST (Cross-Site Tracing).",
                "severity": "medium", "confidence": 0.8, "endpoint": self.target_url,
                "cwe": "CWE-16", "owasp": "API7:2023",
                "remediation": "Disable TRACE, TRACK, DEBUG methods on the web server.",
                "evidence": evidence, "category": "HTTP Methods",
            })

    async def _test_crlf_injection(self, session):
        """Test CRLF injection in headers."""
        from backend.agents.modern_payloads import CRLF_PAYLOADS
        evidence = []
        for payload in CRLF_PAYLOADS[:4]:
            sep = "&" if "?" in self.target_url else "?"
            url = f"{self.target_url}{sep}param={payload}"
            await asyncio.sleep(self._delay)
            r = await self._req(session, "GET", url)
            if r:
                headers_lower = {k.lower(): v for k, v in r["headers"].items()}
                if "injected" in str(headers_lower) or "x-injected" in headers_lower:
                    evidence.append({"payload": payload, "headers": headers_lower, "endpoint": url})

        if evidence:
            self.findings.append({
                "type": "crlf_injection", "title": "CRLF Injection — Header Injection",
                "description": "CRLF injection allows header injection, enabling cache poisoning and session fixation.",
                "severity": "high", "confidence": 0.85, "endpoint": self.target_url,
                "cwe": "CWE-93", "owasp": "API8:2023",
                "remediation": "Sanitize CRLF characters from all user input used in HTTP headers. URL-encode output.",
                "evidence": evidence, "category": "CRLF Injection",
            })

    async def _test_ssrf_advanced(self, session):
        """Advanced SSRF testing with cloud metadata endpoints."""
        from backend.agents.modern_payloads import SSRF_ADVANCED_PAYLOADS
        evidence = []
        parsed = urlparse(self.target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        ssrf_endpoints = [
            f"{base}/api/v1/fetch", f"{base}/api/v1/proxy", f"{base}/api/v1/url",
        ]

        for ep in ssrf_endpoints:
            for ssrf_url in SSRF_ADVANCED_PAYLOADS[:4]:
                for param_name in ["url", "uri", "src"]:
                    await asyncio.sleep(self._delay)
                    test_url = f"{ep}?{param_name}={ssrf_url}"
                    r = await self._req(session, "GET", test_url)
                    if r and r["status"] == 200:
                        body = r["body"].lower()
                        if any(x in body for x in ["root:", "instance-id", "ami-id", "iam", "169.254", "redis"]):
                            evidence.append({"technique": "ssrf_query", "endpoint": ep, "param": param_name, "ssrf_target": ssrf_url, "body_preview": r["body"][:200]})
                            break
                if evidence: break
            if evidence: break

        if evidence:
            self.findings.append({
                "type": "ssrf", "title": "Server-Side Request Forgery (SSRF)",
                "description": f"SSRF vulnerability confirmed. Internal/cloud resources accessible via API.",
                "severity": "critical", "confidence": 0.85, "endpoint": evidence[0]["endpoint"],
                "cwe": "CWE-918", "owasp": "API8:2023",
                "remediation": "Whitelist allowed URLs/domains. Block internal IP ranges. Disable redirects. Use egress filtering.",
                "evidence": evidence, "category": "SSRF",
            })

