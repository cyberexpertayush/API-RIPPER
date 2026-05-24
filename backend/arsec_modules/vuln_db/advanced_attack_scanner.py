"""
API RIPPER v3.0 — WebSocket + File Upload + Webhook + LLM API Scanner
"""
import asyncio, json, logging, time, re, io
from typing import Dict, List, Optional
from urllib.parse import urlparse, urljoin
import aiohttp

logger = logging.getLogger(__name__)

async def advanced_attack_scan(target_url: str, auth_config: dict = None, options: dict = None) -> List[Dict]:
    scanner = AdvancedAttackScanner(target_url, auth_config or {}, options or {})
    return await scanner.scan()

class AdvancedAttackScanner:
    def __init__(self, target_url, auth_config, options):
        self.target_url = target_url.rstrip('/')
        self.auth_config = auth_config
        self.findings = []
        self.timeout = aiohttp.ClientTimeout(total=options.get("timeout", 15))
        self._delay = options.get("delay_ms", 100) / 1000.0

    def _headers(self):
        h = {"User-Agent": "Mozilla/5.0", "Accept": "*/*"}
        if self.auth_config.get("bearer_token"): h["Authorization"] = f"Bearer {self.auth_config['bearer_token']}"
        return h

    async def scan(self):
        connector = aiohttp.TCPConnector(ssl=False, limit=5)
        try:
            async with aiohttp.ClientSession(timeout=self.timeout, headers=self._headers(), connector=connector) as s:
                await self._test_websocket_attacks(s)
                await self._test_file_upload(s)
                await self._test_webhook_ssrf(s)
                await self._test_llm_injection(s)
                await self._test_api_versioning(s)
                await self._test_hidden_apis(s)
                await self._test_xxe_attacks(s)
        except asyncio.CancelledError:
            logger.warning("[advanced_scanner] Cancelled — returning partial results")
        except Exception as e:
            logger.error(f"[advanced_scanner] Error: {e}")
        return self.findings

    async def _req(self, session, method, url, headers=None, body=None, ct=None, data=None):
        try:
            kw = {}
            if headers: kw["headers"] = headers
            if body: kw["data"] = body; kw.setdefault("headers", {})["Content-Type"] = ct or "application/json"
            if data: kw["data"] = data
            start = time.time()
            fn = getattr(session, method.lower(), session.get)
            async with fn(url, **kw) as r:
                b = await r.text(errors="replace")
                return {"status": r.status, "body": b[:500], "body_length": len(b), "headers": dict(r.headers), "latency_ms": round((time.time()-start)*1000,2)}
        except: return None

    async def _test_websocket_attacks(self, session):
        """Test WebSocket security (CSWSH, injection, auth bypass)."""
        evidence = []
        parsed = urlparse(self.target_url)
        ws_scheme = "wss" if parsed.scheme == "https" else "ws"
        ws_paths = ["/ws", "/websocket", "/socket", "/api/ws", "/api/v1/ws", "/realtime", "/live", "/stream", "/socket.io/"]

        for path in ws_paths:
            ws_url = f"{ws_scheme}://{parsed.netloc}{path}"
            try:
                # Test 1: Connect without auth (CSWSH)
                async with session.ws_connect(ws_url, origin="https://evil.com", timeout=5) as ws:
                    evidence.append({"technique": "cswsh", "url": ws_url, "origin": "evil.com", "description": "WebSocket accepts connections from arbitrary origins"})
                    # Test 2: Injection
                    from backend.agents.modern_payloads import WEBSOCKET_INJECTION_PAYLOADS
                    for payload in WEBSOCKET_INJECTION_PAYLOADS[:3]:
                        await ws.send_str(payload)
                        try:
                            msg = await asyncio.wait_for(ws.receive(), timeout=3)
                            if msg.type == aiohttp.WSMsgType.TEXT:
                                if any(x in msg.data.lower() for x in ["admin", "error", "sql", "__proto__"]):
                                    evidence.append({"technique": "ws_injection", "payload": payload[:80], "response": msg.data[:200]})
                        except: pass
                    await ws.close()
            except Exception as e:
                if "403" not in str(e) and "404" not in str(e):
                    logger.debug(f"WS test {ws_url}: {e}")

        if evidence:
            self.findings.append({
                "type": "websocket_vulnerability", "title": "WebSocket Security Vulnerability",
                "description": f"WebSocket vulnerabilities: {len(evidence)} issues found including potential CSWSH.",
                "severity": "high", "confidence": 0.75, "endpoint": evidence[0]["url"],
                "cwe": "CWE-1385", "owasp": "API8:2023",
                "remediation": "Validate Origin header on WebSocket connections. Implement authentication for WS. Sanitize WS message input.",
                "evidence": evidence, "category": "WebSocket",
            })

    async def _test_file_upload(self, session):
        """Test file upload vulnerabilities."""
        from backend.agents.modern_payloads import SVG_XSS_PAYLOAD, XXE_SVG_PAYLOAD, EXTENSION_BYPASSES
        evidence = []
        parsed = urlparse(self.target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        upload_endpoints = [f"{base}/api/v1/upload", f"{base}/api/v1/files", f"{base}/upload", f"{base}/api/upload",
                           f"{base}/api/v1/images", f"{base}/api/v1/documents", f"{base}/api/v1/import"]

        for ep in upload_endpoints:
            # Test 1: SVG XSS
            form = aiohttp.FormData()
            form.add_field('file', SVG_XSS_PAYLOAD.encode(), filename='test.svg', content_type='image/svg+xml')
            await asyncio.sleep(self._delay)
            try:
                async with session.post(ep, data=form) as r:
                    if r.status in (200, 201):
                        body = await r.text(errors="replace")
                        evidence.append({"technique": "svg_xss_upload", "endpoint": ep, "status": r.status, "body_preview": body[:200]})
            except: continue

            # Test 2: Extension bypass
            for ext in EXTENSION_BYPASSES[:5]:
                form2 = aiohttp.FormData()
                form2.add_field('file', b'<?php echo "test"; ?>', filename=f'shell{ext}', content_type='image/jpeg')
                await asyncio.sleep(self._delay)
                try:
                    async with session.post(ep, data=form2) as r:
                        if r.status in (200, 201):
                            evidence.append({"technique": "extension_bypass", "extension": ext, "endpoint": ep, "status": r.status})
                            break
                except: continue

            # Test 3: XXE via SVG
            form3 = aiohttp.FormData()
            form3.add_field('file', XXE_SVG_PAYLOAD.encode(), filename='test.svg', content_type='image/svg+xml')
            await asyncio.sleep(self._delay)
            try:
                async with session.post(ep, data=form3) as r:
                    if r.status in (200, 201):
                        body = await r.text(errors="replace")
                        if "root:" in body or "etc/passwd" in body:
                            evidence.append({"technique": "xxe_via_svg", "endpoint": ep, "severity": "critical"})
            except: continue

            # Test 4: Path traversal in filename
            form4 = aiohttp.FormData()
            form4.add_field('file', b'test', filename='../../../etc/passwd', content_type='text/plain')
            await asyncio.sleep(self._delay)
            try:
                async with session.post(ep, data=form4) as r:
                    if r.status in (200, 201):
                        evidence.append({"technique": "path_traversal_filename", "endpoint": ep})
            except: continue

        if evidence:
            sev = "critical" if any(e.get("severity") == "critical" or e["technique"] == "xxe_via_svg" for e in evidence) else "high"
            self.findings.append({
                "type": "file_upload_vuln", "title": "File Upload Vulnerability",
                "description": f"File upload vulnerabilities: {len(evidence)} vectors found.",
                "severity": sev, "confidence": 0.7, "endpoint": evidence[0]["endpoint"],
                "cwe": "CWE-434", "owasp": "API8:2023",
                "remediation": "Validate file extensions against whitelist. Check MIME types server-side. Disable SVG script execution. Sanitize filenames. Store uploads outside webroot.",
                "evidence": evidence, "category": "File Upload",
            })

    async def _test_webhook_ssrf(self, session):
        """Test webhook endpoints for SSRF."""
        from backend.agents.modern_payloads import WEBHOOK_SSRF_URLS
        evidence = []
        parsed = urlparse(self.target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        webhook_eps = [f"{base}/api/v1/webhooks", f"{base}/api/v1/integrations", f"{base}/api/v1/callbacks",
                      f"{base}/api/webhooks", f"{base}/webhooks"]

        for ep in webhook_eps:
            for ssrf_url in WEBHOOK_SSRF_URLS[:4]:
                payloads = [
                    {"url": ssrf_url, "event": "test"},
                    {"callback_url": ssrf_url},
                    {"webhook_url": ssrf_url, "events": ["all"]},
                ]
                for payload in payloads:
                    await asyncio.sleep(self._delay)
                    r = await self._req(session, "POST", ep, body=json.dumps(payload), ct="application/json")
                    if r and r["status"] in (200, 201, 202):
                        evidence.append({"technique": "webhook_ssrf", "endpoint": ep, "ssrf_url": ssrf_url, "status": r["status"]})
                        break
                if evidence: break
            if evidence: break

        if evidence:
            self.findings.append({
                "type": "webhook_ssrf", "title": "Webhook SSRF Vulnerability",
                "description": "Webhook endpoint accepts internal URLs — SSRF via webhook registration.",
                "severity": "high", "confidence": 0.65, "endpoint": evidence[0]["endpoint"],
                "cwe": "CWE-918", "owasp": "API8:2023",
                "remediation": "Validate webhook URLs against whitelist. Block internal IPs. Implement URL validation. Use egress firewall rules.",
                "evidence": evidence, "category": "Webhook SSRF",
            })

    async def _test_llm_injection(self, session):
        """Test AI/LLM API endpoints for prompt injection."""
        from backend.agents.modern_payloads import LLM_INJECTION_PAYLOADS
        evidence = []
        parsed = urlparse(self.target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        ai_eps = [f"{base}/api/v1/chat", f"{base}/api/v1/ai", f"{base}/api/v1/generate",
                 f"{base}/api/v1/completions", f"{base}/api/v1/ask", f"{base}/api/chat",
                 f"{base}/chat", f"{base}/api/v1/assistant"]

        for ep in ai_eps:
            for payload in LLM_INJECTION_PAYLOADS[:5]:
                body_variants = [
                    {"message": payload}, {"prompt": payload}, {"input": payload},
                    {"query": payload}, {"text": payload}, {"content": payload},
                ]
                for body in body_variants:
                    await asyncio.sleep(self._delay)
                    r = await self._req(session, "POST", ep, body=json.dumps(body), ct="application/json")
                    if r and r["status"] == 200:
                        resp_body = r["body"].lower()
                        leak_indicators = ["api_key", "secret", "password", "system prompt", "you are", "internal", "database", "credential"]
                        if any(x in resp_body for x in leak_indicators):
                            evidence.append({"technique": "prompt_injection", "endpoint": ep, "payload": payload[:100], "leak_detected": True, "body_preview": r["body"][:200]})
                        break
                if evidence: break
            if evidence: break

        if evidence:
            self.findings.append({
                "type": "llm_prompt_injection", "title": "LLM/AI Prompt Injection",
                "description": "AI endpoint vulnerable to prompt injection — system prompt or internal data leaked.",
                "severity": "high", "confidence": 0.7, "endpoint": evidence[0]["endpoint"],
                "cwe": "CWE-77", "owasp": "LLM01:2023",
                "remediation": "Implement input sanitization for LLM prompts. Use system prompt isolation. Limit output to prevent data exfiltration. Add output filtering.",
                "evidence": evidence, "category": "AI/LLM Security",
            })

    async def _test_api_versioning(self, session):
        """Test for API versioning issues — old versions still accessible."""
        evidence = []
        parsed = urlparse(self.target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        current_path = parsed.path

        # Detect current version
        version_match = re.search(r'/v(\d+)/', current_path)
        if version_match:
            current_ver = int(version_match.group(1))
            # Test older versions
            for old_ver in range(1, current_ver):
                old_path = current_path.replace(f"/v{current_ver}/", f"/v{old_ver}/")
                old_url = f"{base}{old_path}"
                await asyncio.sleep(self._delay)
                r = await self._req(session, "GET", old_url)
                if r and r["status"] == 200:
                    evidence.append({"old_version": f"v{old_ver}", "url": old_url, "status": r["status"]})

        # Test common old API paths
        old_paths = ["/api/v0/", "/api/v1/", "/api/beta/", "/api/alpha/", "/api/legacy/", "/api/old/", "/api/deprecated/"]
        for path in old_paths:
            url = f"{base}{path}"
            await asyncio.sleep(self._delay)
            r = await self._req(session, "GET", url)
            if r and r["status"] == 200 and r["body_length"] > 50:
                evidence.append({"path": path, "url": url, "status": r["status"]})

        if evidence:
            self.findings.append({
                "type": "api_versioning", "title": "Deprecated API Versions Still Accessible",
                "description": f"Old/deprecated API versions are accessible. {len(evidence)} legacy endpoints found.",
                "severity": "medium", "confidence": 0.7, "endpoint": evidence[0]["url"],
                "cwe": "CWE-1059", "owasp": "API9:2023",
                "remediation": "Decommission old API versions. Redirect deprecated endpoints. Implement version sunset policies.",
                "evidence": evidence, "category": "API Versioning",
            })

    async def _test_hidden_apis(self, session):
        """Discover hidden/internal API endpoints."""
        evidence = []
        parsed = urlparse(self.target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        hidden_paths = [
            "/api/internal/", "/api/private/", "/api/debug/", "/internal/", "/private/",
            "/api/v1/internal/", "/_debug/", "/__debug__/", "/api/test/", "/api/staging/",
            "/actuator/", "/actuator/env", "/actuator/mappings", "/actuator/beans",
            "/.well-known/", "/server-info", "/server-status", "/api/health/detailed",
            "/api/v1/debug/config", "/api/v1/admin/config", "/metrics", "/prometheus",
            "/api/v1/swagger.json", "/api/v1/openapi.yaml", "/debug/vars", "/debug/pprof/",
        ]

        for path in hidden_paths:
            url = f"{base}{path}"
            await asyncio.sleep(self._delay)
            r = await self._req(session, "GET", url)
            if r and r["status"] == 200 and r["body_length"] > 20:
                evidence.append({"path": path, "url": url, "body_length": r["body_length"], "body_preview": r["body"][:200]})

        if evidence:
            self.findings.append({
                "type": "hidden_api_exposed", "title": f"Hidden/Internal APIs Exposed ({len(evidence)} endpoints)",
                "description": f"Internal/debug API endpoints are publicly accessible.",
                "severity": "high", "confidence": 0.8, "endpoint": evidence[0]["url"],
                "cwe": "CWE-200", "owasp": "API9:2023",
                "remediation": "Restrict internal endpoints. Use network segmentation. Disable debug/actuator endpoints in production.",
                "evidence": evidence, "category": "Hidden APIs",
            })

    async def _test_xxe_attacks(self, session):
        """Test XML External Entity (XXE) injection."""
        from backend.agents.modern_payloads import XXE_PAYLOADS
        evidence = []
        parsed = urlparse(self.target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        xml_eps = [self.target_url, f"{base}/api/v1/import", f"{base}/api/v1/parse", f"{base}/api/v1/xml", f"{base}/api/v1/data"]

        for ep in xml_eps:
            for payload in XXE_PAYLOADS:
                await asyncio.sleep(self._delay)
                r = await self._req(session, "POST", ep, body=payload, ct="application/xml")
                if r:
                    if r["status"] == 200 and any(x in r["body"] for x in ["root:", "boot.ini", "[extensions]", "instance-id"]):
                        evidence.append({"technique": "xxe", "endpoint": ep, "severity": "critical", "body_preview": r["body"][:200]})
                    elif r["status"] == 500 and any(x in r["body"].lower() for x in ["entity", "dtd", "xml", "parser"]):
                        evidence.append({"technique": "xxe_error", "endpoint": ep, "body_preview": r["body"][:200]})

        if evidence:
            sev = "critical" if any(e.get("severity") == "critical" for e in evidence) else "high"
            self.findings.append({
                "type": "xxe", "title": "XML External Entity (XXE) Injection",
                "description": f"XXE vulnerability detected. External entities are processed.",
                "severity": sev, "confidence": 0.8, "endpoint": evidence[0]["endpoint"],
                "cwe": "CWE-611", "owasp": "API8:2023",
                "remediation": "Disable external entity processing. Use JSON instead of XML. Configure XML parser to disallow DTDs.",
                "evidence": evidence, "category": "XXE",
            })
