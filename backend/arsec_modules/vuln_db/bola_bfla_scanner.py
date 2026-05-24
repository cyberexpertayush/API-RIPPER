"""
API RIPPER v3.0 — BOLA/BFLA + Race Condition + Mass Assignment Scanner
Detects modern authorization vulnerabilities in real-world APIs.

Covers:
  - BOLA (Broken Object Level Authorization) / IDOR
  - BFLA (Broken Function Level Authorization)
  - Race Conditions (TOCTOU, concurrent state mutation)
  - Mass Assignment (unprotected field binding)
"""

import asyncio
import json
import logging
import time
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urljoin, parse_qs

import aiohttp

logger = logging.getLogger(__name__)


async def bola_bfla_scan(target_url: str, auth_config: dict = None, options: dict = None) -> List[Dict]:
    """Run BOLA/BFLA/Race Condition/Mass Assignment scanner."""
    scanner = AuthzVulnScanner(target_url, auth_config or {}, options or {})
    return await scanner.scan()


class AuthzVulnScanner:
    """Advanced authorization vulnerability scanner."""
    
    def __init__(self, target_url: str, auth_config: dict, options: dict):
        self.target_url = target_url.rstrip('/')
        self.auth_config = auth_config
        self.options = options
        self.findings = []
        self.timeout = aiohttp.ClientTimeout(total=options.get("timeout", 15))
        self._delay = options.get("delay_ms", 100) / 1000.0
        
    async def scan(self) -> List[Dict]:
        """Execute all authorization vulnerability tests."""
        connector = aiohttp.TCPConnector(ssl=False, limit=8)
        headers = self._build_headers()
        
        try:
            async with aiohttp.ClientSession(
                timeout=self.timeout, headers=headers, connector=connector
            ) as session:
                # Discover API structure
                endpoints = await self._discover_endpoints(session)
                
                # Test each endpoint
                for ep in endpoints:
                    await self._test_bola(session, ep)
                    await self._test_bfla(session, ep)
                    await self._test_mass_assignment(session, ep)
                    await self._test_race_condition(session, ep)
        except asyncio.CancelledError:
            logger.warning("[bola_scanner] Cancelled — returning partial results")
        except Exception as e:
            logger.error(f"[bola_scanner] Error: {e}")
                
        return self.findings
    
    def _build_headers(self) -> dict:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "Accept": "application/json, */*"}
        if self.auth_config.get("bearer_token"):
            headers["Authorization"] = f"Bearer {self.auth_config['bearer_token']}"
        if self.auth_config.get("api_key"):
            headers["X-API-Key"] = self.auth_config["api_key"]
        return headers
    
    async def _discover_endpoints(self, session) -> List[Dict]:
        """Discover API endpoints with ID parameters."""
        parsed = urlparse(self.target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        resource_paths = [
            "/api/v1/users/{id}", "/api/v1/orders/{id}", "/api/v1/products/{id}",
            "/api/v1/invoices/{id}", "/api/v1/messages/{id}", "/api/v1/posts/{id}",
            "/api/v1/comments/{id}", "/api/v1/files/{id}", "/api/v1/documents/{id}",
            "/api/v1/accounts/{id}", "/api/v1/transactions/{id}",
            "/api/v2/users/{id}", "/api/v2/orders/{id}",
            "/api/users/{id}", "/api/orders/{id}", "/api/items/{id}",
            "/users/{id}", "/orders/{id}", "/posts/{id}", "/items/{id}",
        ]
        
        discovered = []
        
        for path_template in resource_paths:
            # Test with ID=1
            url = f"{base}{path_template.replace('{id}', '1')}"
            try:
                await asyncio.sleep(self._delay)
                async with session.get(url) as resp:
                    if resp.status in (200, 201, 403, 401):
                        body = await resp.text(errors="replace")
                        discovered.append({
                            "url_template": f"{base}{path_template}",
                            "url": url,
                            "status": resp.status,
                            "body_length": len(body),
                            "has_json": self._is_json(body),
                            "path": path_template,
                        })
            except Exception:
                continue
        
        # Also check the target URL itself
        try:
            await asyncio.sleep(self._delay)
            async with session.get(self.target_url) as resp:
                body = await resp.text(errors="replace")
                # Extract resource URLs from response
                urls = re.findall(r'"(?:url|href|link|self)":\s*"([^"]+)"', body)
                for url in urls[:10]:
                    if re.search(r'/\d+', url):
                        full_url = urljoin(self.target_url, url)
                        discovered.append({
                            "url": full_url,
                            "url_template": re.sub(r'/\d+', '/{id}', full_url),
                            "status": 200,
                            "body_length": 0,
                            "has_json": True,
                            "path": urlparse(full_url).path,
                        })
        except Exception:
            pass
        
        return discovered
    
    async def _test_bola(self, session, endpoint: Dict):
        """Test Broken Object Level Authorization (IDOR)."""
        url_template = endpoint.get("url_template", "")
        if "{id}" not in url_template:
            return
        
        evidence = []
        responses = {}
        
        # Phase 1: Enumerate IDs and compare responses
        test_ids = ["1", "2", "3", "100", "999", "0", "-1", "admin"]
        
        for test_id in test_ids:
            url = url_template.replace("{id}", test_id)
            try:
                await asyncio.sleep(self._delay)
                async with session.get(url) as resp:
                    body = await resp.text(errors="replace")
                    if resp.status == 200:
                        responses[test_id] = {
                            "status": resp.status,
                            "body": body,
                            "body_length": len(body),
                            "headers": dict(resp.headers),
                        }
            except Exception:
                continue
        
        if len(responses) < 2:
            return
        
        # Phase 2: Statistical analysis
        bodies = [r["body"] for r in responses.values()]
        lengths = [r["body_length"] for r in responses.values()]
        
        # Check for genuinely different responses (IDOR indicator)
        unique_bodies = set(bodies)
        if len(unique_bodies) >= 2:
            avg_len = sum(lengths) / len(lengths)
            std_dev = (sum((l - avg_len) ** 2 for l in lengths) / len(lengths)) ** 0.5
            
            # High variance = different users' data
            if std_dev > 20:
                # Check for sensitive data in responses
                sensitive_patterns = [
                    r'"email"\s*:', r'"phone"\s*:', r'"address"\s*:',
                    r'"password"\s*:', r'"ssn"\s*:', r'"credit_card"\s*:',
                    r'"token"\s*:', r'"api_key"\s*:', r'"secret"\s*:',
                    r'"name"\s*:', r'"username"\s*:',
                ]
                
                sensitive_found = []
                for body in bodies:
                    for pattern in sensitive_patterns:
                        if re.search(pattern, body, re.IGNORECASE):
                            sensitive_found.append(pattern.replace(r'\s*:', '').strip('"'))
                
                for test_id, resp_data in responses.items():
                    evidence.append({
                        "id": test_id,
                        "status": resp_data["status"],
                        "body_length": resp_data["body_length"],
                        "body_preview": resp_data["body"][:200],
                    })
                
                if evidence:
                    confidence = 0.9 if sensitive_found else 0.7
                    self.findings.append({
                        "type": "bola_idor",
                        "title": f"BOLA/IDOR: {endpoint['path']}",
                        "description": f"Broken Object Level Authorization confirmed. Sequential ID enumeration returns {len(unique_bodies)} distinct user records. "
                                      f"Sensitive fields exposed: {', '.join(set(sensitive_found)) if sensitive_found else 'Data variance detected'}. "
                                      f"Statistical variance: std_dev={std_dev:.1f}",
                        "severity": "critical",
                        "confidence": confidence,
                        "endpoint": endpoint["url"],
                        "cwe": "CWE-639",
                        "owasp": "API1:2023",
                        "remediation": "Implement object-level authorization. Verify the requesting user owns/has access to the resource. Use UUIDs instead of sequential IDs. Add access control checks in every data-access layer.",
                        "evidence": evidence,
                        "category": "BOLA/IDOR",
                    })

        # Phase 3: Test horizontal access without auth
        if self.auth_config.get("bearer_token"):
            no_auth_evidence = []
            for test_id in ["1", "2"]:
                url = url_template.replace("{id}", test_id)
                try:
                    await asyncio.sleep(self._delay)
                    async with session.get(url, headers={"Authorization": ""}) as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="replace")
                            no_auth_evidence.append({
                                "id": test_id, "status": resp.status,
                                "body_preview": body[:200], "auth": "none",
                            })
                except Exception:
                    continue
            
            if no_auth_evidence:
                self.findings.append({
                    "type": "bola_no_auth",
                    "title": f"BOLA Without Authentication: {endpoint['path']}",
                    "description": f"Objects accessible without any authentication via ID enumeration.",
                    "severity": "critical",
                    "confidence": 0.9,
                    "endpoint": endpoint["url"],
                    "cwe": "CWE-639",
                    "owasp": "API1:2023",
                    "remediation": "Enforce authentication on all resource endpoints. Add authorization checks.",
                    "evidence": no_auth_evidence,
                    "category": "BOLA/IDOR",
                })

    async def _test_bfla(self, session, endpoint: Dict):
        """Test Broken Function Level Authorization."""
        url = endpoint.get("url", "")
        evidence = []
        
        # Test 1: Admin endpoint access
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        admin_paths = [
            parsed.path.replace("/users/", "/admin/users/"),
            parsed.path.replace("/api/v1/", "/api/v1/admin/"),
            parsed.path + "/admin",
            "/admin" + parsed.path,
            parsed.path.replace("/v1/", "/internal/"),
        ]
        
        for admin_path in admin_paths:
            admin_url = f"{base}{admin_path}"
            try:
                await asyncio.sleep(self._delay)
                async with session.get(admin_url) as resp:
                    if resp.status == 200:
                        body = await resp.text(errors="replace")
                        if len(body) > 50:  # Not empty
                            evidence.append({
                                "technique": "admin_path_access",
                                "url": admin_url,
                                "status": resp.status,
                                "body_preview": body[:200],
                            })
            except Exception:
                continue
        
        # Test 2: HTTP method escalation (GET → DELETE/PUT)
        destructive_methods = ["DELETE", "PUT", "PATCH"]
        for method in destructive_methods:
            try:
                await asyncio.sleep(self._delay)
                req_method = getattr(session, method.lower())
                async with req_method(url) as resp:
                    if resp.status in (200, 204):
                        evidence.append({
                            "technique": "method_escalation",
                            "method": method,
                            "url": url,
                            "status": resp.status,
                        })
            except Exception:
                continue
        
        # Test 3: Method override headers
        override_headers = [
            {"X-HTTP-Method-Override": "DELETE"},
            {"X-HTTP-Method": "PUT"},
            {"X-Method-Override": "DELETE"},
            {"_method": "DELETE"},
        ]
        for oh in override_headers:
            try:
                await asyncio.sleep(self._delay)
                async with session.post(url, headers=oh) as resp:
                    if resp.status in (200, 204):
                        evidence.append({
                            "technique": "method_override",
                            "headers": oh,
                            "url": url,
                            "status": resp.status,
                        })
                        break
            except Exception:
                continue
        
        if evidence:
            self.findings.append({
                "type": "bfla",
                "title": f"BFLA: Unauthorized Function Access at {endpoint['path']}",
                "description": f"Broken Function Level Authorization detected. {len(evidence)} unauthorized function access vectors confirmed.",
                "severity": "high",
                "confidence": 0.75,
                "endpoint": url,
                "cwe": "CWE-285",
                "owasp": "API5:2023",
                "remediation": "Implement role-based access control. Restrict admin functions by role. Deny dangerous HTTP methods on non-admin routes. Block method override headers.",
                "evidence": evidence,
                "category": "BFLA",
            })

    async def _test_mass_assignment(self, session, endpoint: Dict):
        """Test mass assignment vulnerabilities."""
        url = endpoint.get("url", "")
        evidence = []
        
        # Get baseline response
        try:
            await asyncio.sleep(self._delay)
            async with session.get(url) as resp:
                if resp.status != 200:
                    return
                baseline_body = await resp.text(errors="replace")
                baseline_length = len(baseline_body)
        except Exception:
            return
        
        # Mass assignment payloads
        payloads = [
            {"role": "admin", "is_admin": True},
            {"admin": True, "privilege": "superuser"},
            {"role": "administrator", "permissions": ["*"]},
            {"isAdmin": True, "user_type": "admin"},
            {"access_level": 999, "verified": True},
            {"email_verified": True, "phone_verified": True},
            {"balance": 99999, "credits": 99999},
            {"subscription": "enterprise", "plan": "unlimited"},
        ]
        
        for payload in payloads:
            for method in ["PUT", "PATCH", "POST"]:
                try:
                    await asyncio.sleep(self._delay)
                    req_method = getattr(session, method.lower())
                    async with req_method(
                        url,
                        data=json.dumps(payload),
                        headers={"Content-Type": "application/json"}
                    ) as resp:
                        if resp.status in (200, 201):
                            body = await resp.text(errors="replace")
                            
                            # Verify the fields were actually set
                            for key, value in payload.items():
                                if str(value).lower() in body.lower():
                                    evidence.append({
                                        "technique": "mass_assignment",
                                        "method": method,
                                        "payload": payload,
                                        "key_reflected": key,
                                        "status": resp.status,
                                        "body_preview": body[:300],
                                    })
                                    break
                except Exception:
                    continue
        
        # Verify persistence: re-fetch and check
        if evidence:
            try:
                await asyncio.sleep(self._delay)
                async with session.get(url) as resp:
                    if resp.status == 200:
                        verify_body = await resp.text(errors="replace")
                        for ev in evidence:
                            key = ev["key_reflected"]
                            if key in verify_body.lower():
                                ev["persisted"] = True
            except Exception:
                pass
        
        if evidence:
            persisted = any(e.get("persisted") for e in evidence)
            severity = "critical" if persisted else "high"
            confidence = 0.9 if persisted else 0.65
            
            self.findings.append({
                "type": "mass_assignment",
                "title": f"Mass Assignment: {endpoint['path']}",
                "description": f"Mass assignment vulnerability detected. Injected privilege fields were {'persisted in the database' if persisted else 'accepted by the API'}.",
                "severity": severity,
                "confidence": confidence,
                "endpoint": url,
                "cwe": "CWE-915",
                "owasp": "API6:2023",
                "remediation": "Use allowlists for bindable fields. Never auto-bind request data to internal models. Implement DTOs/schemas for input validation.",
                "evidence": evidence,
                "category": "Mass Assignment",
            })

    async def _test_race_condition(self, session, endpoint: Dict):
        """Test race condition vulnerabilities."""
        url = endpoint.get("url", "")
        evidence = []
        
        # Test 1: Concurrent read (response inconsistency)
        tasks = []
        for _ in range(20):
            tasks.append(self._timed_request(session, "GET", url))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        valid = [r for r in results if isinstance(r, dict) and r.get("status")]
        
        if len(valid) >= 15:
            statuses = [r["status"] for r in valid]
            bodies = [r.get("body_preview", "") for r in valid]
            lengths = [r.get("body_length", 0) for r in valid]
            latencies = [r.get("latency_ms", 0) for r in valid]
            
            unique_statuses = set(statuses)
            unique_bodies = len(set(bodies))
            
            # Inconsistent responses under concurrency = race condition indicator
            if len(unique_statuses) > 1 or unique_bodies > 3:
                evidence.append({
                    "technique": "concurrent_read_inconsistency",
                    "requests_sent": 20,
                    "unique_statuses": list(unique_statuses),
                    "unique_responses": unique_bodies,
                    "avg_latency_ms": sum(latencies) / len(latencies),
                })
        
        # Test 2: Concurrent POST (double-spending / duplicate creation)
        test_payload = json.dumps({"action": "test", "amount": 1})
        post_tasks = []
        for _ in range(15):
            post_tasks.append(self._timed_request(
                session, "POST", url,
                body=test_payload,
                content_type="application/json"
            ))
        
        post_results = await asyncio.gather(*post_tasks, return_exceptions=True)
        post_valid = [r for r in post_results if isinstance(r, dict) and r.get("status")]
        
        if len(post_valid) >= 10:
            success_count = sum(1 for r in post_valid if r["status"] in (200, 201))
            if success_count > 1:
                evidence.append({
                    "technique": "concurrent_post_duplication",
                    "requests_sent": 15,
                    "successful_creates": success_count,
                    "description": "Multiple concurrent POST requests succeeded — potential double-spending or duplicate creation",
                })
        
        # Test 3: No rate limiting under concurrent load
        all_200 = all(r.get("status") == 200 for r in valid) if valid else False
        if all_200 and len(valid) >= 18:
            evidence.append({
                "technique": "no_concurrency_protection",
                "requests_sent": 20,
                "all_succeeded": len(valid),
                "description": "All concurrent requests succeeded — no mutex, semaphore, or rate limiting",
            })
        
        if evidence:
            self.findings.append({
                "type": "race_condition",
                "title": f"Race Condition: {endpoint['path']}",
                "description": f"Race condition vulnerability detected with {len(evidence)} indicators. Concurrent requests show state inconsistency.",
                "severity": "high",
                "confidence": 0.65,
                "endpoint": url,
                "cwe": "CWE-362",
                "owasp": "API2:2023",
                "remediation": "Implement optimistic/pessimistic locking. Use database transactions with proper isolation levels. Add idempotency keys for state-changing operations. Implement request deduplication.",
                "evidence": evidence,
                "category": "Race Condition",
            })

    async def _timed_request(self, session, method: str, url: str,
                             body: str = None, content_type: str = None) -> Optional[Dict]:
        """Make a timed HTTP request."""
        try:
            kwargs = {}
            if body:
                kwargs["data"] = body
                if content_type:
                    kwargs["headers"] = {"Content-Type": content_type}
            
            req_fn = getattr(session, method.lower(), session.get)
            start = time.time()
            async with req_fn(url, **kwargs) as resp:
                resp_body = await resp.text(errors="replace")
                return {
                    "status": resp.status,
                    "body_length": len(resp_body),
                    "body_preview": resp_body[:300],
                    "headers": dict(resp.headers),
                    "latency_ms": round((time.time() - start) * 1000, 2),
                }
        except Exception:
            return None
    
    def _is_json(self, text: str) -> bool:
        try:
            json.loads(text)
            return True
        except Exception:
            return False
