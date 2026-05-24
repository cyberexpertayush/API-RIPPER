"""
API RIPPER v2.0 — Auth Flow Analyzer
Authentication mechanism detection and analysis.
Detects auth types (JWT, session cookie, API key, OAuth),
maps auth token lifecycle, and identifies unprotected endpoints.

Used by the Recon Agent and Exploit Agent for auth-aware scanning.
"""

import base64
import json
import logging
import re
import time
from typing import Any, Dict, List, Optional, Tuple

import aiohttp

logger = logging.getLogger(__name__)


class AuthFlowAnalyzer:
    """
    Analyzes authentication mechanisms of a target API.
    Detects auth type, tests token handling, and identifies
    auth boundary weaknesses.
    """

    def __init__(self, auth_config: Dict[str, Any] = None):
        self.auth_config = auth_config or {}
        self.detected_auth_type: Optional[str] = None
        self.auth_endpoints: List[str] = []
        self.token_info: Dict[str, Any] = {}

    def get_auth_headers(self) -> Dict[str, str]:
        """Build authentication headers from user-supplied config."""
        headers = {}

        if self.auth_config.get("bearer_token"):
            headers["Authorization"] = f"Bearer {self.auth_config['bearer_token']}"

        if self.auth_config.get("api_key"):
            # Try common API key header names
            key_header = self.auth_config.get("api_key_header", "X-API-Key")
            headers[key_header] = self.auth_config["api_key"]

        if self.auth_config.get("basic_auth"):
            creds = self.auth_config["basic_auth"]  # "user:pass"
            encoded = base64.b64encode(creds.encode()).decode()
            headers["Authorization"] = f"Basic {encoded}"

        if self.auth_config.get("custom_headers"):
            headers.update(self.auth_config["custom_headers"])

        return headers

    def get_cookies(self) -> Dict[str, str]:
        """Get cookies from auth config."""
        return self.auth_config.get("cookies", {})

    async def detect_auth_type(self, session: aiohttp.ClientSession, target_url: str) -> Dict[str, Any]:
        """
        Auto-detect the authentication mechanism used by the API.
        Tests: JWT, session cookies, API key headers, OAuth flows.
        """
        result = {
            "auth_type": "none",
            "auth_endpoints": [],
            "token_type": None,
            "requires_auth": False,
        }

        # 1. Check if unauthenticated access is rejected
        try:
            async with session.get(target_url, headers={"Authorization": ""}) as resp:
                if resp.status in (401, 403):
                    result["requires_auth"] = True

                # Check WWW-Authenticate header for auth type hints
                www_auth = resp.headers.get("www-authenticate", "").lower()
                if "bearer" in www_auth:
                    result["auth_type"] = "bearer"
                elif "basic" in www_auth:
                    result["auth_type"] = "basic"
                elif "digest" in www_auth:
                    result["auth_type"] = "digest"

                # Check for session cookies in response
                set_cookie = resp.headers.getall("set-cookie", [])
                for cookie in set_cookie:
                    if any(kw in cookie.lower() for kw in ["session", "sess", "sid", "token"]):
                        result["auth_type"] = "session_cookie"
                        break

        except Exception as e:
            logger.debug(f"Auth detection error: {e}")

        # 2. Discover auth endpoints
        auth_paths = [
            "/api/auth/login", "/api/login", "/auth/login",
            "/api/auth/token", "/oauth/token", "/api/token",
            "/api/auth/signin", "/api/signin", "/signin",
            "/api/auth/register", "/api/register",
            "/api/auth/refresh", "/api/token/refresh",
        ]

        for path in auth_paths:
            from urllib.parse import urljoin
            url = urljoin(target_url, path)
            try:
                async with session.options(url) as resp:
                    if resp.status != 404:
                        result["auth_endpoints"].append(url)
            except Exception:
                pass

        self.detected_auth_type = result["auth_type"]
        self.auth_endpoints = result["auth_endpoints"]

        return result

    def analyze_jwt(self, token: str) -> Dict[str, Any]:
        """Decode and analyze a JWT token (without verification)."""
        result = {
            "valid_format": False,
            "header": {},
            "payload": {},
            "signature_present": False,
            "issues": [],
        }

        parts = token.split(".")
        if len(parts) != 3:
            result["issues"].append("Invalid JWT format (expected 3 parts)")
            return result

        result["valid_format"] = True
        result["signature_present"] = len(parts[2]) > 0

        # Decode header
        try:
            header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            result["header"] = json.loads(base64.urlsafe_b64decode(header_b64))
        except Exception:
            result["issues"].append("Failed to decode JWT header")

        # Decode payload
        try:
            payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
            result["payload"] = json.loads(base64.urlsafe_b64decode(payload_b64))
        except Exception:
            result["issues"].append("Failed to decode JWT payload")

        # Security analysis
        header = result["header"]
        payload = result["payload"]

        # Check algorithm
        alg = header.get("alg", "").upper()
        if alg == "NONE":
            result["issues"].append("CRITICAL: Algorithm set to 'none' — signature not verified")
        elif alg in ("HS256", "HS384", "HS512"):
            result["issues"].append("Uses symmetric signing (HMAC) — shared secret vulnerability")

        # Check expiration
        if "exp" not in payload:
            result["issues"].append("No expiration (exp) claim — token never expires")
        else:
            import datetime
            exp = payload["exp"]
            if exp < time.time():
                result["issues"].append("Token is expired")
            elif exp > time.time() + 86400 * 30:
                result["issues"].append("Token expiration > 30 days — excessively long lifetime")

        # Check claims
        if "iat" not in payload:
            result["issues"].append("No issued-at (iat) claim")
        if "sub" not in payload and "user_id" not in payload:
            result["issues"].append("No subject identifier — may allow token reuse")

        # Check for sensitive data in payload
        sensitive_keys = ["password", "secret", "ssn", "credit_card"]
        for key in payload:
            if any(s in key.lower() for s in sensitive_keys):
                result["issues"].append(f"Sensitive field '{key}' in JWT payload")

        return result

    def analyze_session_token(self, token_value: str) -> Dict[str, Any]:
        """Analyze a session token for randomness and predictability."""
        import math

        result = {
            "length": len(token_value),
            "character_set": "",
            "entropy_bits": 0.0,
            "issues": [],
        }

        # Determine character set
        has_lower = bool(re.search(r'[a-z]', token_value))
        has_upper = bool(re.search(r'[A-Z]', token_value))
        has_digit = bool(re.search(r'[0-9]', token_value))
        has_special = bool(re.search(r'[^a-zA-Z0-9]', token_value))

        charset_size = 0
        parts = []
        if has_lower:
            charset_size += 26
            parts.append("lowercase")
        if has_upper:
            charset_size += 26
            parts.append("uppercase")
        if has_digit:
            charset_size += 10
            parts.append("digits")
        if has_special:
            charset_size += 32
            parts.append("special")

        result["character_set"] = "+".join(parts)

        # Calculate entropy
        if charset_size > 0 and len(token_value) > 0:
            result["entropy_bits"] = round(len(token_value) * math.log2(charset_size), 2)

        # Issues
        if result["entropy_bits"] < 64:
            result["issues"].append(f"Low entropy ({result['entropy_bits']:.0f} bits) — predictable token")
        if len(token_value) < 16:
            result["issues"].append(f"Short token ({len(token_value)} chars) — brute-forceable")
        if re.match(r'^\d+$', token_value):
            result["issues"].append("Numeric-only token — highly predictable")
        if re.match(r'^[0-9a-f]+$', token_value, re.I) and len(token_value) == 32:
            result["issues"].append("Looks like MD5 hash — may be predictable if based on known input")

        return result
