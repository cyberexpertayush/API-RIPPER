#!/usr/bin/env python3
"""
Comprehensive HTTP Security Headers Analyzer
Deep audit of all security-relevant HTTP headers including:
  - Content-Security-Policy (CSP) directive-level analysis
  - HSTS configuration checking (max-age, includeSubDomains, preload)
  - X-Frame-Options / frame-ancestors validation
  - Permissions-Policy / Feature-Policy audit
  - Cache-Control & Pragma for sensitive data
  - Cross-Origin headers (CORP, COEP, COOP)
  - Information leakage via Server, X-Powered-By, etc.
  - Cookie security flags (Secure, HttpOnly, SameSite)
  - Referrer-Policy strictness grading
  - Overall security grade calculation (A+ through F)
"""

from colorama import Fore
import requests
import urllib3
import re
import os
import logging
from urllib.parse import urlparse
from typing import Dict, List, Any, Optional, Tuple

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)


class SecurityHeadersAnalyzer:
    """Deep HTTP security headers analysis and grading"""

    # Weight each header category for the overall score
    HEADER_WEIGHTS = {
        "Strict-Transport-Security": 15,
        "Content-Security-Policy": 20,
        "X-Content-Type-Options": 10,
        "X-Frame-Options": 10,
        "Referrer-Policy": 5,
        "Permissions-Policy": 5,
        "X-XSS-Protection": 3,
        "Cross-Origin-Opener-Policy": 5,
        "Cross-Origin-Resource-Policy": 5,
        "Cross-Origin-Embedder-Policy": 5,
        "Cache-Control": 7,
        "Information-Leakage": 10,  # negative score for leaking info
    }

    # Maximum achievable score
    MAX_SCORE = sum(HEADER_WEIGHTS.values())

    # Dangerous CSP directives
    CSP_UNSAFE_PATTERNS = [
        ("unsafe-inline", "Allows inline scripts/styles, defeating XSS protection"),
        ("unsafe-eval", "Allows eval(), significant XSS risk"),
        ("data:", "Allows data: URIs which can execute scripts"),
        ("blob:", "Allows blob: URIs which can execute scripts"),
        ("*", "Wildcard allows loading resources from any origin"),
        ("http:", "Allows loading resources over insecure HTTP"),
    ]

    def __init__(self, target_url: str):
        self.target = target_url.rstrip("/")
        self.parsed = urlparse(self.target)
        self.base = f"{self.parsed.scheme}://{self.parsed.netloc}"
        self.findings: List[Dict[str, Any]] = []
        self.endpoints: List[str] = []
        self.score = 0
        self.grade_details: Dict[str, Dict[str, Any]] = {}
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })

    # ── Fetch headers ────────────────────────────────────────────
    def _fetch_headers(self, url: str = None) -> Optional[Dict[str, str]]:
        """Fetch response headers from the target."""
        url = url or self.target
        try:
            r = self.session.get(url, timeout=10, allow_redirects=True)
            return dict(r.headers), r.cookies, r.url
        except Exception as e:
            logger.error(f"Failed to fetch headers: {e}")
            return None, None, None

    # ── HSTS Analysis ────────────────────────────────────────────
    def _analyze_hsts(self, headers: dict):
        """Analyze Strict-Transport-Security header."""
        hsts = headers.get("Strict-Transport-Security", "")
        weight = self.HEADER_WEIGHTS["Strict-Transport-Security"]

        if not hsts:
            self.findings.append({
                "type": "Missing HSTS Header",
                "severity": "high",
                "endpoint": self.target,
                "details": (
                    "Strict-Transport-Security header is missing. "
                    "Without HSTS, users can be downgraded to HTTP via "
                    "man-in-the-middle attacks (SSL stripping). "
                    "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
                ),
                "method": "GET",
            })
            self.grade_details["HSTS"] = {"status": "MISSING", "score": 0, "max": weight}
            return

        score = weight * 0.4  # Base score for having HSTS

        # Check max-age
        max_age_match = re.search(r'max-age=(\d+)', hsts)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age >= 31536000:  # 1 year
                score += weight * 0.3
            elif max_age >= 15768000:  # 6 months
                score += weight * 0.2
            elif max_age < 86400:  # Less than 1 day
                self.findings.append({
                    "type": "HSTS Max-Age Too Short",
                    "severity": "medium",
                    "endpoint": self.target,
                    "details": (
                        f"HSTS max-age is only {max_age} seconds ({max_age/3600:.1f} hours). "
                        f"Minimum recommended value is 31536000 (1 year)."
                    ),
                    "method": "GET",
                })

        # Check includeSubDomains
        if "includesubdomains" in hsts.lower():
            score += weight * 0.15
        else:
            self.findings.append({
                "type": "HSTS Missing includeSubDomains",
                "severity": "low",
                "endpoint": self.target,
                "details": "HSTS does not include subdomains. Subdomains are still vulnerable to downgrade attacks.",
                "method": "GET",
            })

        # Check preload
        if "preload" in hsts.lower():
            score += weight * 0.15

        self.score += score
        self.grade_details["HSTS"] = {"status": "PRESENT", "value": hsts, "score": round(score, 1), "max": weight}

    # ── CSP Analysis ─────────────────────────────────────────────
    def _analyze_csp(self, headers: dict):
        """Deep Content-Security-Policy analysis."""
        csp = headers.get("Content-Security-Policy", "")
        weight = self.HEADER_WEIGHTS["Content-Security-Policy"]

        if not csp:
            # Check for report-only
            csp_ro = headers.get("Content-Security-Policy-Report-Only", "")
            if csp_ro:
                self.findings.append({
                    "type": "CSP in Report-Only Mode",
                    "severity": "medium",
                    "endpoint": self.target,
                    "details": (
                        "Content-Security-Policy is set in report-only mode. "
                        "It logs violations but does NOT enforce restrictions. "
                        "Transition to enforcing mode for actual protection."
                    ),
                    "method": "GET",
                })
                self.score += weight * 0.2
                self.grade_details["CSP"] = {"status": "REPORT-ONLY", "score": round(weight * 0.2, 1), "max": weight}
                return

            self.findings.append({
                "type": "Missing Content-Security-Policy",
                "severity": "high",
                "endpoint": self.target,
                "details": (
                    "Content-Security-Policy header is missing. "
                    "Without CSP, the application is vulnerable to XSS attacks, "
                    "clickjacking via inline frames, and data exfiltration."
                ),
                "method": "GET",
            })
            self.grade_details["CSP"] = {"status": "MISSING", "score": 0, "max": weight}
            return

        score = weight * 0.3  # Base for having CSP

        # Parse directives
        directives = {}
        for directive in csp.split(";"):
            directive = directive.strip()
            if not directive:
                continue
            parts = directive.split(None, 1)
            name = parts[0].lower()
            value = parts[1] if len(parts) > 1 else ""
            directives[name] = value

        # Check for critical directives
        if "default-src" in directives:
            score += weight * 0.15
        else:
            self.findings.append({
                "type": "CSP Missing default-src",
                "severity": "medium",
                "endpoint": self.target,
                "details": "CSP lacks 'default-src' fallback directive. Resources not covered by specific directives have no restrictions.",
                "method": "GET",
            })

        if "script-src" in directives:
            score += weight * 0.15
        if "style-src" in directives:
            score += weight * 0.05
        if "frame-ancestors" in directives:
            score += weight * 0.1

        # Check for dangerous values
        for unsafe_pattern, description in self.CSP_UNSAFE_PATTERNS:
            for directive_name, directive_value in directives.items():
                if unsafe_pattern in directive_value:
                    severity = "high" if unsafe_pattern in ("unsafe-inline", "unsafe-eval", "*") else "medium"
                    self.findings.append({
                        "type": f"CSP Dangerous Directive ({directive_name})",
                        "severity": severity,
                        "endpoint": self.target,
                        "details": (
                            f"CSP directive '{directive_name}' contains '{unsafe_pattern}': "
                            f"{description}. Value: {directive_value[:100]}"
                        ),
                        "method": "GET",
                    })
                    score -= weight * 0.1  # Penalty

        score = max(0, score)
        self.score += score
        self.grade_details["CSP"] = {"status": "PRESENT", "directives": len(directives), "score": round(score, 1), "max": weight}

    # ── X-Content-Type-Options ───────────────────────────────────
    def _analyze_xcto(self, headers: dict):
        weight = self.HEADER_WEIGHTS["X-Content-Type-Options"]
        val = headers.get("X-Content-Type-Options", "")

        if val.lower() == "nosniff":
            self.score += weight
            self.grade_details["X-Content-Type-Options"] = {"status": "PASS", "score": weight, "max": weight}
        else:
            self.findings.append({
                "type": "Missing X-Content-Type-Options",
                "severity": "medium",
                "endpoint": self.target,
                "details": (
                    "X-Content-Type-Options: nosniff is missing. "
                    "Browsers may MIME-sniff responses, potentially executing "
                    "uploaded files as scripts."
                ),
                "method": "GET",
            })
            self.grade_details["X-Content-Type-Options"] = {"status": "MISSING", "score": 0, "max": weight}

    # ── X-Frame-Options ──────────────────────────────────────────
    def _analyze_xfo(self, headers: dict):
        weight = self.HEADER_WEIGHTS["X-Frame-Options"]
        val = headers.get("X-Frame-Options", "").upper()

        if val in ("DENY", "SAMEORIGIN"):
            self.score += weight
            self.grade_details["X-Frame-Options"] = {"status": "PASS", "value": val, "score": weight, "max": weight}
        elif val:
            self.score += weight * 0.5
            self.grade_details["X-Frame-Options"] = {"status": "WEAK", "value": val, "score": round(weight * 0.5, 1), "max": weight}
        else:
            self.findings.append({
                "type": "Missing X-Frame-Options",
                "severity": "medium",
                "endpoint": self.target,
                "details": (
                    "X-Frame-Options header is missing. "
                    "The page can be embedded in iframes, enabling clickjacking attacks. "
                    "Set to DENY or SAMEORIGIN."
                ),
                "method": "GET",
            })
            self.grade_details["X-Frame-Options"] = {"status": "MISSING", "score": 0, "max": weight}

    # ── Referrer-Policy ──────────────────────────────────────────
    def _analyze_referrer(self, headers: dict):
        weight = self.HEADER_WEIGHTS["Referrer-Policy"]
        val = headers.get("Referrer-Policy", "").lower()

        strict_policies = ["no-referrer", "strict-origin-when-cross-origin", "same-origin", "strict-origin"]
        if val in strict_policies:
            self.score += weight
            self.grade_details["Referrer-Policy"] = {"status": "PASS", "value": val, "score": weight, "max": weight}
        elif val:
            self.score += weight * 0.5
            self.grade_details["Referrer-Policy"] = {"status": "WEAK", "value": val, "score": round(weight * 0.5, 1), "max": weight}
        else:
            self.findings.append({
                "type": "Missing Referrer-Policy",
                "severity": "low",
                "endpoint": self.target,
                "details": "Referrer-Policy not set. Full URLs may leak via the Referer header to third parties.",
                "method": "GET",
            })
            self.grade_details["Referrer-Policy"] = {"status": "MISSING", "score": 0, "max": weight}

    # ── Permissions-Policy ───────────────────────────────────────
    def _analyze_permissions(self, headers: dict):
        weight = self.HEADER_WEIGHTS["Permissions-Policy"]
        val = headers.get("Permissions-Policy", "") or headers.get("Feature-Policy", "")

        if val:
            self.score += weight
            self.grade_details["Permissions-Policy"] = {"status": "PASS", "score": weight, "max": weight}
        else:
            self.findings.append({
                "type": "Missing Permissions-Policy",
                "severity": "low",
                "endpoint": self.target,
                "details": (
                    "Permissions-Policy header is missing. Browser features like "
                    "camera, microphone, and geolocation are unrestricted."
                ),
                "method": "GET",
            })
            self.grade_details["Permissions-Policy"] = {"status": "MISSING", "score": 0, "max": weight}

    # ── Cross-Origin headers ─────────────────────────────────────
    def _analyze_cross_origin(self, headers: dict):
        for header_name in ["Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy", "Cross-Origin-Embedder-Policy"]:
            weight = self.HEADER_WEIGHTS.get(header_name, 5)
            val = headers.get(header_name, "")
            if val:
                self.score += weight
                self.grade_details[header_name] = {"status": "PASS", "value": val, "score": weight, "max": weight}
            else:
                self.grade_details[header_name] = {"status": "MISSING", "score": 0, "max": weight}

    # ── Cache-Control for APIs ───────────────────────────────────
    def _analyze_cache(self, headers: dict):
        weight = self.HEADER_WEIGHTS["Cache-Control"]
        cc = headers.get("Cache-Control", "").lower()
        pragma = headers.get("Pragma", "").lower()

        if "no-store" in cc or "no-cache" in cc:
            self.score += weight
            self.grade_details["Cache-Control"] = {"status": "PASS", "score": weight, "max": weight}
        elif "private" in cc:
            self.score += weight * 0.7
            self.grade_details["Cache-Control"] = {"status": "PARTIAL", "score": round(weight * 0.7, 1), "max": weight}
        else:
            self.findings.append({
                "type": "Missing Cache-Control for Sensitive API",
                "severity": "low",
                "endpoint": self.target,
                "details": (
                    "API responses may be cached by intermediate proxies. "
                    "For sensitive data, set: Cache-Control: no-store, no-cache, must-revalidate"
                ),
                "method": "GET",
            })
            self.grade_details["Cache-Control"] = {"status": "MISSING", "score": 0, "max": weight}

    # ── Information leakage ──────────────────────────────────────
    def _analyze_info_leakage(self, headers: dict):
        weight = self.HEADER_WEIGHTS["Information-Leakage"]
        leaked = []

        leaky_headers = {
            "Server": "Web server software and version",
            "X-Powered-By": "Backend technology stack",
            "X-AspNet-Version": "ASP.NET version",
            "X-AspNetMvc-Version": "ASP.NET MVC version",
            "X-Runtime": "Request processing time (allows timing attacks)",
            "X-Debug-Token": "Debug token (should never be in production)",
            "X-Debug-Token-Link": "Debug panel link",
        }

        for header, description in leaky_headers.items():
            if header in headers:
                leaked.append(f"{header}: {headers[header]}")

        if leaked:
            penalty = min(weight, len(leaked) * 2)
            self.findings.append({
                "type": "Information Leakage via Headers",
                "severity": "low",
                "endpoint": self.target,
                "details": (
                    f"Server leaks {len(leaked)} information header(s): "
                    f"{'; '.join(leaked)}. "
                    f"Remove these headers to reduce the attack surface."
                ),
                "method": "GET",
            })
            self.grade_details["Info-Leakage"] = {"status": "LEAKING", "headers": leaked, "score": 0, "max": weight}
        else:
            self.score += weight
            self.grade_details["Info-Leakage"] = {"status": "CLEAN", "score": weight, "max": weight}

    # ── Cookie analysis ──────────────────────────────────────────
    def _analyze_cookies(self, cookies):
        if not cookies:
            return

        for cookie in cookies:
            issues = []
            if not cookie.secure:
                issues.append("Missing 'Secure' flag (transmitted over HTTP)")
            if "httponly" not in str(cookie._rest).lower() and not getattr(cookie, "has_nonstandard_attr", lambda x: False)("HttpOnly"):
                issues.append("Missing 'HttpOnly' flag (accessible via JavaScript)")
            if not hasattr(cookie, "samesite") or not cookie.get_nonstandard_attr("SameSite"):
                issues.append("Missing 'SameSite' attribute (CSRF risk)")

            if issues:
                self.findings.append({
                    "type": "Insecure Cookie Configuration",
                    "severity": "medium",
                    "endpoint": self.target,
                    "details": (
                        f"Cookie '{cookie.name}' has security issues: "
                        f"{'; '.join(issues)}"
                    ),
                    "method": "GET",
                })

    # ── Grade calculation ────────────────────────────────────────
    def _calculate_grade(self) -> str:
        """Calculate overall security grade from A+ to F."""
        pct = (self.score / self.MAX_SCORE) * 100 if self.MAX_SCORE > 0 else 0

        if pct >= 95:
            return "A+"
        elif pct >= 85:
            return "A"
        elif pct >= 75:
            return "B"
        elif pct >= 60:
            return "C"
        elif pct >= 40:
            return "D"
        else:
            return "F"

    # ── Main scan ────────────────────────────────────────────────
    def scan(self):
        """Run the full security headers analysis."""
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}Starting Security Headers Analysis...{Fore.RESET}")

        headers, cookies, final_url = self._fetch_headers()
        if headers is None:
            print(f"{Fore.RED}[-] Failed to fetch headers from target{Fore.RESET}")
            return

        if final_url != self.target:
            print(f"{Fore.CYAN}[*] Followed redirect to: {final_url}{Fore.RESET}")

        self.endpoints.append(final_url or self.target)

        # Run all analyses
        print(f"{Fore.CYAN}[*] Analyzing HSTS...{Fore.RESET}", end="", flush=True)
        self._analyze_hsts(headers)
        print(f" {Fore.GREEN}Done{Fore.RESET}")

        print(f"{Fore.CYAN}[*] Analyzing Content-Security-Policy...{Fore.RESET}", end="", flush=True)
        self._analyze_csp(headers)
        print(f" {Fore.GREEN}Done{Fore.RESET}")

        print(f"{Fore.CYAN}[*] Analyzing X-Content-Type-Options...{Fore.RESET}", end="", flush=True)
        self._analyze_xcto(headers)
        print(f" {Fore.GREEN}Done{Fore.RESET}")

        print(f"{Fore.CYAN}[*] Analyzing X-Frame-Options...{Fore.RESET}", end="", flush=True)
        self._analyze_xfo(headers)
        print(f" {Fore.GREEN}Done{Fore.RESET}")

        print(f"{Fore.CYAN}[*] Analyzing Referrer-Policy...{Fore.RESET}", end="", flush=True)
        self._analyze_referrer(headers)
        print(f" {Fore.GREEN}Done{Fore.RESET}")

        print(f"{Fore.CYAN}[*] Analyzing Permissions-Policy...{Fore.RESET}", end="", flush=True)
        self._analyze_permissions(headers)
        print(f" {Fore.GREEN}Done{Fore.RESET}")

        print(f"{Fore.CYAN}[*] Analyzing Cross-Origin headers...{Fore.RESET}", end="", flush=True)
        self._analyze_cross_origin(headers)
        print(f" {Fore.GREEN}Done{Fore.RESET}")

        print(f"{Fore.CYAN}[*] Analyzing Cache-Control...{Fore.RESET}", end="", flush=True)
        self._analyze_cache(headers)
        print(f" {Fore.GREEN}Done{Fore.RESET}")

        print(f"{Fore.CYAN}[*] Checking information leakage...{Fore.RESET}", end="", flush=True)
        self._analyze_info_leakage(headers)
        print(f" {Fore.GREEN}Done{Fore.RESET}")

        print(f"{Fore.CYAN}[*] Analyzing cookie security...{Fore.RESET}", end="", flush=True)
        self._analyze_cookies(cookies)
        print(f" {Fore.GREEN}Done{Fore.RESET}")

        # Calculate grade
        grade = self._calculate_grade()
        pct = (self.score / self.MAX_SCORE) * 100 if self.MAX_SCORE > 0 else 0

        # Add grade as an info finding
        self.findings.append({
            "type": f"Security Headers Grade: {grade} ({pct:.0f}%)",
            "severity": "critical" if grade in ("D", "F") else "medium" if grade == "C" else "info",
            "endpoint": self.target,
            "details": (
                f"Overall security headers score: {self.score:.1f}/{self.MAX_SCORE} ({pct:.0f}%). "
                f"Grade: {grade}. "
                f"Headers analyzed: {len(self.grade_details)}"
            ),
            "method": "GET",
        })

        grade_color = Fore.GREEN if grade.startswith("A") else Fore.YELLOW if grade in ("B", "C") else Fore.RED
        print(f"\n{Fore.MAGENTA}[+] {Fore.CYAN}Security Headers Grade: {grade_color}{grade} ({pct:.0f}%){Fore.RESET}")
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}Findings: {len(self.findings)} issue(s){Fore.RESET}")


def security_headers_scan(target: str):
    """Entry point for the orchestrator."""
    analyzer = SecurityHeadersAnalyzer(target)
    analyzer.scan()
    return {
        "findings": analyzer.findings,
        "endpoints": analyzer.endpoints,
    }
