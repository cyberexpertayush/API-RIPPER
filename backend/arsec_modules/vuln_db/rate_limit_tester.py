#!/usr/bin/env python3
"""
Advanced Rate Limit & Resource Exhaustion Tester
Deep analysis of API rate limiting implementations including:
  - Calibrated burst testing with statistical analysis
  - Per-endpoint rate limit profiling
  - Rate limit header parsing (X-RateLimit-*, Retry-After)
  - Bypass techniques (IP rotation headers, case variation, encoding)
  - Cost-based analysis (response time degradation)
  - Concurrent connection exhaustion testing
  - Slowloris-style connection hold detection
"""

from colorama import Fore
import requests
import urllib3
import time
import re
import os
import statistics
import logging
from urllib.parse import urlparse, quote
from typing import Dict, List, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)


class RateLimitTester:
    """Advanced rate limiting analysis with bypass techniques"""

    # Endpoints typically protected by rate limiting
    SENSITIVE_PATHS = [
        "/api/auth/login", "/api/login", "/login", "/auth/login",
        "/api/v1/login", "/api/v1/auth/login",
        "/api/auth/token", "/api/v1/auth/token", "/oauth/token",
        "/api/register", "/register", "/api/v1/register",
        "/api/password/reset", "/api/v1/password/reset",
        "/api/otp/verify", "/api/v1/otp/verify",
        "/api/forgot-password", "/forgot-password",
    ]

    # Headers used to bypass IP-based rate limiting
    IP_BYPASS_HEADERS = [
        {"X-Forwarded-For": "127.0.0.{}"},
        {"X-Real-IP": "10.0.0.{}"},
        {"X-Originating-IP": "192.168.1.{}"},
        {"X-Client-IP": "172.16.0.{}"},
        {"X-Remote-Addr": "10.10.10.{}"},
        {"X-Remote-IP": "192.168.0.{}"},
        {"True-Client-IP": "10.0.1.{}"},
        {"CF-Connecting-IP": "172.16.1.{}"},
        {"X-Forwarded-Host": "bypass{}.example.com"},
        {"X-Host": "bypass{}.example.com"},
    ]

    def __init__(self, target_url: str):
        self.target = target_url.rstrip("/")
        self.parsed = urlparse(self.target)
        self.base = f"{self.parsed.scheme}://{self.parsed.netloc}"
        self.findings: List[Dict[str, Any]] = []
        self.endpoints: List[str] = []
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })

    # ── Baseline calibration ─────────────────────────────────────
    def _get_baseline(self, url: str, method: str = "GET") -> Dict[str, Any]:
        """Measure baseline response characteristics."""
        timings = []
        statuses = []
        sizes = []

        for _ in range(3):
            try:
                start = time.time()
                if method == "POST":
                    r = self.session.post(url, json={"test": "baseline"}, timeout=10)
                else:
                    r = self.session.get(url, timeout=10)
                elapsed = time.time() - start
                timings.append(elapsed)
                statuses.append(r.status_code)
                sizes.append(len(r.content))
                time.sleep(0.5)  # Wait between baseline requests
            except Exception:
                pass

        if not timings:
            return {"available": False}

        return {
            "available": True,
            "avg_time": statistics.mean(timings),
            "std_time": statistics.stdev(timings) if len(timings) > 1 else 0,
            "mode_status": max(set(statuses), key=statuses.count),
            "avg_size": statistics.mean(sizes) if sizes else 0,
        }

    # ── Rate limit header analysis ───────────────────────────────
    def _analyze_rate_limit_headers(self, response: requests.Response) -> Dict[str, Any]:
        """Parse and analyze rate-limiting headers."""
        headers = response.headers
        info = {}

        # Standard rate limit headers
        patterns = {
            "limit": [
                "X-RateLimit-Limit", "X-Rate-Limit-Limit",
                "RateLimit-Limit", "X-Rate-Limit",
            ],
            "remaining": [
                "X-RateLimit-Remaining", "X-Rate-Limit-Remaining",
                "RateLimit-Remaining",
            ],
            "reset": [
                "X-RateLimit-Reset", "X-Rate-Limit-Reset",
                "RateLimit-Reset", "Retry-After",
            ],
        }

        for category, header_names in patterns.items():
            for name in header_names:
                if name in headers:
                    info[category] = {"header": name, "value": headers[name]}
                    break

        return info

    # ── Burst test ───────────────────────────────────────────────
    def _burst_test(self, url: str, count: int = 30, method: str = "GET") -> Dict[str, Any]:
        """Send a burst of rapid requests and analyze the response pattern."""
        results = []

        for i in range(count):
            try:
                start = time.time()
                if method == "POST":
                    r = self.session.post(
                        url,
                        json={"username": f"test{i}", "password": "test"},
                        timeout=10,
                    )
                else:
                    r = self.session.get(url, timeout=10)
                elapsed = time.time() - start

                rate_info = self._analyze_rate_limit_headers(r)

                results.append({
                    "request_num": i + 1,
                    "status": r.status_code,
                    "time": elapsed,
                    "size": len(r.content),
                    "rate_headers": rate_info,
                })
            except requests.exceptions.ConnectionError:
                results.append({
                    "request_num": i + 1,
                    "status": 0,
                    "time": 0,
                    "error": "connection_refused",
                })
            except requests.exceptions.ReadTimeout:
                results.append({
                    "request_num": i + 1,
                    "status": 0,
                    "time": 10,
                    "error": "timeout",
                })

        return self._analyze_burst_results(results, count)

    # ── Burst result analysis ────────────────────────────────────
    def _analyze_burst_results(self, results: list, total: int) -> Dict[str, Any]:
        """Statistical analysis of burst test results."""
        statuses = [r["status"] for r in results if r.get("status")]
        timings = [r["time"] for r in results if r.get("time", 0) > 0]
        errors = [r for r in results if r.get("error")]

        analysis = {
            "total_requests": total,
            "successful": sum(1 for s in statuses if s == 200),
            "rate_limited": sum(1 for s in statuses if s == 429),
            "server_errors": sum(1 for s in statuses if s >= 500),
            "client_errors": sum(1 for s in statuses if 400 <= s < 500 and s != 429),
            "connection_errors": len(errors),
            "has_rate_limiting": False,
            "rate_limit_threshold": None,
            "avg_response_time": statistics.mean(timings) if timings else 0,
            "max_response_time": max(timings) if timings else 0,
        }

        # Detect rate limiting
        if analysis["rate_limited"] > 0:
            analysis["has_rate_limiting"] = True
            # Find when rate limiting kicked in
            for r in results:
                if r.get("status") == 429:
                    analysis["rate_limit_threshold"] = r["request_num"]
                    break

        # Check for response time degradation (soft rate limiting)
        if len(timings) >= 10:
            first_half = timings[:len(timings)//2]
            second_half = timings[len(timings)//2:]
            avg_first = statistics.mean(first_half)
            avg_second = statistics.mean(second_half)
            if avg_second > avg_first * 3:  # 3x slowdown
                analysis["has_rate_limiting"] = True
                analysis["soft_limiting"] = True
                analysis["slowdown_factor"] = round(avg_second / avg_first, 2)

        # Check for rate limit headers
        for r in results:
            if r.get("rate_headers"):
                analysis["rate_headers_present"] = True
                analysis["rate_headers"] = r["rate_headers"]
                break

        return analysis

    # ── IP rotation bypass ───────────────────────────────────────
    def _test_ip_bypass(self, url: str, method: str = "GET"):
        """Test if rate limiting can be bypassed with IP spoofing headers."""
        print(f"{Fore.CYAN}[*] Testing rate limit IP bypass...{Fore.RESET}", end="", flush=True)

        # First, trigger rate limiting
        for _ in range(40):
            try:
                self.session.get(url, timeout=5)
            except Exception:
                pass

        # Check if we're rate limited
        try:
            r = self.session.get(url, timeout=5)
            if r.status_code != 429:
                print(f" {Fore.YELLOW}Skipped (no rate limiting detected){Fore.RESET}")
                return
        except Exception:
            print(f" {Fore.YELLOW}Skipped{Fore.RESET}")
            return

        # Try bypass headers
        for i, header_template in enumerate(self.IP_BYPASS_HEADERS):
            bypass_headers = {}
            for k, v in header_template.items():
                bypass_headers[k] = v.format(i + 1)

            try:
                r = self.session.get(url, headers=bypass_headers, timeout=5)
                if r.status_code == 200:
                    header_name = list(header_template.keys())[0]
                    self.findings.append({
                        "type": "Rate Limit Bypass via IP Spoofing",
                        "severity": "high",
                        "endpoint": url,
                        "details": (
                            f"Rate limiting can be bypassed using the '{header_name}' header. "
                            f"The server trusts client-provided IP headers for rate limiting, "
                            f"allowing unlimited requests by rotating the header value."
                        ),
                        "method": method,
                    })
                    print(f" {Fore.RED}BYPASS FOUND ({header_name}){Fore.RESET}")
                    return
            except Exception:
                pass

        print(f" {Fore.GREEN}No bypass found{Fore.RESET}")

    # ── URL encoding bypass ──────────────────────────────────────
    def _test_encoding_bypass(self, url: str):
        """Test rate limit bypass via URL encoding and path variations."""
        parsed = urlparse(url)
        path = parsed.path

        variations = [
            path.upper(),                          # Case variation
            path + "/",                            # Trailing slash
            path + "?",                            # Empty query
            path.replace("/", "//"),               # Double slash
            path + "/..",                           # Path traversal noop
            quote(path, safe=""),                   # URL encoded
            path + "%20",                          # Space encoding
            path.replace("/", "/%2e/"),            # Dot encoding
        ]

        for variant in variations:
            test_url = f"{parsed.scheme}://{parsed.netloc}{variant}"
            if variant == path:
                continue
            try:
                r = self.session.get(test_url, timeout=5)
                if r.status_code == 200:
                    self.findings.append({
                        "type": "Rate Limit Bypass via URL Variation",
                        "severity": "medium",
                        "endpoint": test_url,
                        "details": (
                            f"Rate limiting can be bypassed using URL path variation: "
                            f"'{variant}'. Different URL representations may be treated "
                            f"as separate rate-limit buckets."
                        ),
                        "method": "GET",
                    })
                    return
            except Exception:
                pass

    # ── Concurrent connection test ───────────────────────────────
    def _test_concurrent_connections(self, url: str, workers: int = 15):
        """Test server behavior under concurrent connections."""
        print(f"{Fore.CYAN}[*] Testing concurrent connection handling ({workers} workers)...{Fore.RESET}", end="", flush=True)

        def make_request(n):
            try:
                s = requests.Session()
                s.verify = False
                start = time.time()
                r = s.get(url, timeout=15, headers={
                    "User-Agent": f"ConcurrencyTest-{n}"
                })
                return {
                    "worker": n,
                    "status": r.status_code,
                    "time": time.time() - start,
                }
            except Exception as e:
                return {"worker": n, "error": str(type(e).__name__)}

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(make_request, i) for i in range(workers)]
            results = [f.result() for f in as_completed(futures)]

        errors = sum(1 for r in results if "error" in r)
        successes = sum(1 for r in results if r.get("status") == 200)
        timings = [r["time"] for r in results if "time" in r]

        if errors > workers * 0.5:
            self.findings.append({
                "type": "Insufficient Connection Handling",
                "severity": "medium",
                "endpoint": url,
                "details": (
                    f"Server dropped {errors}/{workers} concurrent connections. "
                    f"This indicates potential vulnerability to connection exhaustion DoS."
                ),
                "method": "GET",
            })

        if timings and max(timings) > 10:
            self.findings.append({
                "type": "Slow Response Under Load",
                "severity": "low",
                "endpoint": url,
                "details": (
                    f"Maximum response time under {workers} concurrent connections: "
                    f"{max(timings):.2f}s (avg: {statistics.mean(timings):.2f}s). "
                    f"Server may be vulnerable to slowloris-style attacks."
                ),
                "method": "GET",
            })

        print(f" {Fore.GREEN}Done ({successes}/{workers} OK, avg {statistics.mean(timings):.2f}s){Fore.RESET}" if timings else f" {Fore.RED}Failed{Fore.RESET}")

    # ── Main scan ────────────────────────────────────────────────
    def scan(self):
        """Run the full rate limit testing suite."""
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}Starting Rate Limit & Resource Exhaustion Analysis...{Fore.RESET}")

        # Discover testable endpoints
        test_endpoints = [self.target]
        for path in self.SENSITIVE_PATHS:
            url = f"{self.base}{path}"
            try:
                r = self.session.get(url, timeout=5)
                if r.status_code in [200, 401, 403, 405, 422]:
                    test_endpoints.append(url)
                    self.endpoints.append(url)
            except Exception:
                pass

        test_endpoints = list(set(test_endpoints))[:5]  # Test up to 5 endpoints
        print(f"{Fore.CYAN}[*] Testing {len(test_endpoints)} endpoint(s)...{Fore.RESET}")

        for url in test_endpoints:
            print(f"\n{Fore.CYAN}[*] Analyzing: {url}{Fore.RESET}")

            # Get baseline
            baseline = self._get_baseline(url)
            if not baseline["available"]:
                continue

            # Burst test
            print(f"{Fore.CYAN}[*] Running burst test (30 rapid requests)...{Fore.RESET}", end="", flush=True)
            burst_result = self._burst_test(url, count=30)

            if not burst_result["has_rate_limiting"]:
                self.findings.append({
                    "type": "No Rate Limiting Detected",
                    "severity": "medium",
                    "endpoint": url,
                    "details": (
                        f"No rate limiting detected after {burst_result['total_requests']} rapid requests. "
                        f"{burst_result['successful']} succeeded, "
                        f"avg response time: {burst_result['avg_response_time']:.3f}s. "
                        f"This endpoint is vulnerable to brute-force, credential stuffing, "
                        f"and denial-of-service attacks."
                    ),
                    "method": "GET",
                })
                print(f" {Fore.RED}NO RATE LIMITING{Fore.RESET}")
            else:
                threshold = burst_result.get("rate_limit_threshold", "?")
                soft = burst_result.get("soft_limiting", False)
                print(f" {Fore.GREEN}Rate limited (threshold: ~{threshold}, soft={soft}){Fore.RESET}")

                # If rate limited, test bypass techniques
                self._test_ip_bypass(url)
                self._test_encoding_bypass(url)

            # Check rate limit header quality
            if burst_result.get("rate_headers_present"):
                headers = burst_result.get("rate_headers", {})
                self.findings.append({
                    "type": "Rate Limit Headers Present",
                    "severity": "info",
                    "endpoint": url,
                    "details": (
                        f"Rate limiting headers detected: "
                        f"{', '.join(h.get('header', '') for h in headers.values())}. "
                        f"This is good practice for client-side rate limit awareness."
                    ),
                    "method": "GET",
                })
            elif burst_result["has_rate_limiting"]:
                self.findings.append({
                    "type": "Rate Limiting Without Headers",
                    "severity": "low",
                    "endpoint": url,
                    "details": (
                        "Server enforces rate limiting but doesn't send rate limit "
                        "headers (X-RateLimit-Limit, X-RateLimit-Remaining, etc.). "
                        "Clients cannot proactively avoid hitting limits."
                    ),
                    "method": "GET",
                })

        # Concurrent connection test
        self._test_concurrent_connections(self.target)

        # Summary
        if self.findings:
            critical_medium = sum(1 for f in self.findings if f["severity"] in ("critical", "high", "medium"))
            print(f"\n{Fore.MAGENTA}[+] {Fore.CYAN}Rate Limit Analysis Complete: {len(self.findings)} findings ({critical_medium} actionable){Fore.RESET}")
        else:
            print(f"\n{Fore.GREEN}[+] Rate Limit Analysis Complete: No issues found{Fore.RESET}")


def rate_limit_scan(target: str):
    """Entry point for the orchestrator."""
    tester = RateLimitTester(target)
    tester.scan()
    return {
        "findings": tester.findings,
        "endpoints": tester.endpoints,
    }
