#!/usr/bin/env python3
"""
Sensitive Data Exposure Scanner
Deep analysis of API responses for sensitive data leakage including:
  - PII detection (emails, phones, addresses, SSNs, credit cards)
  - Secret/credential detection (API keys, passwords, tokens, connection strings)
  - Internal infrastructure leakage (internal IPs, hostnames, paths, stack traces)
  - Debug / verbose error response analysis
  - Source code leakage in responses
  - Database query leakage in error messages
  - Environment variable exposure
  - Backup file and source map enumeration
  - .git/.svn/.env exposure testing
"""

from colorama import Fore
import requests
import urllib3
import json
import re
import os
import logging
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Any, Optional

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)


class SensitiveDataScanner:
    """Advanced sensitive data exposure detection"""

    # ── PII Patterns ─────────────────────────────────────────────
    PII_PATTERNS = {
        "email": {
            "regex": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            "severity": "medium",
            "description": "Email address exposed in response",
        },
        "phone_number": {
            "regex": r'(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}',
            "severity": "medium",
            "description": "Phone number exposed in response",
        },
        "ssn": {
            "regex": r'\b\d{3}-\d{2}-\d{4}\b',
            "severity": "critical",
            "description": "Social Security Number (SSN) exposed",
        },
        "credit_card": {
            "regex": r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
            "severity": "critical",
            "description": "Credit card number exposed in response",
        },
        "ipv4_internal": {
            "regex": r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b',
            "severity": "medium",
            "description": "Internal/private IP address leaked",
        },
    }

    # ── Secret/Credential Patterns ───────────────────────────────
    SECRET_PATTERNS = {
        "aws_access_key": {
            "regex": r'(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}',
            "severity": "critical",
            "description": "AWS Access Key ID exposed",
        },
        "aws_secret_key": {
            "regex": r'(?:aws)?_?(?:secret)?_?(?:access)?_?key["\s:=]+[A-Za-z0-9/+=]{40}',
            "severity": "critical",
            "description": "AWS Secret Access Key exposed",
        },
        "github_token": {
            "regex": r'gh[ps]_[A-Za-z0-9_]{36,}',
            "severity": "critical",
            "description": "GitHub Personal Access Token exposed",
        },
        "generic_api_key": {
            "regex": r'(?:api[_-]?key|apikey|api_secret|api[_-]?token)["\s:=]+["\'`]?([A-Za-z0-9_\-]{20,})["\'`]?',
            "severity": "high",
            "description": "API key/token exposed in response",
        },
        "password_field": {
            "regex": r'(?:"password"|"passwd"|"pwd"|"pass"|"secret"|"credential")["\s]*:\s*"[^"]{1,100}"',
            "severity": "critical",
            "description": "Password or secret exposed in API response",
        },
        "bearer_token": {
            "regex": r'[Bb]earer\s+[A-Za-z0-9_\-\.]{20,}',
            "severity": "high",
            "description": "Bearer token exposed in response",
        },
        "private_key": {
            "regex": r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
            "severity": "critical",
            "description": "Private key exposed in response",
        },
        "connection_string": {
            "regex": r'(?:mongodb|mysql|postgres|redis|amqp|smtp)://[^\s<>"\']{10,}',
            "severity": "critical",
            "description": "Database/service connection string exposed",
        },
        "jwt_token": {
            "regex": r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*',
            "severity": "medium",
            "description": "JWT token exposed in response body",
        },
        "slack_webhook": {
            "regex": r'https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24}',
            "severity": "high",
            "description": "Slack webhook URL exposed",
        },
        "google_api_key": {
            "regex": r'AIza[0-9A-Za-z_-]{35}',
            "severity": "high",
            "description": "Google API key exposed",
        },
    }

    # ── Infrastructure Leakage Patterns ──────────────────────────
    INFRA_PATTERNS = {
        "stack_trace_python": {
            "regex": r'Traceback \(most recent call last\)',
            "severity": "high",
            "description": "Python stack trace exposed in error response",
        },
        "stack_trace_java": {
            "regex": r'at\s+[\w.$]+\([\w.]+:\d+\)',
            "severity": "high",
            "description": "Java stack trace exposed in error response",
        },
        "stack_trace_csharp": {
            "regex": r'at\s+[\w.]+\s+in\s+[A-Za-z]:\\[^\s]+:\s*line\s+\d+',
            "severity": "high",
            "description": "C#/.NET stack trace with file paths exposed",
        },
        "stack_trace_node": {
            "regex": r'at\s+\w+\s+\(/[^\s]+\.js:\d+:\d+\)',
            "severity": "high",
            "description": "Node.js stack trace with file paths exposed",
        },
        "sql_error": {
            "regex": r'(?:SQL syntax|mysql_fetch|ORA-\d{5}|PG::Error|sqlite3\.OperationalError|SQLSTATE\[)',
            "severity": "high",
            "description": "SQL error message leaking database details",
        },
        "sql_query": {
            "regex": r'(?:SELECT|INSERT|UPDATE|DELETE)\s+.+\s+(?:FROM|INTO|SET)\s+\w+',
            "severity": "critical",
            "description": "Raw SQL query exposed in response",
        },
        "file_path_unix": {
            "regex": r'/(?:home|var|usr|etc|opt|tmp|root)/[\w/._-]{5,}',
            "severity": "medium",
            "description": "Unix file system path leaked",
        },
        "file_path_windows": {
            "regex": r'[A-Za-z]:\\(?:Users|Program Files|Windows|inetpub|wwwroot)\\[^\s<>"]{5,}',
            "severity": "medium",
            "description": "Windows file system path leaked",
        },
        "debug_mode": {
            "regex": r'(?:DEBUG\s*=\s*True|debug\s*mode|DJANGO_DEBUG|APP_DEBUG|NODE_ENV.*development)',
            "severity": "high",
            "description": "Application running in debug mode",
        },
        "env_variable": {
            "regex": r'(?:DB_PASSWORD|DATABASE_URL|SECRET_KEY|ENCRYPTION_KEY|REDIS_URL|SMTP_PASS)\s*[=:]\s*[^\s]{3,}',
            "severity": "critical",
            "description": "Environment variable with sensitive value exposed",
        },
    }

    # ── Sensitive file paths to check ────────────────────────────
    SENSITIVE_PATHS = [
        "/.env", "/.env.local", "/.env.production", "/.env.backup",
        "/.git/config", "/.git/HEAD",
        "/.svn/entries",
        "/config.json", "/config.yml", "/config.yaml",
        "/wp-config.php.bak", "/wp-config.php~",
        "/server-status", "/server-info",
        "/.htaccess", "/.htpasswd",
        "/phpinfo.php", "/info.php",
        "/debug", "/debug/vars", "/debug/pprof",
        "/actuator", "/actuator/env", "/actuator/health",
        "/swagger.json", "/swagger.yaml", "/openapi.json",
        "/api-docs", "/api/docs",
        "/.DS_Store",
        "/robots.txt", "/sitemap.xml",
        "/crossdomain.xml", "/clientaccesspolicy.xml",
        "/elmah.axd", "/errorlog",
        "/trace.axd",
        "/__debug__",
        "/graphql",  # Introspection might leak schema
        "/.well-known/security.txt",
        "/backup", "/backup.sql", "/dump.sql",
        "/database.sql", "/db.sql",
        "/.bash_history",
        "/id_rsa", "/.ssh/id_rsa",
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

    # ── Scan response body ───────────────────────────────────────
    def _scan_response_body(self, url: str, body: str, context: str = ""):
        """Scan a response body for all sensitive data patterns."""
        if not body or len(body) < 10:
            return

        all_patterns = {
            **self.PII_PATTERNS,
            **self.SECRET_PATTERNS,
            **self.INFRA_PATTERNS,
        }

        found_types = set()

        for name, pattern_info in all_patterns.items():
            try:
                matches = re.findall(pattern_info["regex"], body, re.IGNORECASE)
                if matches and name not in found_types:
                    found_types.add(name)

                    # Redact actual values for safety
                    sample = matches[0] if isinstance(matches[0], str) else str(matches[0])
                    if len(sample) > 30:
                        sample = sample[:15] + "..." + sample[-10:]

                    self.findings.append({
                        "type": f"Data Exposure: {name.replace('_', ' ').title()}",
                        "severity": pattern_info["severity"],
                        "endpoint": url,
                        "details": (
                            f"{pattern_info['description']}. "
                            f"Found {len(matches)} instance(s) in {context or 'response body'}. "
                            f"Sample (redacted): {sample}"
                        ),
                        "method": "GET",
                    })
            except re.error:
                pass

    # ── Error trigger testing ────────────────────────────────────
    def _test_error_responses(self):
        """Trigger error responses to check for verbose error handling."""
        print(f"{Fore.CYAN}[*] Testing error response verbosity...{Fore.RESET}", end="", flush=True)

        error_triggers = [
            # Invalid input
            (f"{self.target}/'", "SQL injection probe"),
            (f"{self.target}/<script>", "XSS probe"),
            (f"{self.target}/{{{{7*7}}}}", "SSTI probe"),
            (f"{self.target}/../../../etc/passwd", "Path traversal"),
            # Non-existent endpoints
            (f"{self.base}/api/v999/nonexistent", "Invalid API version"),
            (f"{self.base}/api/v1/users/999999999", "Invalid resource ID"),
            # Invalid methods
        ]

        for url, trigger_type in error_triggers:
            try:
                r = self.session.get(url, timeout=5)
                if r.status_code >= 400:
                    body = r.text
                    if len(body) > 100:
                        self._scan_response_body(url, body, f"error response ({trigger_type})")
            except Exception:
                pass

        # Test POST with malformed data
        error_post_urls = [
            f"{self.base}/api/login",
            f"{self.base}/api/v1/login",
            f"{self.base}/api/auth",
            self.target,
        ]

        for url in error_post_urls:
            try:
                r = self.session.post(url, data="{{invalid json}}", headers={
                    "Content-Type": "application/json"
                }, timeout=5)
                if r.status_code >= 400:
                    self._scan_response_body(url, r.text, "malformed JSON error")
            except Exception:
                pass

        print(f" {Fore.GREEN}Done{Fore.RESET}")

    # ── Sensitive file enumeration ───────────────────────────────
    def _enumerate_sensitive_files(self):
        """Check for exposed sensitive files and endpoints."""
        print(f"{Fore.CYAN}[*] Enumerating sensitive files ({len(self.SENSITIVE_PATHS)} paths)...{Fore.RESET}", end="", flush=True)

        for path in self.SENSITIVE_PATHS:
            url = f"{self.base}{path}"
            try:
                r = self.session.get(url, timeout=5)
                if r.status_code == 200 and len(r.content) > 10:
                    self.endpoints.append(url)

                    # Determine severity based on what was found
                    severity = "medium"
                    details = f"Sensitive file accessible: {path}"

                    if ".env" in path:
                        severity = "critical"
                        details = f"Environment file exposed at {path}. May contain database credentials, API keys, and secrets."
                        self._scan_response_body(url, r.text, ".env file")
                    elif ".git" in path:
                        severity = "critical"
                        details = f"Git repository exposed at {path}. Full source code may be downloadable."
                    elif "config" in path.lower():
                        severity = "high"
                        details = f"Configuration file exposed at {path}."
                        self._scan_response_body(url, r.text, "config file")
                    elif ".sql" in path or "dump" in path or "backup" in path:
                        severity = "critical"
                        details = f"Database dump/backup file exposed at {path}."
                    elif "phpinfo" in path or "debug" in path or "actuator" in path:
                        severity = "high"
                        details = f"Debug/diagnostic endpoint exposed at {path}."
                        self._scan_response_body(url, r.text, "debug endpoint")
                    elif "swagger" in path or "openapi" in path or "api-docs" in path:
                        severity = "low"
                        details = f"API documentation exposed at {path}. May reveal internal API structure."

                    self.findings.append({
                        "type": f"Sensitive File Exposed: {path}",
                        "severity": severity,
                        "endpoint": url,
                        "details": details,
                        "method": "GET",
                    })

            except Exception:
                pass

        print(f" {Fore.GREEN}Done{Fore.RESET}")

    # ── Source map detection ──────────────────────────────────────
    def _check_source_maps(self):
        """Check for exposed JavaScript source maps."""
        print(f"{Fore.CYAN}[*] Checking for source map exposure...{Fore.RESET}", end="", flush=True)

        try:
            r = self.session.get(self.target, timeout=10)
            # Find JS file references
            js_files = re.findall(r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', r.text)
            js_files += re.findall(r'href=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', r.text)

            for js_file in js_files[:10]:  # Check first 10
                js_url = urljoin(self.target, js_file.split("?")[0])
                map_url = js_url + ".map"

                try:
                    r_map = self.session.get(map_url, timeout=5)
                    if r_map.status_code == 200 and "sources" in r_map.text:
                        self.findings.append({
                            "type": "JavaScript Source Map Exposed",
                            "severity": "medium",
                            "endpoint": map_url,
                            "details": (
                                f"Source map file accessible at {map_url}. "
                                "Attackers can reconstruct original source code, "
                                "revealing business logic, API endpoints, and secrets."
                            ),
                            "method": "GET",
                        })
                        self.endpoints.append(map_url)
                        break
                except Exception:
                    pass
        except Exception:
            pass

        print(f" {Fore.GREEN}Done{Fore.RESET}")

    # ── Main response scanning ───────────────────────────────────
    def _scan_target_responses(self):
        """Scan main target and discovered API endpoints for data leakage."""
        print(f"{Fore.CYAN}[*] Scanning target responses for sensitive data...{Fore.RESET}", end="", flush=True)

        urls_to_scan = [self.target]

        # Discover API endpoints from target page
        try:
            r = self.session.get(self.target, timeout=10)
            self._scan_response_body(self.target, r.text, "main page")

            # Find API URLs in the page
            api_urls = re.findall(
                r'["\'](/api/[^"\']+)["\']', r.text, re.IGNORECASE
            )
            for api_url in api_urls[:15]:
                full_url = urljoin(self.target, api_url)
                urls_to_scan.append(full_url)
        except Exception:
            pass

        # Scan each URL
        for url in urls_to_scan:
            try:
                r = self.session.get(url, timeout=5)
                if r.status_code == 200:
                    self._scan_response_body(url, r.text, "API response")
                    # Also check response headers
                    for hdr_name, hdr_val in r.headers.items():
                        if len(hdr_val) > 20:
                            self._scan_response_body(url, hdr_val, f"header: {hdr_name}")
            except Exception:
                pass

        print(f" {Fore.GREEN}Done{Fore.RESET}")

    # ── Main scan ────────────────────────────────────────────────
    def scan(self):
        """Run the full sensitive data exposure scan."""
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}Starting Sensitive Data Exposure Scan...{Fore.RESET}")

        self._scan_target_responses()
        self._test_error_responses()
        self._enumerate_sensitive_files()
        self._check_source_maps()

        # Summary
        if self.findings:
            crit = sum(1 for f in self.findings if f["severity"] == "critical")
            high = sum(1 for f in self.findings if f["severity"] == "high")
            print(f"\n{Fore.MAGENTA}[+] {Fore.CYAN}Data Exposure Scan Complete: {len(self.findings)} findings ({crit} critical, {high} high){Fore.RESET}")
        else:
            print(f"\n{Fore.GREEN}[+] Data Exposure Scan Complete: No sensitive data detected{Fore.RESET}")


def sensitive_data_scan(target: str):
    """Entry point for the orchestrator."""
    scanner = SensitiveDataScanner(target)
    scanner.scan()
    return {
        "findings": scanner.findings,
        "endpoints": scanner.endpoints,
    }
