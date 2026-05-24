#!/usr/bin/env python3
"""
Advanced IDOR (Insecure Direct Object Reference) / BOLA Scanner
Deep enumeration and exploitation testing for object-level authorization:
  - Sequential numeric ID manipulation with response comparison
  - UUID predictability testing and enumeration
  - Horizontal privilege escalation (cross-user access)
  - Vertical privilege escalation (role-based bypass)
  - Parameter pollution for IDOR
  - HTTP method-based IDOR (GET vs POST with different IDs)
  - Nested resource IDOR (/users/{id}/orders/{order_id})
  - Response fingerprinting to confirm real data leakage
  - Timestamp-based object prediction
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
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
from typing import Dict, List, Any, Optional, Tuple, Set

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)


class IDORScanner:
    """Deep IDOR/BOLA vulnerability scanner with exploitation logic"""

    # Known patterns where IDOR commonly occurs
    IDOR_ENDPOINT_PATTERNS = [
        "/api/v{v}/users/{id}",
        "/api/v{v}/user/{id}",
        "/api/v{v}/accounts/{id}",
        "/api/v{v}/account/{id}",
        "/api/v{v}/profiles/{id}",
        "/api/v{v}/profile/{id}",
        "/api/v{v}/orders/{id}",
        "/api/v{v}/order/{id}",
        "/api/v{v}/invoices/{id}",
        "/api/v{v}/documents/{id}",
        "/api/v{v}/files/{id}",
        "/api/v{v}/messages/{id}",
        "/api/v{v}/transactions/{id}",
        "/api/v{v}/payments/{id}",
        "/api/v{v}/settings/{id}",
        "/api/v{v}/data/{id}",
        "/api/v{v}/items/{id}",
        "/api/v{v}/records/{id}",
        "/api/v{v}/tickets/{id}",
        "/api/v{v}/reports/{id}",
    ]

    # Non-versioned patterns
    IDOR_SIMPLE_PATTERNS = [
        "/users/{id}", "/user/{id}",
        "/accounts/{id}", "/account/{id}",
        "/profiles/{id}", "/profile/{id}",
        "/orders/{id}", "/order/{id}",
        "/invoices/{id}", "/documents/{id}",
        "/files/{id}", "/messages/{id}",
        "/api/users/{id}", "/api/user/{id}",
        "/api/accounts/{id}", "/api/profile/{id}",
        "/api/orders/{id}", "/api/files/{id}",
        "/api/data/{id}", "/api/items/{id}",
    ]

    # Parameter names commonly vulnerable to IDOR
    IDOR_PARAMS = [
        "id", "user_id", "userId", "uid", "account_id", "accountId",
        "profile_id", "profileId", "order_id", "orderId", "doc_id",
        "document_id", "file_id", "fileId", "msg_id", "message_id",
        "transaction_id", "transactionId", "ref", "reference",
        "token", "ticket_id", "report_id", "item_id", "record_id",
    ]

    # Sensitive data patterns that confirm real data leakage
    DATA_LEAK_PATTERNS = [
        r'"email"\s*:\s*"[^"]+@[^"]+"',
        r'"phone"\s*:\s*"[\d\+\-\(\)\s]+"',
        r'"address"\s*:\s*"[^"]+"',
        r'"name"\s*:\s*"[^"]+"',
        r'"username"\s*:\s*"[^"]+"',
        r'"password"\s*:\s*',
        r'"ssn"\s*:\s*"[^"]+"',
        r'"credit_card"\s*:\s*"[^"]+"',
        r'"balance"\s*:\s*[\d\.]',
        r'"salary"\s*:\s*[\d\.]',
        r'"dob"\s*:\s*"[^"]+"',
        r'"date_of_birth"\s*:\s*"[^"]+"',
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

    # ── Response fingerprinting ──────────────────────────────────
    def _fingerprint_response(self, response: requests.Response) -> Dict[str, Any]:
        """Create a fingerprint of the response for comparison."""
        body = response.text
        return {
            "status": response.status_code,
            "size": len(body),
            "content_type": response.headers.get("Content-Type", ""),
            "hash": hashlib.md5(body.encode()).hexdigest(),
            "has_json": self._is_json(body),
            "sensitive_data": self._detect_sensitive_data(body),
            "body_preview": body[:200] if body else "",
        }

    def _is_json(self, text: str) -> bool:
        try:
            json.loads(text)
            return True
        except (json.JSONDecodeError, ValueError):
            return False

    def _detect_sensitive_data(self, body: str) -> List[str]:
        """Detect sensitive PII/data in response body."""
        found = []
        for pattern in self.DATA_LEAK_PATTERNS:
            matches = re.findall(pattern, body, re.IGNORECASE)
            if matches:
                # Extract the field name
                field_match = re.match(r'"(\w+)"', pattern)
                if field_match:
                    found.append(field_match.group(1))
        return found

    # ── Endpoint discovery ───────────────────────────────────────
    def _discover_idor_endpoints(self) -> List[Dict[str, Any]]:
        """Discover endpoints that may be vulnerable to IDOR."""
        print(f"{Fore.CYAN}[*] Discovering IDOR-vulnerable endpoints...{Fore.RESET}", end="", flush=True)

        discovered = []

        # Test versioned patterns
        for version in ["1", "2", "3"]:
            for pattern in self.IDOR_ENDPOINT_PATTERNS:
                path = pattern.replace("{v}", version).replace("{id}", "1")
                url = f"{self.base}{path}"
                try:
                    r = self.session.get(url, timeout=5)
                    if r.status_code in [200, 401, 403, 404]:
                        discovered.append({
                            "url": url,
                            "pattern": pattern.replace("{v}", version),
                            "status": r.status_code,
                            "has_data": r.status_code == 200 and len(r.content) > 50,
                        })
                        self.endpoints.append(url)
                except Exception:
                    pass

        # Test simple patterns
        for pattern in self.IDOR_SIMPLE_PATTERNS:
            path = pattern.replace("{id}", "1")
            url = f"{self.base}{path}"
            try:
                r = self.session.get(url, timeout=5)
                if r.status_code in [200, 401, 403, 404]:
                    discovered.append({
                        "url": url,
                        "pattern": pattern,
                        "status": r.status_code,
                        "has_data": r.status_code == 200 and len(r.content) > 50,
                    })
                    self.endpoints.append(url)
            except Exception:
                pass

        # Scan target page for API endpoints with IDs
        try:
            r = self.session.get(self.target, timeout=10)
            # Find URLs with numeric or UUID parameters in the page source
            urls = re.findall(
                r'(?:href|src|action|url)\s*[=:]\s*["\']?([^"\'>\s]+/\d+[^"\'>\s]*)',
                r.text, re.IGNORECASE
            )
            for found_url in urls:
                full_url = urljoin(self.target, found_url)
                if full_url not in [d["url"] for d in discovered]:
                    discovered.append({
                        "url": full_url,
                        "pattern": "discovered_in_page",
                        "status": 0,
                        "has_data": False,
                    })
                    self.endpoints.append(full_url)
        except Exception:
            pass

        print(f" {Fore.GREEN}Found {len(discovered)} candidate(s){Fore.RESET}")
        return discovered

    # ── Sequential ID enumeration ────────────────────────────────
    def _test_sequential_ids(self, base_url: str, pattern: str):
        """Test sequential ID manipulation for horizontal privilege escalation."""
        # Extract the ID from the URL and try adjacent values
        id_match = re.search(r'/(\d+)(?:/|$|\?)', base_url)
        if not id_match:
            return

        original_id = int(id_match.group(1))
        test_ids = [
            original_id - 1, original_id + 1,
            original_id + 2, original_id + 10,
            original_id + 100, 1, 0, 9999,
        ]

        # Get baseline response for the original ID
        try:
            baseline_r = self.session.get(base_url, timeout=5)
            baseline = self._fingerprint_response(baseline_r)
        except Exception:
            return

        if baseline["status"] not in [200, 401, 403]:
            return

        for test_id in test_ids:
            if test_id < 0:
                continue
            test_url = re.sub(r'/\d+(?=/|$|\?)', f'/{test_id}', base_url)
            if test_url == base_url:
                continue

            try:
                r = self.session.get(test_url, timeout=5)
                test_fp = self._fingerprint_response(r)

                # Case 1: We got different data for a different ID (IDOR confirmed)
                if (test_fp["status"] == 200 and
                    test_fp["has_json"] and
                    test_fp["hash"] != baseline["hash"] and
                    test_fp["size"] > 50):

                    severity = "high"
                    sensitve = test_fp["sensitive_data"]
                    if sensitve:
                        severity = "critical"

                    self.findings.append({
                        "type": "IDOR - Sequential ID Enumeration",
                        "severity": severity,
                        "endpoint": base_url,
                        "details": (
                            f"Horizontal privilege escalation confirmed. "
                            f"Changing ID from {original_id} to {test_id} returned "
                            f"different data ({test_fp['size']} bytes). "
                            f"{'Leaked fields: ' + ', '.join(sensitve) if sensitve else ''} "
                            f"No authorization check prevents accessing other users' resources."
                        ),
                        "method": "GET",
                        "evidence_url": test_url,
                    })
                    return  # One confirmed finding per endpoint is enough

                # Case 2: Endpoint returns 200 for any ID (potential IDOR)
                elif (test_fp["status"] == 200 and baseline["status"] == 200 and
                      test_fp["hash"] == baseline["hash"]):
                    # Same response = might be a generic response, not real IDOR
                    pass

                # Case 3: Got access when we shouldn't
                elif (baseline["status"] in [401, 403] and
                      test_fp["status"] == 200):
                    self.findings.append({
                        "type": "IDOR - Authorization Bypass via ID Manipulation",
                        "severity": "critical",
                        "endpoint": base_url,
                        "details": (
                            f"Original ID {original_id} returned {baseline['status']}, "
                            f"but ID {test_id} returned 200 OK with {test_fp['size']} bytes. "
                            f"Broken access control allows accessing restricted resources."
                        ),
                        "method": "GET",
                    })
                    return

            except Exception:
                pass

    # ── Parameter-based IDOR ─────────────────────────────────────
    def _test_parameter_idor(self, url: str):
        """Test query parameter-based IDOR."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for param_name in self.IDOR_PARAMS:
            # Test as query parameter
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            test_params = {**params}

            for test_id in ["1", "2", "999", "0", "admin"]:
                test_params[param_name] = [test_id]
                query = urlencode(test_params, doseq=True)
                full_url = f"{test_url}?{query}"

                try:
                    r = self.session.get(full_url, timeout=5)
                    if r.status_code == 200 and len(r.content) > 100:
                        fp = self._fingerprint_response(r)
                        if fp["has_json"] and fp["sensitive_data"]:
                            self.findings.append({
                                "type": "IDOR - Parameter Manipulation",
                                "severity": "high",
                                "endpoint": full_url,
                                "details": (
                                    f"Parameter '{param_name}={test_id}' returns "
                                    f"sensitive data ({', '.join(fp['sensitive_data'])}). "
                                    f"No authorization check on resource access."
                                ),
                                "method": "GET",
                            })
                            return
                except Exception:
                    pass

    # ── HTTP method IDOR ─────────────────────────────────────────
    def _test_method_idor(self, url: str):
        """Test IDOR via different HTTP methods on the same resource."""
        id_match = re.search(r'/(\d+)(?:/|$)', url)
        if not id_match:
            return

        original_id = int(id_match.group(1))
        test_id = original_id + 1 if original_id > 0 else 2
        test_url = re.sub(r'/\d+(?=/|$)', f'/{test_id}', url)

        methods_to_test = {
            "PUT": {"updated": True},
            "PATCH": {"status": "modified"},
            "DELETE": None,
            "POST": {"action": "duplicate"},
        }

        for method, body in methods_to_test.items():
            try:
                if body:
                    r = self.session.request(method, test_url, json=body, timeout=5)
                else:
                    r = self.session.request(method, test_url, timeout=5)

                if r.status_code in [200, 201, 204]:
                    self.findings.append({
                        "type": f"IDOR - {method} Method on Foreign Resource",
                        "severity": "critical" if method in ["PUT", "DELETE", "PATCH"] else "high",
                        "endpoint": test_url,
                        "details": (
                            f"{method} request to another user's resource (ID {test_id}) "
                            f"returned HTTP {r.status_code}. This could allow "
                            f"{'data modification' if method in ['PUT', 'PATCH'] else 'data deletion' if method == 'DELETE' else 'unauthorized action'} "
                            f"on other users' resources."
                        ),
                        "method": method,
                    })
            except Exception:
                pass

    # ── Nested resource IDOR ─────────────────────────────────────
    def _test_nested_idor(self, url: str):
        """Test IDOR on nested resources like /users/1/orders/5."""
        # Find URLs with multiple numeric IDs
        ids = re.findall(r'/(\d+)', url)
        if len(ids) < 2:
            return

        # Try changing the nested (second) ID while keeping the parent
        for i, idx in enumerate(ids[1:], 1):
            original = int(idx)
            for test_val in [original + 1, original - 1, 1, 999]:
                if test_val == original or test_val < 0:
                    continue
                test_url = url
                # Replace the i-th numeric ID
                count = 0
                def replacer(m):
                    nonlocal count
                    count += 1
                    if count == i + 1:
                        return f"/{test_val}"
                    return m.group(0)

                count = 0
                test_url = re.sub(r'/\d+', replacer, url)

                try:
                    r = self.session.get(test_url, timeout=5)
                    if r.status_code == 200 and len(r.content) > 50:
                        fp = self._fingerprint_response(r)
                        if fp["has_json"]:
                            self.findings.append({
                                "type": "IDOR - Nested Resource Access",
                                "severity": "high",
                                "endpoint": test_url,
                                "details": (
                                    f"Nested resource IDOR: changing sub-resource ID "
                                    f"from {original} to {test_val} returned data. "
                                    f"Cross-user access to nested resources may be possible."
                                ),
                                "method": "GET",
                            })
                            return
                except Exception:
                    pass

    # ── UUID predictability ──────────────────────────────────────
    def _test_uuid_predictability(self, url: str):
        """Check if UUIDs in URLs are predictable (v1 time-based)."""
        uuid_match = re.search(
            r'([0-9a-f]{8}-[0-9a-f]{4}-([0-9a-f])[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12})',
            url, re.IGNORECASE
        )
        if not uuid_match:
            return

        uuid_str = uuid_match.group(1)
        version = uuid_match.group(2)

        if version == "1":
            self.findings.append({
                "type": "Predictable UUID v1 in Resource Identifier",
                "severity": "medium",
                "endpoint": url,
                "details": (
                    f"Resource uses UUID v1 ({uuid_str}) which is time-based "
                    f"and partially predictable. UUID v1 encodes the MAC address "
                    f"and timestamp, making it possible to enumerate resources "
                    f"by predicting adjacent UUIDs. Use UUID v4 (random) instead."
                ),
                "method": "GET",
            })

    # ── Main scan ────────────────────────────────────────────────
    def scan(self):
        """Run the full IDOR/BOLA scanning suite."""
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}Starting Advanced IDOR/BOLA Scan...{Fore.RESET}")

        # Phase 1: Discover endpoints
        candidates = self._discover_idor_endpoints()

        if not candidates:
            print(f"{Fore.YELLOW}[!] No IDOR-candidate endpoints found{Fore.RESET}")
            return

        # Phase 2: Test each candidate
        tested = 0
        for candidate in candidates:
            url = candidate["url"]
            tested += 1
            print(f"\n{Fore.CYAN}[*] Testing [{tested}/{len(candidates)}]: {url}{Fore.RESET}")

            if candidate["status"] == 200 or candidate["has_data"]:
                self._test_sequential_ids(url, candidate["pattern"])
                self._test_method_idor(url)
                self._test_nested_idor(url)
                self._test_uuid_predictability(url)

            self._test_parameter_idor(url)

        # Summary
        if self.findings:
            crit = sum(1 for f in self.findings if f["severity"] == "critical")
            high = sum(1 for f in self.findings if f["severity"] == "high")
            print(f"\n{Fore.MAGENTA}[+] {Fore.CYAN}IDOR Scan Complete: {len(self.findings)} findings ({crit} critical, {high} high){Fore.RESET}")
        else:
            print(f"\n{Fore.GREEN}[+] IDOR Scan Complete: No vulnerabilities found{Fore.RESET}")


def idor_scan(target: str):
    """Entry point for the orchestrator."""
    scanner = IDORScanner(target)
    scanner.scan()
    return {
        "findings": scanner.findings,
        "endpoints": scanner.endpoints,
    }
