"""
API RIPPER v2.0 — Differential Analysis Agent
The CORE detection engine. Compares responses across controlled
variations to detect inconsistencies, hidden params, IDOR, and
auth boundary weaknesses.

OBSERVE: Collect baseline responses for all endpoints
PROFILE: Establish response fingerprints (status, length, structure, headers)
DIFF:    Systematically vary inputs and compare across 8 dimensions
INFER:   Detect IDOR, hidden params, inconsistent validation, auth bypass signals
"""

import asyncio
import hashlib
import json
import logging
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urlencode

import aiohttp

from backend.agents.base_agent import BaseAgent, Finding

logger = logging.getLogger(__name__)


class DiffResult:
    """Result of comparing two HTTP responses."""
    def __init__(self, baseline, modified, variation_type, variation_detail):
        self.baseline = baseline
        self.modified = modified
        self.variation_type = variation_type
        self.variation_detail = variation_detail

        # Compute diffs
        self.status_changed = baseline.get("status") != modified.get("status")
        self.semantic_class_changed = baseline.get("response_class") != modified.get("response_class")
        self.error_signature_changed = baseline.get("error_signature") != modified.get("error_signature")
        self.length_delta = abs(modified.get("body_length", 0) - baseline.get("body_length", 0))
        self.length_ratio = (modified.get("body_length", 1) / max(baseline.get("body_length", 1), 1))
        self.timing_delta = modified.get("latency_ms", 0) - baseline.get("latency_ms", 0)
        self.content_type_changed = baseline.get("content_type", "") != modified.get("content_type", "")
        self.has_error_changed = baseline.get("has_error", False) != modified.get("has_error", False)

        # Structure diff (JSON keys)
        self.structure_diff = self._compute_structure_diff()
        self.is_anomalous = self._check_anomalous()

    def _compute_structure_diff(self):
        # In v2, we check full schema shapes if available, but for now we do deep key tracking
        b_keys = set(self.baseline.get("json_keys", []))
        m_keys = set(self.modified.get("json_keys", []))
        
        # Look for semantic changes (e.g., 'role' suddenly appears)
        critical_keys = {"role", "admin", "is_admin", "permissions", "token", "password", "hidden"}
        added = m_keys - b_keys
        critical_added = list(added.intersection(critical_keys))
        
        return {
            "added_keys": list(added),
            "removed_keys": list(b_keys - m_keys),
            "key_count_diff": len(m_keys) - len(b_keys),
            "critical_added": critical_added
        }

    def _check_anomalous(self):
        # A semantic change is anomalous (e.g. AUTH_REQUIRED -> SUCCESS)
        if self.semantic_class_changed:
            # Not anomalous if it went from SUCCESS to RESOURCE_NOT_FOUND on ID change
            if self.variation_type == "id_variation" and self.modified.get("response_class") == "RESOURCE_NOT_FOUND":
                return False
            return True
            
        # Error signature changed (e.g., normal error to SQL syntax error)
        if self.error_signature_changed and self.modified.get("error_signature"):
            return True
            
        if self.status_changed:
            return True
        if self.length_delta > 100 and abs(1 - self.length_ratio) > 0.15:
            return True
        if self.structure_diff["key_count_diff"] != 0 or self.structure_diff["critical_added"]:
            return True
        # Timing variance anomaly
        if abs(self.timing_delta) > 1500:
            return True
        if self.content_type_changed:
            return True
        return False

    def to_dict(self):
        return {
            "variation_type": self.variation_type,
            "variation_detail": self.variation_detail,
            "status_changed": self.status_changed,
            "semantic_class_changed": self.semantic_class_changed,
            "error_signature_changed": self.error_signature_changed,
            "baseline_status": self.baseline.get("status"),
            "modified_status": self.modified.get("status"),
            "baseline_class": self.baseline.get("response_class"),
            "modified_class": self.modified.get("response_class"),
            "length_delta": self.length_delta,
            "length_ratio": round(self.length_ratio, 3),
            "timing_delta_ms": round(self.timing_delta, 2),
            "content_type_changed": self.content_type_changed,
            "structure_diff": self.structure_diff,
            "is_anomalous": self.is_anomalous,
        }


class DifferentialAgent(BaseAgent):
    """
    Differential Analysis Agent — the primary detection engine.
    Systematically varies inputs and compares responses to detect weaknesses.
    """

    name = "differential_agent"

    def __init__(self, knowledge_graph, message_bus, config=None):
        super().__init__(knowledge_graph, message_bus, config)
        self._max_variations = config.get("max_variations_per_endpoint", 10) if config else 10
        self._max_total = config.get("max_total_diff_tests", 1000) if config else 1000
        self._total_tests = 0
        self._consecutive_no_anomaly = 0

    async def observe(self) -> Dict[str, Dict]:
        """Step 1: Collect baseline responses for all endpoints."""
        endpoints = self.kg.get_all_endpoints()
        baselines = {}

        if not endpoints:
            return baselines

        auth_config = self.config.get("auth_config", {})
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        if auth_config.get("bearer_token"):
            headers["Authorization"] = f"Bearer {auth_config['bearer_token']}"

        timeout = aiohttp.ClientTimeout(total=10)
        connector = aiohttp.TCPConnector(ssl=False, limit=5)

        async with aiohttp.ClientSession(timeout=timeout, headers=headers, connector=connector) as session:
            for ep in endpoints[:30]:
                url = ep["url"]
                await self.rate_limited_delay()
                baseline = await self._fetch_response(session, url)
                if baseline and baseline.get("status", 0) > 0:
                    baselines[url] = baseline

        return baselines

    async def profile(self, baselines: Dict[str, Dict]) -> Dict[str, Dict]:
        """Step 2: Baseline response fingerprints are already captured."""
        return baselines

    async def differential_analyze(self, baselines: Dict[str, Dict]) -> List[DiffResult]:
        """Step 3: Vary inputs and compare — the core engine."""
        all_diffs = []

        if not baselines:
            return all_diffs

        auth_config = self.config.get("auth_config", {})
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        if auth_config.get("bearer_token"):
            headers["Authorization"] = f"Bearer {auth_config['bearer_token']}"

        timeout = aiohttp.ClientTimeout(total=10)
        connector = aiohttp.TCPConnector(ssl=False, limit=5)

        async with aiohttp.ClientSession(timeout=timeout, headers=headers, connector=connector) as session:
            for url, baseline in baselines.items():
                if self._total_tests >= self._max_total:
                    logger.info("[diff] Reached MAX_TOTAL_DIFF_TESTS limit")
                    break
                if self._consecutive_no_anomaly >= 10:
                    logger.info("[diff] Diminishing returns — stopping early")
                    break

                endpoint_diffs = await self._test_endpoint(session, url, baseline)
                if endpoint_diffs:
                    all_diffs.extend(endpoint_diffs)
                    self._consecutive_no_anomaly = 0
                else:
                    self._consecutive_no_anomaly += 1

        return all_diffs

    async def infer(self, diffs: List[DiffResult]) -> List[Finding]:
        """Step 4: Generate findings from differential analysis."""
        findings = []

        for diff in diffs:
            if not diff.is_anomalous:
                continue

            # IDOR Detection: Different IDs return different data without auth
            if diff.variation_type == "id_variation" and not diff.status_changed:
                if diff.length_delta > 50:
                    findings.append(Finding(
                        type="potential_idor",
                        title=f"Potential IDOR: {diff.variation_detail.get('url', '')}",
                        description=f"Varying ID parameter returns different-sized responses ({diff.length_delta} bytes diff), suggesting access to different users' data without authorization checks.",
                        severity="high",
                        confidence=0.6,
                        endpoint=diff.variation_detail.get("url", ""),
                        cwe="CWE-639",
                        owasp="API1:2023",
                        remediation="Implement object-level authorization. Verify the requesting user owns the requested resource.",
                        evidence=[{
                            "type": "differential",
                            "baseline": diff.baseline,
                            "modified": diff.modified,
                            "diff": diff.to_dict(),
                        }],
                    ))

            # Hidden Parameter Detection
            if diff.variation_type == "hidden_param" and diff.is_anomalous:
                param_name = diff.variation_detail.get("param", "")
                findings.append(Finding(
                    type="hidden_parameter",
                    title=f"Hidden Parameter Detected: {param_name}",
                    description=f"Adding parameter '{param_name}' changes the response (status: {diff.status_changed}, length delta: {diff.length_delta}). This parameter may enable debug mode or bypass controls.",
                    severity="medium",
                    confidence=0.5,
                    endpoint=diff.variation_detail.get("url", ""),
                    cwe="CWE-912",
                    remediation="Remove or protect hidden parameters. Whitelist allowed parameters.",
                    evidence=[{"type": "differential", "diff": diff.to_dict()}],
                ))

            # Method Tampering
            if diff.variation_type == "method_variation":
                if diff.modified.get("status") in (200, 201, 204):
                    findings.append(Finding(
                        type="method_tampering",
                        title=f"Unexpected Method Accepted: {diff.variation_detail.get('method', '')} on {diff.variation_detail.get('url', '')}",
                        description=f"Endpoint accepts {diff.variation_detail.get('method', '')} method when only GET was expected. This may allow data modification or deletion.",
                        severity="medium",
                        confidence=0.6,
                        endpoint=diff.variation_detail.get("url", ""),
                        cwe="CWE-650",
                        owasp="API5:2023",
                        remediation="Explicitly whitelist allowed HTTP methods per endpoint.",
                        evidence=[{"type": "differential", "diff": diff.to_dict()}],
                    ))

            # Auth Boundary Detection
            if diff.variation_type == "auth_removal":
                if diff.modified.get("status") == 200:
                    findings.append(Finding(
                        type="missing_auth",
                        title=f"Missing Authentication: {diff.variation_detail.get('url', '')}",
                        description="Endpoint returns 200 even without authentication headers. Data may be accessible without login.",
                        severity="high",
                        confidence=0.7,
                        endpoint=diff.variation_detail.get("url", ""),
                        cwe="CWE-306",
                        owasp="API2:2023",
                        remediation="Enforce authentication on all data endpoints.",
                        evidence=[{"type": "differential", "diff": diff.to_dict()}],
                    ))

            # Schema Inconsistency
            if diff.variation_type == "id_variation" and diff.structure_diff.get("key_count_diff", 0) != 0:
                findings.append(Finding(
                    type="inconsistent_schema",
                    title=f"Inconsistent Response Schema: {diff.variation_detail.get('url', '')}",
                    description=f"Same endpoint returns different JSON structures for different inputs. Added keys: {diff.structure_diff.get('added_keys', [])}, removed: {diff.structure_diff.get('removed_keys', [])}. This suggests inconsistent data exposure.",
                    severity="medium",
                    confidence=0.6,
                    endpoint=diff.variation_detail.get("url", ""),
                    cwe="CWE-200",
                    owasp="API3:2023",
                    remediation="Standardize response schemas. Use response serializers to ensure consistent output.",
                    evidence=[{"type": "differential", "structure_diff": diff.structure_diff}],
                ))

        # Emit signals for significant findings
        for f in findings:
            if f.confidence >= 0.5:
                self.emit_signal(f"DIFF_{f.type.upper()}", {
                    "url": f.endpoint,
                    "type": f.type,
                    "confidence": f.confidence,
                }, confidence=f.confidence, priority=3)

        return findings

    # ── Internal Methods ────────────────────────────────────

    async def _test_endpoint(self, session, url: str, baseline: Dict) -> List[DiffResult]:
        """Run all differential tests on a single endpoint."""
        diffs = []
        tests_run = 0

        # Test 1: ID variation (IDOR check)
        if self._has_id_pattern(url):
            for alt_id in ["1", "2", "3", "0", "999"]:
                if tests_run >= self._max_variations:
                    break
                varied_url = self._vary_id(url, alt_id)
                if varied_url != url:
                    await self.rate_limited_delay()
                    modified = await self._fetch_response(session, varied_url)
                    if modified:
                        diff = DiffResult(baseline, modified, "id_variation", {"url": url, "alt_id": alt_id})
                        if diff.is_anomalous:
                            diffs.append(diff)
                        tests_run += 1
                        self._total_tests += 1

        # Test 2: Hidden parameter discovery & Parameter Pollution & Type Confusion
        hidden_params = [
            "debug=true", "test=1", "admin=true", "verbose=1", "internal=true", 
            "dev=true", "trace=true", "raw=true", "format=json", "role=admin", "is_admin=true"
        ]
        
        # Extract existing query params if any
        parsed_url = urlparse(url)
        has_query = bool(parsed_url.query)
        
        for param_str in hidden_params:
            if tests_run >= self._max_variations:
                break
            test_url = f"{url}{'&' if has_query else '?'}{param_str}"
            await self.rate_limited_delay()
            modified = await self._fetch_response(session, test_url)
            if modified:
                diff = DiffResult(baseline, modified, "hidden_param", {"url": url, "param": param_str})
                if diff.is_anomalous:
                    diffs.append(diff)
                tests_run += 1
                self._total_tests += 1

        # Parameter Pollution (duplicate params)
        if has_query:
            if tests_run < self._max_variations:
                polluted_url = f"{url}&{parsed_url.query}"
                await self.rate_limited_delay()
                modified = await self._fetch_response(session, polluted_url)
                if modified:
                    diff = DiffResult(baseline, modified, "parameter_pollution", {"url": url})
                    if diff.is_anomalous:
                        diffs.append(diff)
                    tests_run += 1
                    self._total_tests += 1

        # Version manipulation (/v1/ -> /v2/ or /v0/)
        if "/v1/" in url or "/v2/" in url:
            if tests_run < self._max_variations:
                new_ver = "/v2/" if "/v1/" in url else "/v3/"
                ver_url = url.replace("/v1/", new_ver).replace("/v2/", new_ver)
                await self.rate_limited_delay()
                modified = await self._fetch_response(session, ver_url)
                if modified:
                    diff = DiffResult(baseline, modified, "version_manipulation", {"url": url, "new_version_url": ver_url})
                    if diff.is_anomalous:
                        diffs.append(diff)
                    tests_run += 1
                    self._total_tests += 1

        # Test 3: HTTP method variation
        for method in ["POST", "PUT", "DELETE", "PATCH", "OPTIONS"]:
            if tests_run >= self._max_variations:
                break
            await self.rate_limited_delay()
            modified = await self._fetch_response(session, url, method=method)
            if modified and modified.get("status", 0) > 0:
                diff = DiffResult(baseline, modified, "method_variation", {"url": url, "method": method})
                if diff.is_anomalous and modified.get("status") not in (405, 404):
                    diffs.append(diff)
                tests_run += 1
                self._total_tests += 1

        # Test 4: Auth removal (if auth headers present)
        if self.config.get("auth_config", {}).get("bearer_token"):
            await self.rate_limited_delay()
            modified = await self._fetch_response(session, url, strip_auth=True)
            if modified:
                diff = DiffResult(baseline, modified, "auth_removal", {"url": url})
                if diff.is_anomalous:
                    diffs.append(diff)
                self._total_tests += 1

        return diffs

    async def _fetch_response(self, session, url: str, method: str = "GET", strip_auth: bool = False) -> Optional[Dict]:
        """Fetch a response and return structured data with semantic classification."""
        from backend.agents.response_classifier import ResponseClassifier
        
        # Check cache
        cache_key = f"{method}:{url}:{strip_auth}"
        cached = self.get_cached(cache_key)
        if cached:
            return cached

        try:
            headers = {}
            if strip_auth:
                headers = {"Authorization": ""}  # Override auth

            start = time.time()
            req_method = getattr(session, method.lower(), session.get)
            async with req_method(url, headers=headers if strip_auth else None) as resp:
                body = await resp.text(errors="replace")
                latency = (time.time() - start) * 1000

                # Parse JSON keys if applicable
                json_keys = []
                try:
                    if "json" in resp.headers.get("content-type", ""):
                        data = json.loads(body)
                        if isinstance(data, dict):
                            json_keys = list(data.keys())
                        elif isinstance(data, list) and data and isinstance(data[0], dict):
                            json_keys = list(data[0].keys())
                except Exception:
                    pass

                # Semantic Classification (Differential Intel v2)
                headers_dict = dict(resp.headers)
                response_class = ResponseClassifier.classify(resp.status, headers_dict, body, latency)
                error_signature = ResponseClassifier.extract_error_signature(body)

                result = {
                    "status": resp.status,
                    "response_class": response_class.value,
                    "error_signature": error_signature,
                    "body_length": len(body),
                    "latency_ms": round(latency, 2),
                    "content_type": resp.headers.get("content-type", ""),
                    "json_keys": json_keys,
                    "has_error": any(kw in body.lower() for kw in ["error", "exception", "traceback"]),
                }
                self.cache_response(cache_key, result)
                return result

        except Exception:
            return None

    def _has_id_pattern(self, url: str) -> bool:
        """Check if URL contains an ID-like segment."""
        import re
        return bool(re.search(r'/\d+', url) or re.search(r'/[a-f0-9-]{36}', url))

    def _vary_id(self, url: str, new_id: str) -> str:
        """Replace numeric ID in URL path with a different value."""
        import re
        # Replace last numeric segment
        return re.sub(r'/(\d+)(?=[/?#]|$)', f'/{new_id}', url, count=1)
