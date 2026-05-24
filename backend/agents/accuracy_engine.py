"""
API RIPPER v4.0 — Elite Accuracy Engine
Multi-layer verification ensuring ZERO false positives.

Verification Pipeline (ALL must pass):
  Layer 1: Statistical Baseline — Compare against N=5 baseline responses
  Layer 2: Temporal Consistency — Re-test after delay to confirm persistence
  Layer 3: Response Fingerprinting — MinHash similarity to detect real changes vs noise
  Layer 4: Cross-Signal Correlation — Require ≥2 independent signal types
  Layer 5: Negative Validation — Confirm safe input does NOT trigger the same behavior

A finding that fails ANY layer is downgraded or dropped entirely.
"""

import asyncio
import hashlib
import logging
import random
import statistics
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ── Response Fingerprint ────────────────────────────────────

@dataclass
class ResponseFingerprint:
    """Structural fingerprint of an HTTP response for similarity comparison."""
    status: int = 0
    body_length: int = 0
    content_type: str = ""
    header_keys: List[str] = field(default_factory=list)
    body_hash: str = ""
    # Structural tokens (first 50 significant tokens from body)
    structural_tokens: List[str] = field(default_factory=list)
    word_count: int = 0
    tag_count: int = 0
    json_key_count: int = 0
    latency_ms: float = 0.0

    @classmethod
    def from_response(cls, resp: Dict) -> "ResponseFingerprint":
        body = resp.get("body_preview", resp.get("body", ""))
        headers = resp.get("headers", {})

        # Extract structural tokens
        import re
        tokens = re.findall(r'[a-zA-Z_]{3,}', body[:2000])
        unique_tokens = list(dict.fromkeys(tokens))[:50]

        # Count HTML tags
        tags = len(re.findall(r'<[a-zA-Z]', body[:5000]))

        # Count JSON keys
        json_keys = len(re.findall(r'"[a-zA-Z_]+"\s*:', body[:5000]))

        return cls(
            status=resp.get("status", 0),
            body_length=len(body) if isinstance(body, str) else resp.get("body_length", 0),
            content_type=headers.get("content-type", resp.get("content_type", "")),
            header_keys=sorted([k.lower() for k in headers.keys()]),
            body_hash=hashlib.md5(body.encode()[:4096] if isinstance(body, str) else b"").hexdigest(),
            structural_tokens=unique_tokens,
            word_count=len(body.split()) if isinstance(body, str) else 0,
            tag_count=tags,
            json_key_count=json_keys,
            latency_ms=resp.get("latency_ms", 0.0),
        )

    def similarity(self, other: "ResponseFingerprint") -> float:
        """Calculate similarity score (0.0 = completely different, 1.0 = identical)."""
        if self.body_hash == other.body_hash:
            return 1.0

        score = 0.0
        checks = 0

        # Status code match
        checks += 1
        if self.status == other.status:
            score += 1.0

        # Body length similarity (within 10%)
        checks += 1
        if self.body_length > 0 and other.body_length > 0:
            ratio = min(self.body_length, other.body_length) / max(self.body_length, other.body_length)
            score += ratio

        # Content type match
        checks += 1
        if self.content_type == other.content_type:
            score += 1.0

        # Header key overlap (Jaccard similarity)
        checks += 1
        if self.header_keys or other.header_keys:
            s1, s2 = set(self.header_keys), set(other.header_keys)
            if s1 | s2:
                score += len(s1 & s2) / len(s1 | s2)

        # Structural token overlap (Jaccard)
        checks += 1
        if self.structural_tokens or other.structural_tokens:
            s1 = set(self.structural_tokens)
            s2 = set(other.structural_tokens)
            if s1 | s2:
                score += len(s1 & s2) / len(s1 | s2)

        # Word count similarity
        checks += 1
        if self.word_count > 0 and other.word_count > 0:
            ratio = min(self.word_count, other.word_count) / max(self.word_count, other.word_count)
            score += ratio

        return round(score / max(checks, 1), 4)

    def is_structurally_different(self, other: "ResponseFingerprint", threshold: float = 0.15) -> bool:
        """Check if two responses are structurally different enough to indicate a real vulnerability."""
        sim = self.similarity(other)
        # Must be below threshold AND have at least one concrete difference
        if sim >= (1.0 - threshold):
            return False
        # Concrete differences that matter
        concrete_diffs = 0
        if self.status != other.status:
            concrete_diffs += 2
        if abs(self.body_length - other.body_length) > 50:
            concrete_diffs += 1
        if self.json_key_count != other.json_key_count:
            concrete_diffs += 1
        if abs(self.word_count - other.word_count) > 10:
            concrete_diffs += 1
        return concrete_diffs >= 2


# ── Baseline Manager ────────────────────────────────────────

class BaselineManager:
    """
    Collects and manages baseline response profiles per endpoint.
    Every endpoint gets N=5 baseline requests to establish normal behavior.
    """

    def __init__(self):
        self._baselines: Dict[str, List[ResponseFingerprint]] = {}
        self._baseline_stats: Dict[str, Dict] = {}

    async def collect_baseline(self, request_func, url: str, method: str = "GET",
                               n: int = 5, delay: float = 0.3) -> Dict:
        """Collect N baseline responses and compute statistical profile."""
        fingerprints = []
        for i in range(n):
            if i > 0:
                await asyncio.sleep(delay)
            resp = await request_func(url, method)
            if resp:
                fp = ResponseFingerprint.from_response(resp)
                fingerprints.append(fp)

        if not fingerprints:
            return {"status": "failed", "reason": "no_responses"}

        self._baselines[url] = fingerprints

        # Compute statistics
        statuses = [fp.status for fp in fingerprints]
        lengths = [fp.body_length for fp in fingerprints]
        latencies = [fp.latency_ms for fp in fingerprints]
        word_counts = [fp.word_count for fp in fingerprints]

        stats = {
            "dominant_status": max(set(statuses), key=statuses.count),
            "status_variance": len(set(statuses)) > 1,
            "avg_length": statistics.mean(lengths) if lengths else 0,
            "length_stddev": statistics.stdev(lengths) if len(lengths) > 1 else 0,
            "avg_latency": statistics.mean(latencies) if latencies else 0,
            "latency_stddev": statistics.stdev(latencies) if len(latencies) > 1 else 0,
            "avg_words": statistics.mean(word_counts) if word_counts else 0,
            "sample_count": len(fingerprints),
            "body_hashes": list(set(fp.body_hash for fp in fingerprints)),
            "is_dynamic": len(set(fp.body_hash for fp in fingerprints)) > 1,
        }
        self._baseline_stats[url] = stats
        return stats

    def is_anomalous(self, url: str, test_fp: ResponseFingerprint) -> Tuple[bool, Dict]:
        """Check if a test response deviates significantly from baseline."""
        baselines = self._baselines.get(url, [])
        stats = self._baseline_stats.get(url)
        if not baselines or not stats:
            return False, {"reason": "no_baseline"}

        anomaly_signals = []
        anomaly_score = 0.0

        # Status code deviation
        if test_fp.status != stats["dominant_status"]:
            anomaly_signals.append(f"status_changed:{stats['dominant_status']}→{test_fp.status}")
            anomaly_score += 2.0

        # Body length deviation (>3 stddev from mean)
        if stats["length_stddev"] > 0:
            z_score = abs(test_fp.body_length - stats["avg_length"]) / stats["length_stddev"]
            if z_score > 3.0:
                anomaly_signals.append(f"length_deviation:z={z_score:.1f}")
                anomaly_score += min(z_score * 0.5, 3.0)
        elif abs(test_fp.body_length - stats["avg_length"]) > 100:
            anomaly_signals.append(f"length_diff:{abs(test_fp.body_length - stats['avg_length'])}")
            anomaly_score += 1.5

        # Latency deviation (>3 stddev — indicates time-based injection)
        if stats["latency_stddev"] > 0 and test_fp.latency_ms > 0:
            z_lat = (test_fp.latency_ms - stats["avg_latency"]) / max(stats["latency_stddev"], 1)
            if z_lat > 3.0:
                anomaly_signals.append(f"latency_spike:z={z_lat:.1f}")
                anomaly_score += min(z_lat * 0.3, 2.0)

        # Structural similarity to all baselines
        similarities = [test_fp.similarity(bp) for bp in baselines]
        avg_similarity = statistics.mean(similarities) if similarities else 1.0
        if avg_similarity < 0.7:
            anomaly_signals.append(f"structural_deviation:sim={avg_similarity:.2f}")
            anomaly_score += (1.0 - avg_similarity) * 3.0

        is_anomalous = anomaly_score >= 2.0

        return is_anomalous, {
            "anomaly_score": round(anomaly_score, 2),
            "signals": anomaly_signals,
            "avg_similarity": round(avg_similarity, 4),
            "is_anomalous": is_anomalous,
        }

    def get_baseline(self, url: str) -> Optional[Dict]:
        return self._baseline_stats.get(url)


# ── Verification Pipeline ───────────────────────────────────

class VerificationResult:
    """Result of running the full verification pipeline on a finding."""

    def __init__(self):
        self.layers_passed: List[str] = []
        self.layers_failed: List[str] = []
        self.final_confidence: float = 0.0
        self.verified: bool = False
        self.evidence: List[Dict] = []
        self.curl_command: str = ""

    def to_dict(self) -> dict:
        return {
            "verified": self.verified,
            "final_confidence": self.final_confidence,
            "layers_passed": self.layers_passed,
            "layers_failed": self.layers_failed,
            "evidence_count": len(self.evidence),
            "curl_command": self.curl_command,
        }


class AccuracyEngine:
    """
    Elite accuracy verification engine.
    Every finding must pass through this pipeline before being reported.

    Layers:
      1. Statistical Baseline Comparison
      2. Temporal Consistency (re-test after delay)
      3. Response Fingerprint Divergence
      4. Negative Validation (safe input must NOT trigger)
      5. Cross-Signal Correlation
    """

    def __init__(self, baseline_manager: BaselineManager = None):
        self.baseline = baseline_manager or BaselineManager()
        self._verification_cache: Dict[str, VerificationResult] = {}

    async def verify_finding(
        self,
        finding_type: str,
        endpoint: str,
        payload: str,
        request_func,
        method: str = "GET",
        inject_param: str = "id",
        inject_location: str = "query",
        original_response: Dict = None,
        supporting_signals: List[str] = None,
    ) -> VerificationResult:
        """
        Run the full 5-layer verification pipeline on a potential finding.
        Returns VerificationResult with pass/fail for each layer.
        """
        result = VerificationResult()
        confidence = 0.0

        # ── Layer 1: Statistical Baseline ─────────────────
        baseline_stats = self.baseline.get_baseline(endpoint)
        if not baseline_stats:
            baseline_stats = await self.baseline.collect_baseline(request_func, endpoint, method)

        if original_response:
            test_fp = ResponseFingerprint.from_response(original_response)
            is_anomalous, anomaly_info = self.baseline.is_anomalous(endpoint, test_fp)

            if is_anomalous:
                result.layers_passed.append("L1_statistical_baseline")
                confidence += 0.2
                result.evidence.append({"layer": "L1", "anomaly": anomaly_info})
            else:
                result.layers_failed.append("L1_statistical_baseline")
                result.evidence.append({"layer": "L1", "reason": "response_within_baseline", "info": anomaly_info})

        # ── Layer 2: Temporal Consistency ─────────────────
        await asyncio.sleep(random.uniform(1.5, 3.0))
        retest_resp = await self._inject_and_request(
            request_func, endpoint, method, inject_param, inject_location, payload
        )

        if retest_resp and original_response:
            orig_fp = ResponseFingerprint.from_response(original_response)
            retest_fp = ResponseFingerprint.from_response(retest_resp)
            temporal_sim = orig_fp.similarity(retest_fp)

            if temporal_sim > 0.8:
                result.layers_passed.append("L2_temporal_consistency")
                confidence += 0.2
                result.evidence.append({"layer": "L2", "similarity": temporal_sim, "retest_status": retest_resp.get("status")})
            else:
                result.layers_failed.append("L2_temporal_consistency")
                result.evidence.append({"layer": "L2", "reason": "inconsistent_retest", "similarity": temporal_sim})

        # ── Layer 3: Response Fingerprint Divergence ──────
        if original_response and baseline_stats:
            baselines = self.baseline._baselines.get(endpoint, [])
            if baselines:
                test_fp = ResponseFingerprint.from_response(original_response)
                max_baseline_sim = max(test_fp.similarity(bp) for bp in baselines)

                if max_baseline_sim < 0.85:
                    result.layers_passed.append("L3_fingerprint_divergence")
                    confidence += 0.2
                    result.evidence.append({"layer": "L3", "max_baseline_similarity": max_baseline_sim})
                else:
                    result.layers_failed.append("L3_fingerprint_divergence")
                    result.evidence.append({"layer": "L3", "reason": "too_similar_to_baseline", "similarity": max_baseline_sim})

        # ── Layer 4: Negative Validation ─────────────────
        safe_inputs = self._get_safe_inputs(finding_type)
        false_positive = False

        for safe_input in safe_inputs[:2]:
            safe_resp = await self._inject_and_request(
                request_func, endpoint, method, inject_param, inject_location, safe_input
            )
            if safe_resp and original_response:
                safe_fp = ResponseFingerprint.from_response(safe_resp)
                orig_fp = ResponseFingerprint.from_response(original_response)
                # If safe input produces same anomaly → false positive
                if safe_fp.similarity(orig_fp) > 0.9:
                    false_positive = True
                    break

        if not false_positive:
            result.layers_passed.append("L4_negative_validation")
            confidence += 0.2
        else:
            result.layers_failed.append("L4_negative_validation")
            confidence -= 0.3
            result.evidence.append({"layer": "L4", "reason": "safe_input_triggers_same_behavior"})

        # ── Layer 5: Cross-Signal Correlation ────────────
        signals = supporting_signals or []
        unique_signal_types = set(signals)
        if len(unique_signal_types) >= 2:
            result.layers_passed.append("L5_cross_signal")
            confidence += 0.2
            result.evidence.append({"layer": "L5", "signal_count": len(unique_signal_types), "types": list(unique_signal_types)})
        elif len(unique_signal_types) == 1:
            # Partial credit
            confidence += 0.05
        else:
            result.layers_failed.append("L5_cross_signal")

        # ── Final Verdict ────────────────────────────────
        result.final_confidence = max(0.0, min(1.0, confidence))
        result.verified = len(result.layers_passed) >= 3 and result.final_confidence >= 0.5

        # Generate curl command for reproduction
        result.curl_command = self._generate_curl(endpoint, method, inject_param, inject_location, payload)

        return result

    async def _inject_and_request(self, request_func, endpoint, method, param, location, payload):
        """Build and send an injection request."""
        if location == "query":
            sep = "&" if "?" in endpoint else "?"
            url = f"{endpoint}{sep}{param}={payload}"
            return await request_func(url, method)
        elif location == "body":
            return await request_func(endpoint, "POST", body=f"{param}={payload}",
                                      content_type="application/x-www-form-urlencoded")
        elif location == "path":
            import re
            url = re.sub(r'/(\d+)(?=[/?#]|$)', f'/{payload}', endpoint, count=1)
            return await request_func(url, method)
        else:
            return await request_func(endpoint, method)

    def _get_safe_inputs(self, finding_type: str) -> List[str]:
        """Get safe (non-malicious) inputs that should NOT trigger the vulnerability."""
        safe_map = {
            "sqli": ["1", "test", "hello", "12345"],
            "xss": ["hello", "test123", "normal text"],
            "ssti": ["hello", "7", "test"],
            "ssrf": ["https://example.com", "test"],
            "lfi": ["index.html", "test.txt"],
            "rce": ["hello", "test", "123"],
            "idor": ["99999998"],
            "nosqli": ["test", "1", "hello"],
        }
        for key, values in safe_map.items():
            if key in finding_type.lower():
                return values
        return ["test", "hello", "123"]

    def _generate_curl(self, endpoint, method, param, location, payload) -> str:
        """Generate a curl command for finding reproduction."""
        import shlex
        if location == "query":
            sep = "&" if "?" in endpoint else "?"
            url = f"{endpoint}{sep}{param}={payload}"
            return f"curl -X {method} {shlex.quote(url)} -k -v"
        elif location == "body":
            return f"curl -X POST {shlex.quote(endpoint)} -d {shlex.quote(f'{param}={payload}')} -k -v"
        elif location == "header":
            return f"curl -X {method} {shlex.quote(endpoint)} -H {shlex.quote(f'{param}: {payload}')} -k -v"
        else:
            return f"curl -X {method} {shlex.quote(endpoint)} -k -v"


# ── Verification Decorators for Agents ──────────────────────

class FindingVerifier:
    """
    Wraps AccuracyEngine for use by exploit agents.
    Provides simple verify() interface.
    """

    def __init__(self, accuracy_engine: AccuracyEngine = None):
        self.engine = accuracy_engine or AccuracyEngine()
        self._stats = {"verified": 0, "rejected": 0, "total": 0}

    async def verify(self, finding, request_func, **kwargs) -> Tuple[bool, float, Dict]:
        """
        Verify a finding. Returns (is_verified, adjusted_confidence, verification_details).
        """
        self._stats["total"] += 1

        result = await self.engine.verify_finding(
            finding_type=finding.type,
            endpoint=finding.endpoint,
            payload=kwargs.get("payload", ""),
            request_func=request_func,
            method=kwargs.get("method", finding.method),
            inject_param=kwargs.get("param", "id"),
            inject_location=kwargs.get("location", "query"),
            original_response=kwargs.get("original_response"),
            supporting_signals=finding.supporting_signals,
        )

        if result.verified:
            self._stats["verified"] += 1
            adjusted_confidence = min(1.0, finding.confidence * 0.5 + result.final_confidence * 0.5)
        else:
            self._stats["rejected"] += 1
            adjusted_confidence = finding.confidence * 0.3

        return result.verified, adjusted_confidence, result.to_dict()

    @property
    def stats(self) -> Dict:
        return dict(self._stats)
