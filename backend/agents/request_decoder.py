"""
API RIPPER v2.0 — Request Decoder
Deep request/response parsing and analysis utility.
Decodes URL structure, parameter types, body formats,
headers, cookies, embedded tokens, and encoding layers.

Used by agents (especially Recon and Differential) to
understand API request/response semantics.
"""

import base64
import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, unquote

logger = logging.getLogger(__name__)


class RequestDecoder:
    """
    Deep request/response decoder for API analysis.
    Parses every layer of an HTTP transaction to extract
    structural intelligence for the Knowledge Graph.
    """

    @staticmethod
    def decode_url(url: str) -> Dict[str, Any]:
        """Parse URL into structured components."""
        parsed = urlparse(url)
        path_segments = [s for s in parsed.path.strip("/").split("/") if s]
        query_params = parse_qs(parsed.query, keep_blank_values=True)

        # Detect ID patterns in path
        id_segments = []
        resource_segments = []
        for i, seg in enumerate(path_segments):
            if re.match(r'^\d+$', seg):
                id_segments.append({"index": i, "value": seg, "type": "integer_id"})
            elif re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', seg, re.I):
                id_segments.append({"index": i, "value": seg, "type": "uuid"})
            elif re.match(r'^[a-f0-9]{24}$', seg, re.I):
                id_segments.append({"index": i, "value": seg, "type": "mongodb_id"})
            else:
                resource_segments.append(seg)

        # Detect versioning
        version = None
        for seg in path_segments:
            if re.match(r'^v\d+$', seg, re.I):
                version = seg
                break

        # Classify parameters
        param_types = {}
        for key, values in query_params.items():
            val = values[0] if values else ""
            param_types[key] = {
                "value": val,
                "type": RequestDecoder._infer_param_type(val),
                "location": "query",
            }

        return {
            "scheme": parsed.scheme,
            "host": parsed.netloc,
            "path": parsed.path,
            "path_segments": path_segments,
            "resource_hierarchy": resource_segments,
            "id_segments": id_segments,
            "version": version,
            "query_params": param_types,
            "fragment": parsed.fragment,
            "has_ids": len(id_segments) > 0,
        }

    @staticmethod
    def decode_headers(headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze HTTP headers for security-relevant information."""
        analysis = {
            "auth_type": None,
            "auth_token": None,
            "content_type": None,
            "security_headers": {},
            "info_leaks": [],
            "custom_headers": [],
            "caching": {},
        }

        security_headers = [
            "strict-transport-security", "content-security-policy",
            "x-content-type-options", "x-frame-options",
            "x-xss-protection", "referrer-policy",
            "permissions-policy", "cross-origin-opener-policy",
            "cross-origin-resource-policy",
        ]

        leak_headers = [
            "server", "x-powered-by", "x-aspnet-version",
            "x-runtime", "x-generator", "x-debug",
        ]

        for key, value in headers.items():
            lower_key = key.lower()

            # Auth detection
            if lower_key == "authorization":
                if value.lower().startswith("bearer "):
                    analysis["auth_type"] = "bearer_jwt" if value.count(".") == 2 else "bearer_opaque"
                    analysis["auth_token"] = value[7:]
                elif value.lower().startswith("basic "):
                    analysis["auth_type"] = "basic"
                    analysis["auth_token"] = value[6:]
                elif value.lower().startswith("apikey "):
                    analysis["auth_type"] = "api_key"
                    analysis["auth_token"] = value[7:]

            # API key headers
            if lower_key in ("x-api-key", "api-key", "apikey", "x-auth-token"):
                analysis["auth_type"] = "api_key_header"
                analysis["auth_token"] = value

            # Content type
            if lower_key == "content-type":
                analysis["content_type"] = value

            # Security headers (present or missing)
            if lower_key in security_headers:
                analysis["security_headers"][lower_key] = value

            # Info leaks
            if lower_key in leak_headers and value:
                analysis["info_leaks"].append({"header": key, "value": value})

            # Caching
            if lower_key in ("cache-control", "expires", "etag", "last-modified"):
                analysis["caching"][lower_key] = value

            # Custom headers
            if lower_key.startswith("x-") and lower_key not in leak_headers:
                analysis["custom_headers"].append({"header": key, "value": value})

        # Missing security headers
        analysis["missing_security_headers"] = [
            h for h in security_headers
            if h not in analysis["security_headers"]
        ]

        return analysis

    @staticmethod
    def decode_body(body: str, content_type: str = "") -> Dict[str, Any]:
        """Parse request/response body based on content type."""
        result = {
            "format": "unknown",
            "parsed": None,
            "fields": [],
            "nested_depth": 0,
            "embedded_tokens": [],
            "embedded_urls": [],
        }

        ct = content_type.lower()

        if "json" in ct or body.strip().startswith(("{", "[")):
            try:
                parsed = json.loads(body)
                result["format"] = "json"
                result["parsed"] = parsed
                result["fields"] = RequestDecoder._extract_json_fields(parsed)
                result["nested_depth"] = RequestDecoder._json_depth(parsed)
                result["embedded_tokens"] = RequestDecoder._find_tokens(body)
                result["embedded_urls"] = re.findall(r'https?://[^\s"\']+', body)
            except json.JSONDecodeError:
                result["format"] = "invalid_json"

        elif "xml" in ct or body.strip().startswith("<"):
            result["format"] = "xml"
            result["embedded_tokens"] = RequestDecoder._find_tokens(body)

        elif "form" in ct:
            result["format"] = "form_urlencoded"
            pairs = body.split("&")
            for pair in pairs:
                if "=" in pair:
                    key, val = pair.split("=", 1)
                    result["fields"].append({
                        "name": unquote(key),
                        "value": unquote(val),
                        "type": RequestDecoder._infer_param_type(unquote(val)),
                    })

        elif "multipart" in ct:
            result["format"] = "multipart"

        else:
            result["format"] = "text"
            result["embedded_tokens"] = RequestDecoder._find_tokens(body)
            result["embedded_urls"] = re.findall(r'https?://[^\s"\']+', body)

        return result

    @staticmethod
    def decode_cookies(cookie_header: str) -> List[Dict[str, Any]]:
        """Parse and analyze cookies for security properties."""
        cookies = []
        if not cookie_header:
            return cookies

        for pair in cookie_header.split(";"):
            pair = pair.strip()
            if "=" in pair:
                name, value = pair.split("=", 1)
                cookie = {
                    "name": name.strip(),
                    "value": value.strip(),
                    "length": len(value.strip()),
                    "looks_like_session": any(
                        kw in name.lower()
                        for kw in ["session", "sess", "sid", "token", "auth", "jwt"]
                    ),
                    "entropy": RequestDecoder._estimate_entropy(value.strip()),
                }
                cookies.append(cookie)

        return cookies

    @staticmethod
    def full_decode(
        url: str,
        method: str = "GET",
        headers: Dict[str, str] = None,
        body: str = "",
        status_code: int = 0,
        response_headers: Dict[str, str] = None,
        response_body: str = "",
    ) -> Dict[str, Any]:
        """Full decode of an HTTP request/response pair."""
        return {
            "request": {
                "url": RequestDecoder.decode_url(url),
                "method": method,
                "headers": RequestDecoder.decode_headers(headers or {}),
                "body": RequestDecoder.decode_body(body, (headers or {}).get("content-type", "")),
                "cookies": RequestDecoder.decode_cookies((headers or {}).get("cookie", "")),
            },
            "response": {
                "status_code": status_code,
                "headers": RequestDecoder.decode_headers(response_headers or {}),
                "body": RequestDecoder.decode_body(
                    response_body,
                    (response_headers or {}).get("content-type", ""),
                ),
            },
        }

    # ── Helpers ─────────────────────────────────────────────

    @staticmethod
    def _infer_param_type(value: str) -> str:
        if not value:
            return "empty"
        if re.match(r'^\d+$', value):
            return "integer"
        if re.match(r'^\d+\.\d+$', value):
            return "float"
        if re.match(r'^(true|false)$', value, re.I):
            return "boolean"
        if re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-', value, re.I):
            return "uuid"
        if re.match(r'^[\w.+-]+@[\w-]+\.[\w.]+$', value):
            return "email"
        if re.match(r'^https?://', value):
            return "url"
        if value.startswith("eyJ"):
            return "jwt"
        return "string"

    @staticmethod
    def _extract_json_fields(data: Any, prefix: str = "") -> List[Dict]:
        fields = []
        if isinstance(data, dict):
            for key, val in data.items():
                path = f"{prefix}.{key}" if prefix else key
                fields.append({
                    "name": path,
                    "type": RequestDecoder._infer_param_type(str(val)) if isinstance(val, str) else type(val).__name__,
                    "sample": str(val)[:100],
                })
                if isinstance(val, dict):
                    fields.extend(RequestDecoder._extract_json_fields(val, path))
                elif isinstance(val, list) and val and isinstance(val[0], dict):
                    fields.extend(RequestDecoder._extract_json_fields(val[0], f"{path}[]"))
        return fields

    @staticmethod
    def _json_depth(data: Any, depth: int = 0) -> int:
        if isinstance(data, dict):
            if not data:
                return depth
            return max(RequestDecoder._json_depth(v, depth + 1) for v in data.values())
        if isinstance(data, list) and data:
            return max(RequestDecoder._json_depth(v, depth + 1) for v in data[:5])
        return depth

    @staticmethod
    def _find_tokens(text: str) -> List[Dict]:
        tokens = []
        # JWT tokens
        for match in re.finditer(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', text):
            tokens.append({"type": "jwt", "value": match.group()[:50] + "...", "position": match.start()})
        # API keys (common patterns)
        for match in re.finditer(r'(?:api[_-]?key|token|secret|password)\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]{20,})', text, re.I):
            tokens.append({"type": "api_key", "value": match.group(1)[:30] + "...", "position": match.start()})
        # Base64 strings
        for match in re.finditer(r'[A-Za-z0-9+/]{40,}={0,2}', text):
            try:
                decoded = base64.b64decode(match.group()).decode("utf-8", errors="replace")
                if any(c.isprintable() for c in decoded[:20]):
                    tokens.append({"type": "base64", "decoded_preview": decoded[:50], "position": match.start()})
            except Exception:
                pass
        return tokens[:10]

    @staticmethod
    def _estimate_entropy(value: str) -> float:
        if not value:
            return 0.0
        import math
        freq = {}
        for c in value:
            freq[c] = freq.get(c, 0) + 1
        total = len(value)
        entropy = -sum((count / total) * math.log2(count / total) for count in freq.values())
        return round(entropy, 3)
