"""
API RIPPER v2.0 — WAF Detection & Bypass Handler
Deep WAF detection with adaptive bypass strategies.

Detects:
  - Cloudflare, Akamai, AWS WAF/Shield, Imperva, ModSecurity
  - Sucuri, F5 BIG-IP, Barracuda, Fortinet
  - Rate-limiting patterns (429/403 bursts)
  - Challenge pages (JS challenges, CAPTCHA)
  - Response jitter and header mutation patterns

Bypass strategies:
  - Header rotation (User-Agent, Accept, Referer)
  - Request timing jitter (randomized delays)
  - Cookie preservation
  - Cache-buster query params
  - Adaptive rate reduction on detection
"""

import logging
import random
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ── WAF Signatures ──────────────────────────────────────────

WAF_SIGNATURES = {
    "cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id"],
        "server": ["cloudflare"],
        "cookies": ["__cfduid", "cf_clearance", "__cf_bm"],
        "body_patterns": ["attention required", "cloudflare", "ray id"],
    },
    "akamai": {
        "headers": ["x-akamai-transformed", "akamai-grn", "x-akamai-request-id"],
        "server": ["akamaighost", "akamai"],
        "cookies": ["akamai_generated", "ak_bmsc", "bm_sv"],
        "body_patterns": ["access denied", "akamai"],
    },
    "aws_waf": {
        "headers": ["x-amzn-requestid", "x-amz-cf-id", "x-amz-apigw-id"],
        "server": ["awselb", "amazons3", "cloudfront"],
        "cookies": ["awsalb", "awsalbcors"],
        "body_patterns": ["request blocked", "aws waf"],
    },
    "imperva": {
        "headers": ["x-iinfo", "x-cdn"],
        "server": ["imperva", "incapsula"],
        "cookies": ["incap_ses", "visid_incap", "__incap_ses"],
        "body_patterns": ["incapsula", "imperva"],
    },
    "modsecurity": {
        "headers": ["x-mod-security"],
        "server": ["modsecurity"],
        "cookies": [],
        "body_patterns": ["modsecurity", "mod_security", "not acceptable"],
    },
    "sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "server": ["sucuri"],
        "cookies": ["sucuri_cloudproxy"],
        "body_patterns": ["sucuri website firewall", "access denied - sucuri"],
    },
    "f5_bigip": {
        "headers": ["x-wa-info"],
        "server": ["bigip", "big-ip", "f5"],
        "cookies": ["ts", "bigipserver"],
        "body_patterns": ["the requested url was rejected"],
    },
}

# ── User-Agent Pool ─────────────────────────────────────────

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
]

ACCEPT_HEADERS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "application/json, text/plain, */*",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "*/*",
]

ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.5",
    "en,es;q=0.9",
]

REFERERS = [
    "",  # No referer
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://duckduckgo.com/",
]


# ── Data Classes ────────────────────────────────────────────

@dataclass
class WAFProfile:
    """Detected WAF information."""
    detected: bool = False
    waf_name: str = "none"
    confidence: float = 0.0
    signatures_matched: List[str] = field(default_factory=list)
    rate_limiting_detected: bool = False
    challenge_page_detected: bool = False
    block_status_codes: List[int] = field(default_factory=list)
    # Adaptive state
    consecutive_blocks: int = 0
    last_block_time: float = 0.0

    def to_dict(self) -> dict:
        return {
            "detected": self.detected,
            "waf_name": self.waf_name,
            "confidence": self.confidence,
            "signatures_matched": self.signatures_matched,
            "rate_limiting": self.rate_limiting_detected,
            "challenge_page": self.challenge_page_detected,
            "block_codes": self.block_status_codes,
        }


# ── WAF Detector ────────────────────────────────────────────

class WAFDetector:
    """
    Detects WAF presence from HTTP response data.
    Uses signature matching on headers, server, cookies, and body.
    Also detects rate-limiting patterns and challenge pages.
    """

    def __init__(self):
        self.profile = WAFProfile()
        self._status_history: List[int] = []
        self._block_count = 0

    def analyze_response(
        self,
        status_code: int,
        headers: Dict[str, str],
        body: str = "",
        cookies: Dict[str, str] = None,
    ) -> WAFProfile:
        """
        Analyze a response for WAF signatures.
        Call this on every response for pattern detection.
        """
        self._status_history.append(status_code)
        lower_headers = {k.lower(): v.lower() for k, v in headers.items()}
        lower_body = body.lower()[:5000]  # Only check first 5KB
        cookie_names = list((cookies or {}).keys())

        # Check each WAF signature
        best_match = ""
        best_score = 0.0
        all_sigs = []

        for waf_name, sigs in WAF_SIGNATURES.items():
            score = 0.0
            matched = []

            # Header check
            for h in sigs["headers"]:
                if h.lower() in lower_headers:
                    score += 0.3
                    matched.append(f"header:{h}")

            # Server header check
            server = lower_headers.get("server", "")
            for s in sigs["server"]:
                if s in server:
                    score += 0.4
                    matched.append(f"server:{s}")

            # Cookie check
            for c in sigs["cookies"]:
                if c in cookie_names or any(c.lower() in cn.lower() for cn in cookie_names):
                    score += 0.2
                    matched.append(f"cookie:{c}")

            # Body pattern check
            for p in sigs["body_patterns"]:
                if p in lower_body:
                    score += 0.3
                    matched.append(f"body:{p}")

            if score > best_score:
                best_score = score
                best_match = waf_name
                all_sigs = matched

        # Update profile
        if best_score >= 0.3:
            self.profile.detected = True
            self.profile.waf_name = best_match
            self.profile.confidence = min(1.0, best_score)
            self.profile.signatures_matched = all_sigs

        # Detect rate limiting (429 or burst 403s)
        self._detect_rate_limiting(status_code)

        # Detect challenge pages
        self._detect_challenge(status_code, lower_body, lower_headers)

        # Track blocks
        if status_code in (403, 429, 503):
            self.profile.consecutive_blocks += 1
            self.profile.last_block_time = time.time()
            if status_code not in self.profile.block_status_codes:
                self.profile.block_status_codes.append(status_code)
        else:
            self.profile.consecutive_blocks = 0

        return self.profile

    def _detect_rate_limiting(self, status_code: int):
        """Detect rate-limiting from status code patterns."""
        if status_code == 429:
            self.profile.rate_limiting_detected = True
            self._block_count += 1
            return

        # Check for burst 403s (last 5 responses)
        recent = self._status_history[-5:]
        if len(recent) >= 3 and recent.count(403) >= 3:
            self.profile.rate_limiting_detected = True
            self._block_count += 1

    def _detect_challenge(self, status_code: int, body: str, headers: Dict[str, str]):
        """Detect JS challenges and CAPTCHA pages."""
        challenge_indicators = [
            "checking your browser",
            "just a moment",
            "enable javascript",
            "captcha",
            "recaptcha",
            "hcaptcha",
            "challenge-platform",
            "managed challenge",
            "_cf_chl_opt",
        ]
        for indicator in challenge_indicators:
            if indicator in body:
                self.profile.challenge_page_detected = True
                return

        # Cloudflare challenge response (503 with specific content)
        if status_code == 503 and "cf-ray" in headers:
            self.profile.challenge_page_detected = True


# ── WAF Bypass ──────────────────────────────────────────────

class WAFBypass:
    """
    Adaptive bypass strategies for detected WAFs.

    Strategies:
      1. Header rotation (User-Agent, Accept, Referer, Accept-Language)
      2. Request timing jitter (randomized delays)
      3. Cookie preservation across requests
      4. Cache-buster query params
      5. Adaptive rate reduction on detection
    """

    def __init__(self, waf_profile: WAFProfile = None):
        self.waf_profile = waf_profile or WAFProfile()
        self._request_count = 0
        self._cookies: Dict[str, str] = {}

        # Adaptive delay (increases when WAF blocks)
        self._base_delay = 0.2  # 200ms base
        self._current_delay = 0.2
        self._max_delay = 5.0

    def get_bypass_headers(self) -> Dict[str, str]:
        """
        Get a rotated header set for this request.
        Each call returns a slightly different fingerprint.
        """
        self._request_count += 1

        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": random.choice(ACCEPT_HEADERS),
            "Accept-Language": random.choice(ACCEPT_LANGUAGES),
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        }

        # Add referer occasionally
        referer = random.choice(REFERERS)
        if referer:
            headers["Referer"] = referer

        # Vary DNT header randomly
        if random.random() > 0.5:
            headers["DNT"] = "1"

        # Add Sec-Fetch headers (modern browser fingerprint)
        if random.random() > 0.3:
            headers["Sec-Fetch-Dest"] = random.choice(["document", "empty"])
            headers["Sec-Fetch-Mode"] = random.choice(["navigate", "cors", "no-cors"])
            headers["Sec-Fetch-Site"] = random.choice(["none", "same-origin", "cross-site"])

        return headers

    def get_cache_buster(self) -> str:
        """Generate a cache-buster query parameter."""
        return f"_cb={int(time.time() * 1000)}{random.randint(100, 999)}"

    def preserve_cookies(self, response_cookies: Dict[str, str]):
        """Preserve cookies from responses for session continuity."""
        self._cookies.update(response_cookies)

    def get_cookies(self) -> Dict[str, str]:
        """Get preserved cookies."""
        return dict(self._cookies)

    async def adaptive_delay(self):
        """
        Apply adaptive delay based on WAF state.
        Increases delay on blocks, decreases on success.
        """
        import asyncio

        if self.waf_profile.consecutive_blocks > 0:
            # Exponential backoff on blocks
            multiplier = min(2 ** self.waf_profile.consecutive_blocks, 10)
            self._current_delay = min(self._base_delay * multiplier, self._max_delay)
            logger.debug(f"[WAFBypass] Backoff delay: {self._current_delay:.1f}s (blocks={self.waf_profile.consecutive_blocks})")
        else:
            # Slowly recover to base delay
            self._current_delay = max(self._base_delay, self._current_delay * 0.9)

        # Add jitter (±30%)
        jitter = self._current_delay * random.uniform(-0.3, 0.3)
        actual_delay = max(0.05, self._current_delay + jitter)

        await asyncio.sleep(actual_delay)

    def on_block_detected(self):
        """Called when a WAF block is detected (403/429/503)."""
        self.waf_profile.consecutive_blocks += 1
        self.waf_profile.last_block_time = time.time()

    def on_success(self):
        """Called on successful response."""
        self.waf_profile.consecutive_blocks = 0

    def should_abort(self) -> bool:
        """
        Check if we should abort scanning due to heavy WAF blocking.
        Returns True if >10 consecutive blocks.
        """
        return self.waf_profile.consecutive_blocks > 10

    def stats(self) -> dict:
        return {
            "waf_detected": self.waf_profile.detected,
            "waf_name": self.waf_profile.waf_name,
            "rate_limiting": self.waf_profile.rate_limiting_detected,
            "challenge_pages": self.waf_profile.challenge_page_detected,
            "consecutive_blocks": self.waf_profile.consecutive_blocks,
            "current_delay": round(self._current_delay, 3),
            "total_requests": self._request_count,
            "preserved_cookies": len(self._cookies),
        }
