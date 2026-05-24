"""
API RIPPER v2.0 — Resource Governor
Central request budget controller shared across all agents.

Enforces:
  - MAX_TOTAL_REQUESTS = 8000
  - MAX_REQUESTS_PER_ENDPOINT = 100
  - MAX_SCAN_TIME = 20 minutes
  - Adaptive budgeting: high-risk endpoints get more requests

Agents MUST call governor.can_request() before every HTTP request.
"""

import logging
import threading
import time
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# ── Defaults ────────────────────────────────────────────────
MAX_TOTAL_REQUESTS = 8000
MAX_REQUESTS_PER_ENDPOINT = 100
MAX_SCAN_TIME_SECONDS = 3600  # 60 minutes
BASE_ENDPOINT_BUDGET = 30
PRIORITY_MULTIPLIER = 10


class ResourceGovernor:
    """
    Central request budget controller.
    All agents share a single governor instance per scan.

    Adaptive budgeting:
      endpoint_budget = BASE + (risk_score × PRIORITY_MULTIPLIER)
      High-risk endpoints get more testing budget.
      Low-value endpoints get minimal budget.
    """

    def __init__(
        self,
        max_total: int = MAX_TOTAL_REQUESTS,
        max_per_endpoint: int = MAX_REQUESTS_PER_ENDPOINT,
        max_time_seconds: int = MAX_SCAN_TIME_SECONDS,
    ):
        self._lock = threading.Lock()
        self.max_total = max_total
        self.max_per_endpoint = max_per_endpoint
        self.max_time_seconds = max_time_seconds

        self._total_requests = 0
        self._endpoint_counts: Dict[str, int] = {}
        self._agent_counts: Dict[str, int] = {}
        self._endpoint_budgets: Dict[str, int] = {}  # Adaptive budgets
        self._start_time = time.time()

        # Tracking
        self._blocked_requests = 0
        self._time_expired = False

    def can_request(self, endpoint_url: str, agent_name: str = "") -> bool:
        """
        Check if a request to this endpoint is allowed.

        Returns False if:
          - Total request budget exhausted
          - Per-endpoint budget exhausted
          - Scan time expired
        """
        with self._lock:
            # Time check
            if self._check_time_expired():
                return False

            # Total budget check
            if self._total_requests >= self.max_total:
                self._blocked_requests += 1
                logger.debug(f"[Governor] BLOCKED: total budget exhausted ({self._total_requests}/{self.max_total})")
                return False

            # Per-endpoint budget check (adaptive)
            ep_budget = self._get_endpoint_budget(endpoint_url)
            ep_count = self._endpoint_counts.get(endpoint_url, 0)
            if ep_count >= ep_budget:
                self._blocked_requests += 1
                logger.debug(f"[Governor] BLOCKED: endpoint budget exhausted for {endpoint_url} ({ep_count}/{ep_budget})")
                return False

            return True

    def record_request(self, endpoint_url: str, agent_name: str = ""):
        """Record a request for budget tracking."""
        with self._lock:
            self._total_requests += 1
            self._endpoint_counts[endpoint_url] = self._endpoint_counts.get(endpoint_url, 0) + 1
            if agent_name:
                self._agent_counts[agent_name] = self._agent_counts.get(agent_name, 0) + 1

    def set_endpoint_priority(self, endpoint_url: str, risk_score: float):
        """
        Set adaptive budget for an endpoint based on risk.

        Budget = BASE + (risk_score × MULTIPLIER)
        High-risk (risk=8.0) → 30 + 80 = 110 → capped at max_per_endpoint
        Low-risk  (risk=1.0) → 30 + 10 = 40
        """
        with self._lock:
            budget = int(BASE_ENDPOINT_BUDGET + (risk_score * PRIORITY_MULTIPLIER))
            self._endpoint_budgets[endpoint_url] = min(budget, self.max_per_endpoint)

    def increase_delay(self, added_ms: int):
        """Dynamically increase the global delay (e.g. when WAF is detected)."""
        with self._lock:
            if not hasattr(self, "_global_delay_ms"):
                self._global_delay_ms = 0
            self._global_delay_ms += added_ms
            logger.info(f"[governor] Global delay increased to {self._global_delay_ms}ms")

    def get_delay_ms(self) -> int:
        with self._lock:
            return getattr(self, "_global_delay_ms", 0)

    def is_time_expired(self) -> bool:
        """Check if scan time limit has been exceeded."""
        with self._lock:
            return self._check_time_expired()

    def _check_time_expired(self) -> bool:
        elapsed = time.time() - self._start_time
        if elapsed >= self.max_time_seconds:
            if not self._time_expired:
                self._time_expired = True
                logger.warning(f"[Governor] Scan time limit reached ({self.max_time_seconds}s)")
            return True
        return False

    def _get_endpoint_budget(self, endpoint_url: str) -> int:
        """Get adaptive budget for an endpoint."""
        return self._endpoint_budgets.get(endpoint_url, BASE_ENDPOINT_BUDGET)

    # ── Observability ───────────────────────────────────────

    @property
    def total_requests(self) -> int:
        with self._lock:
            return self._total_requests

    @property
    def remaining_budget(self) -> int:
        with self._lock:
            return max(0, self.max_total - self._total_requests)

    @property
    def elapsed_seconds(self) -> float:
        return round(time.time() - self._start_time, 2)

    @property
    def remaining_time_seconds(self) -> float:
        return max(0, self.max_time_seconds - self.elapsed_seconds)

    def get_agent_usage(self, agent_name: str) -> int:
        with self._lock:
            return self._agent_counts.get(agent_name, 0)

    def stats(self) -> dict:
        with self._lock:
            return {
                "total_requests": self._total_requests,
                "max_total": self.max_total,
                "remaining_budget": max(0, self.max_total - self._total_requests),
                "blocked_requests": self._blocked_requests,
                "unique_endpoints": len(self._endpoint_counts),
                "elapsed_seconds": round(time.time() - self._start_time, 2),
                "max_time_seconds": self.max_time_seconds,
                "time_expired": self._time_expired,
                "per_agent": dict(self._agent_counts),
                "top_endpoints": dict(
                    sorted(self._endpoint_counts.items(), key=lambda x: x[1], reverse=True)[:10]
                ),
            }
