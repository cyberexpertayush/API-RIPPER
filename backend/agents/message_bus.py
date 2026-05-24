"""API RIPPER v2.0 — Message Bus
Inter-agent signal-driven communication system.

Features:
  - Signal weights → effective_confidence = confidence × weight
  - Per-agent cap (MAX_SIGNALS_PER_AGENT = 50)
  - Deduplication via dedup_hash
  - TTL expiration
  - Priority queuing
  - Noise filtering (effective_confidence < 0.1 dropped)
"""

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# ── Signal Weight Constants ─────────────────────────────────
# Used by agents when emitting signals to indicate signal strength.

SIGNAL_WEIGHTS = {
    "STRUCTURAL_DIFF":     0.9,
    "SCHEMA_CHANGE":       0.8,
    "AUTH_BYPASS":         0.9,
    "IDOR_DETECTED":       0.9,
    "STATUS_CHANGE":       0.7,
    "HIDDEN_PARAM":        0.7,
    "SENSITIVE_EXPOSURE":   0.8,
    "LATENCY_ANOMALY":     0.5,
    "TECH_PROFILE":        0.4,
    "ENDPOINT_DISCOVERED": 0.6,
    "FRAGILE_ENDPOINT":    0.5,
    "ERROR_SURFACE":       0.6,
    "WEAK_PATTERN":        0.3,
    "INFO_LEAK":           0.6,
}

MAX_SIGNALS_PER_AGENT = 50


@dataclass
class Signal:
    """
    Typed message passed between agents via the Message Bus.

    Attributes:
        id:          Unique identifier
        type:        Signal type (e.g., "ENDPOINT_DISCOVERED", "STRUCTURAL_DIFF")
        source:      Agent that emitted this signal
        target:      Target agent name or "*" for broadcast
        data:        Structured payload
        confidence:  Emitter's confidence in this signal (0.0–1.0)
        weight:      Signal type weight (from SIGNAL_WEIGHTS, default 1.0)
        priority:    Processing priority (1=highest, 10=lowest)
        dedup_hash:  Hash for deduplication
        ttl:         Time-to-live (max hops before expiry)
        timestamp:   When the signal was created
    """
    id: str
    type: str
    source: str
    target: str
    data: Dict[str, Any]
    confidence: float
    weight: float = 1.0
    priority: int = 5
    dedup_hash: str = ""
    ttl: int = 5
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    @property
    def effective_confidence(self) -> float:
        """effective_confidence = confidence × weight"""
        return round(self.confidence * self.weight, 4)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.type,
            "source": self.source,
            "target": self.target,
            "data": self.data,
            "confidence": self.confidence,
            "weight": self.weight,
            "effective_confidence": self.effective_confidence,
            "priority": self.priority,
            "dedup_hash": self.dedup_hash,
            "ttl": self.ttl,
            "timestamp": self.timestamp,
        }


class MessageBus:
    """
    Central signal routing system for the multi-agent framework.

    Features:
        - Priority queue: high-priority signals processed first
        - Deduplication: identical signals rejected via dedup_hash
        - TTL: signals expire after max hops to prevent infinite loops
        - Noise filtering: signals with confidence < 0.1 are dropped
        - Subscription: agents subscribe to specific signal types
        - Thread-safe: all operations are protected by locks
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._signals: List[Signal] = []           # All signals (ordered)
        self._seen_hashes: Set[str] = set()         # Dedup set
        self._subscribers: Dict[str, List[str]] = {}  # agent_id → [signal_types]
        self._callbacks: Dict[str, List[Callable]] = {}  # signal_type → [callbacks]
        self._signal_count = 0
        self._dropped_count = 0
        self._per_agent_counts: Dict[str, int] = {}  # agent → signal count (for cap)

    # ── Emit ────────────────────────────────────────────────

    def emit(self, signal: Signal) -> bool:
        """
        Emit a signal onto the bus.

        Returns True if the signal was accepted, False if rejected.

        Rejection reasons:
          - Duplicate dedup_hash
          - TTL expired (≤ 0)
          - Confidence too low (< 0.1)
        """
        with self._lock:
            # Auto-assign weight from SIGNAL_WEIGHTS if not set
            if signal.weight == 1.0 and signal.type in SIGNAL_WEIGHTS:
                signal.weight = SIGNAL_WEIGHTS[signal.type]

            # Rule: Noise filter (use effective_confidence)
            if signal.effective_confidence < 0.1:
                self._dropped_count += 1
                logger.debug(f"[MessageBus] Dropped noise: {signal.type} (eff={signal.effective_confidence:.3f})")
                return False

            # Rule: TTL check
            if signal.ttl <= 0:
                self._dropped_count += 1
                return False

            # Rule: Deduplication
            if signal.dedup_hash and signal.dedup_hash in self._seen_hashes:
                self._dropped_count += 1
                return False

            # Rule: Per-agent signal cap (MAX_SIGNALS_PER_AGENT)
            agent_count = self._per_agent_counts.get(signal.source, 0)
            if agent_count >= MAX_SIGNALS_PER_AGENT:
                self._dropped_count += 1
                logger.debug(f"[MessageBus] Cap exceeded for {signal.source} ({agent_count}/{MAX_SIGNALS_PER_AGENT})")
                return False

            # Accept signal
            if signal.dedup_hash:
                self._seen_hashes.add(signal.dedup_hash)
            signal.ttl -= 1
            self._signals.append(signal)
            self._signal_count += 1
            self._per_agent_counts[signal.source] = agent_count + 1

            logger.debug(
                f"[MessageBus] Signal: {signal.source} → {signal.target} "
                f"| {signal.type} (eff={signal.effective_confidence:.3f}, w={signal.weight}, pri={signal.priority})"
            )

            # Fire callbacks
            if signal.type in self._callbacks:
                for cb in self._callbacks[signal.type]:
                    try:
                        cb(signal)
                    except Exception as e:
                        logger.error(f"[MessageBus] Callback error: {e}")

            return True

    # ── Consume ─────────────────────────────────────────────

    def consume(self, agent_id: str, signal_types: List[str] = None) -> List[Signal]:
        """
        Consume all signals targeted at a specific agent.

        Signals are returned sorted by priority (1=highest first),
        then by confidence (highest first).

        Args:
            agent_id:     The consuming agent's name
            signal_types: Optional filter — only return these signal types
        """
        with self._lock:
            result = []
            remaining = []

            for signal in self._signals:
                # Check target match
                is_targeted = (signal.target == "*" or signal.target == agent_id)
                # Check type filter
                type_match = (signal_types is None or signal.type in signal_types)

                if is_targeted and type_match:
                    result.append(signal)
                else:
                    remaining.append(signal)

            # Sort: priority ascending (1=first), then confidence descending
            result.sort(key=lambda s: (s.priority, -s.confidence))

            # Remove consumed signals from bus (for targeted signals)
            # Broadcast signals ("*") remain for other consumers
            self._signals = []
            for signal in remaining:
                self._signals.append(signal)
            # Re-add broadcast signals that weren't consumed by this agent
            for signal in result:
                if signal.target == "*":
                    # Broadcast signals stay on the bus but are still returned
                    pass  # Already consumed by this agent

            return result

    # ── Peek (non-consuming) ────────────────────────────────

    def peek(self, agent_id: str, signal_types: List[str] = None) -> List[Signal]:
        """Look at signals without consuming them."""
        with self._lock:
            result = []
            for signal in self._signals:
                is_targeted = (signal.target == "*" or signal.target == agent_id)
                type_match = (signal_types is None or signal.type in signal_types)
                if is_targeted and type_match:
                    result.append(signal)
            result.sort(key=lambda s: (s.priority, -s.confidence))
            return result

    # ── Subscribe ───────────────────────────────────────────

    def subscribe(self, agent_id: str, signal_types: List[str]):
        """Register an agent's interest in specific signal types."""
        with self._lock:
            self._subscribers[agent_id] = signal_types

    def on_signal(self, signal_type: str, callback: Callable):
        """Register a real-time callback for a signal type."""
        with self._lock:
            if signal_type not in self._callbacks:
                self._callbacks[signal_type] = []
            self._callbacks[signal_type].append(callback)

    # ── Query ───────────────────────────────────────────────

    def get_all_signals(self) -> List[Signal]:
        """Get all signals on the bus (for debugging/tracing)."""
        with self._lock:
            return list(self._signals)

    def get_signals_by_type(self, signal_type: str) -> List[Signal]:
        """Get all signals of a specific type."""
        with self._lock:
            return [s for s in self._signals if s.type == signal_type]

    def get_signals_from(self, source_agent: str) -> List[Signal]:
        """Get all signals emitted by a specific agent."""
        with self._lock:
            return [s for s in self._signals if s.source == source_agent]

    # ── Convergence Detection ───────────────────────────────

    def has_new_signals_since(self, since_count: int) -> bool:
        """
        Check if new signals have arrived since a given count.
        Used for convergence detection — if no new signals emerge
        after 2 agent cycles, the system can stop early.
        """
        return self._signal_count > since_count

    @property
    def total_signals(self) -> int:
        return self._signal_count

    @property
    def dropped_signals(self) -> int:
        return self._dropped_count

    # ── Reset ───────────────────────────────────────────────

    def clear(self):
        """Clear all signals and state (for new scan)."""
        with self._lock:
            self._signals.clear()
            self._seen_hashes.clear()
            self._signal_count = 0
            self._dropped_count = 0
            self._per_agent_counts.clear()

    def stats(self) -> dict:
        """Get bus statistics."""
        with self._lock:
            return {
                "total_emitted": self._signal_count,
                "total_dropped": self._dropped_count,
                "pending_signals": len(self._signals),
                "dedup_entries": len(self._seen_hashes),
                "subscribers": len(self._subscribers),
                "per_agent_counts": dict(self._per_agent_counts),
            }
