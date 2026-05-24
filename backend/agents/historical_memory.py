"""
API RIPPER v2.0 — Historical Memory
Tracks analysis across scans for drift detection and regression analysis.

Connected to scoring:
  - Repeat findings → confidence boost
  - Regression detected → risk score increase
  - Previously confirmed anomaly → prioritize testing

Uses SQLite via the existing database for persistence.
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import Column, String, Float, Integer, Text, DateTime, create_engine
from sqlalchemy.orm import sessionmaker

logger = logging.getLogger(__name__)


class HistoricalMemory:
    """
    Persistent memory across scans for the same target.
    Enables drift detection, regression analysis, and confidence boosting.
    """

    def __init__(self, db_session_factory=None):
        self._db_factory = db_session_factory
        self._cache: Dict[str, Dict] = {}  # target → last scan data

    def record_scan(
        self,
        scan_id: str,
        target_url: str,
        endpoint_urls: List[str],
        finding_signatures: List[Dict[str, Any]],
        risk_scores: Dict[str, float],
    ):
        """
        Record scan results for future comparison.
        finding_signatures: [{type, endpoint, severity, confidence}, ...]
        risk_scores: {endpoint_url: score, ...}
        """
        record = {
            "scan_id": scan_id,
            "target_url": target_url,
            "timestamp": datetime.utcnow().isoformat(),
            "endpoint_count": len(endpoint_urls),
            "endpoints": endpoint_urls[:500],  # Cap at 500
            "findings": finding_signatures[:200],  # Cap at 200
            "risk_scores": risk_scores,
            "finding_types": list(set(f.get("type", "") for f in finding_signatures)),
        }
        self._cache[target_url] = record

        # Persist to DB if available
        if self._db_factory:
            try:
                self._persist_record(target_url, record)
            except Exception as e:
                logger.warning(f"[HistoricalMemory] Failed to persist: {e}")

    def get_previous_scan(self, target_url: str) -> Optional[Dict]:
        """Get the most recent previous scan for this target."""
        if target_url in self._cache:
            return self._cache[target_url]

        if self._db_factory:
            try:
                return self._load_record(target_url)
            except Exception:
                return None
        return None

    def detect_drift(
        self,
        current_endpoints: List[str],
        current_findings: List[Dict],
        target_url: str,
    ) -> List[Dict[str, Any]]:
        """
        Detect changes between current scan and previous scan.

        Returns list of drift events:
          - new_endpoints: endpoints that didn't exist before
          - removed_endpoints: endpoints that disappeared
          - new_findings: finding types that are new
          - resolved_findings: finding types that were fixed
        """
        previous = self.get_previous_scan(target_url)
        if not previous:
            return []

        drift_events = []
        prev_endpoints = set(previous.get("endpoints", []))
        curr_endpoints = set(current_endpoints)

        # New endpoints
        new_eps = curr_endpoints - prev_endpoints
        if new_eps:
            drift_events.append({
                "type": "new_endpoints",
                "count": len(new_eps),
                "endpoints": list(new_eps)[:20],
                "significance": "medium",
            })

        # Removed endpoints
        removed_eps = prev_endpoints - curr_endpoints
        if removed_eps:
            drift_events.append({
                "type": "removed_endpoints",
                "count": len(removed_eps),
                "endpoints": list(removed_eps)[:20],
                "significance": "low",
            })

        # New finding types
        prev_types = set(previous.get("finding_types", []))
        curr_types = set(f.get("type", "") for f in current_findings)
        new_types = curr_types - prev_types
        if new_types:
            drift_events.append({
                "type": "new_finding_types",
                "types": list(new_types),
                "significance": "high",
            })

        # Resolved finding types
        resolved_types = prev_types - curr_types
        if resolved_types:
            drift_events.append({
                "type": "resolved_finding_types",
                "types": list(resolved_types),
                "significance": "info",
            })

        return drift_events

    def detect_regressions(
        self,
        current_findings: List[Dict],
        target_url: str,
    ) -> List[str]:
        """
        Detect regressions — findings that were previously resolved
        but have reappeared.
        """
        previous = self.get_previous_scan(target_url)
        if not previous:
            return []

        prev_types = set(previous.get("finding_types", []))
        curr_types = set(f.get("type", "") for f in current_findings)

        # A regression is when a previously-seen finding type reappears
        # after being absent (would need multi-scan history for true regression)
        # For now: flag findings that match previous scan
        regressions = []
        for ft in curr_types:
            if ft in prev_types:
                regressions.append(f"Recurring finding: {ft}")

        return regressions

    def get_confidence_boost(self, finding_type: str, endpoint: str, target_url: str) -> float:
        """
        Calculate confidence boost for a finding based on historical data.

        Returns:
          +0.1 if same finding type was seen before at this endpoint
          +0.05 if same finding type was seen before at any endpoint
          0.0 if no history
        """
        previous = self.get_previous_scan(target_url)
        if not previous:
            return 0.0

        prev_findings = previous.get("findings", [])

        # Exact match: same type + same endpoint
        for pf in prev_findings:
            if pf.get("type") == finding_type and pf.get("endpoint") == endpoint:
                return 0.1

        # Type match: same type, different endpoint
        for pf in prev_findings:
            if pf.get("type") == finding_type:
                return 0.05

        return 0.0

    def get_risk_boost(self, endpoint_url: str, target_url: str) -> float:
        """
        Calculate risk score boost based on historical anomalies.

        Returns:
          +1.0 if endpoint had findings in previous scan
          +0.5 if endpoint is new (not seen before)
          0.0 if endpoint existed before with no findings
        """
        previous = self.get_previous_scan(target_url)
        if not previous:
            return 0.0

        prev_endpoints = set(previous.get("endpoints", []))
        prev_findings = previous.get("findings", [])

        # New endpoint — potentially unvetted
        if endpoint_url not in prev_endpoints:
            return 0.5

        # Had findings before — needs extra attention
        for pf in prev_findings:
            if pf.get("endpoint") == endpoint_url:
                return 1.0

        return 0.0

    # ── Persistence ─────────────────────────────────────────

    def _persist_record(self, target_url: str, record: Dict):
        """Store record in database."""
        from backend.models import ScanDB
        # Store as JSON in a lightweight way
        # (In production, this would be a dedicated table)
        db = self._db_factory()
        try:
            # Find latest scan for this target and store history data
            scan = (
                db.query(ScanDB)
                .filter(ScanDB.target_url == target_url)
                .order_by(ScanDB.created_at.desc())
                .first()
            )
            if scan and hasattr(scan, 'knowledge_graph_data'):
                history = scan.knowledge_graph_data or {}
                history["_historical_memory"] = {
                    "endpoint_count": record["endpoint_count"],
                    "finding_types": record["finding_types"],
                    "risk_scores": record["risk_scores"],
                    "timestamp": record["timestamp"],
                }
                scan.knowledge_graph_data = history
                db.commit()
        finally:
            db.close()

    def _load_record(self, target_url: str) -> Optional[Dict]:
        """Load most recent record from database."""
        from backend.models import ScanDB
        db = self._db_factory()
        try:
            scan = (
                db.query(ScanDB)
                .filter(ScanDB.target_url == target_url)
                .filter(ScanDB.status.in_(["completed"]))
                .order_by(ScanDB.created_at.desc())
                .first()
            )
            if scan and hasattr(scan, 'knowledge_graph_data'):
                kg_data = scan.knowledge_graph_data or {}
                return kg_data.get("_historical_memory")
            return None
        finally:
            db.close()
