"""
API RIPPER — Scan Comparison Routes
Compare two scan results side-by-side to track vulnerability changes over time.
"""

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from backend.database import get_db
from backend.models import ScanDB, FindingDB, EndpointDB

logger = logging.getLogger(__name__)
router = APIRouter()


# ── Response Models ──────────────────────────────────────────────────

class FindingDiff(BaseModel):
    id: str
    title: str
    severity: str
    category: str
    module_name: str
    endpoint_url: Optional[str] = None
    description: Optional[str] = None


class ComparisonResult(BaseModel):
    scan_a_id: str
    scan_a_name: str
    scan_a_target: str
    scan_b_id: str
    scan_b_name: str
    scan_b_target: str
    new_findings: List[FindingDiff]        # In B but not in A (new)
    fixed_findings: List[FindingDiff]      # In A but not in B (fixed)
    persistent_findings: List[FindingDiff]  # In both A and B
    summary: dict


class EndpointDiff(BaseModel):
    url: str
    method: str
    status: str  # "new", "removed", "unchanged"


# ── Helpers ──────────────────────────────────────────────────────────

def _sev(f):
    return f.severity.value if hasattr(f.severity, "value") else str(f.severity)


def _finding_signature(f: FindingDB) -> str:
    """Create a unique signature for a finding to match across scans."""
    return f"{f.title}|{_sev(f)}|{f.category}|{f.module_name}|{f.endpoint_url or ''}"


def _to_diff(f: FindingDB) -> FindingDiff:
    return FindingDiff(
        id=str(f.id),
        title=f.title,
        severity=_sev(f).upper(),
        category=f.category,
        module_name=f.module_name,
        endpoint_url=f.endpoint_url,
        description=(f.description or "")[:200],
    )


# ── Endpoints ────────────────────────────────────────────────────────

@router.get("/scans/compare", response_model=ComparisonResult)
async def compare_scans(
    scan_a: str = Query(..., description="ID of the baseline scan"),
    scan_b: str = Query(..., description="ID of the comparison scan"),
    db=Depends(get_db),
):
    """Compare two scan results and show new, fixed, and persistent findings."""

    # Fetch scans
    a = db.query(ScanDB).filter(ScanDB.id == scan_a).first()
    b = db.query(ScanDB).filter(ScanDB.id == scan_b).first()

    if not a:
        raise HTTPException(status_code=404, detail=f"Scan A ({scan_a}) not found")
    if not b:
        raise HTTPException(status_code=404, detail=f"Scan B ({scan_b}) not found")

    # Fetch findings
    findings_a = db.query(FindingDB).filter(FindingDB.scan_id == scan_a).all()
    findings_b = db.query(FindingDB).filter(FindingDB.scan_id == scan_b).all()

    # Build signature maps
    sigs_a = {_finding_signature(f): f for f in findings_a}
    sigs_b = {_finding_signature(f): f for f in findings_b}

    set_a = set(sigs_a.keys())
    set_b = set(sigs_b.keys())

    # Calculate diffs
    new_sigs = set_b - set_a         # In B but not in A
    fixed_sigs = set_a - set_b       # In A but not in B
    persistent_sigs = set_a & set_b  # In both

    new_findings = [_to_diff(sigs_b[s]) for s in new_sigs]
    fixed_findings = [_to_diff(sigs_a[s]) for s in fixed_sigs]
    persistent_findings = [_to_diff(sigs_b[s]) for s in persistent_sigs]

    # Sort by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    for lst in [new_findings, fixed_findings, persistent_findings]:
        lst.sort(key=lambda f: sev_order.get(f.severity, 99))

    # Severity breakdown for new findings
    new_sev = {}
    for f in new_findings:
        new_sev[f.severity] = new_sev.get(f.severity, 0) + 1

    fixed_sev = {}
    for f in fixed_findings:
        fixed_sev[f.severity] = fixed_sev.get(f.severity, 0) + 1

    return ComparisonResult(
        scan_a_id=scan_a,
        scan_a_name=a.name,
        scan_a_target=a.target_url,
        scan_b_id=scan_b,
        scan_b_name=b.name,
        scan_b_target=b.target_url,
        new_findings=new_findings,
        fixed_findings=fixed_findings,
        persistent_findings=persistent_findings,
        summary={
            "total_new": len(new_findings),
            "total_fixed": len(fixed_findings),
            "total_persistent": len(persistent_findings),
            "scan_a_total": len(findings_a),
            "scan_b_total": len(findings_b),
            "new_by_severity": new_sev,
            "fixed_by_severity": fixed_sev,
            "improvement_score": round(
                (len(fixed_findings) / max(len(findings_a), 1)) * 100, 1
            ),
        },
    )


@router.get("/scans/compare/endpoints")
async def compare_endpoints(
    scan_a: str = Query(...),
    scan_b: str = Query(...),
    db=Depends(get_db),
):
    """Compare discovered endpoints between two scans."""
    endpoints_a = db.query(EndpointDB).filter(EndpointDB.scan_id == scan_a).all()
    endpoints_b = db.query(EndpointDB).filter(EndpointDB.scan_id == scan_b).all()

    # Build URL+method sets
    set_a = {f"{e.method}|{e.url}" for e in endpoints_a}
    set_b = {f"{e.method}|{e.url}" for e in endpoints_b}

    new_eps = set_b - set_a
    removed_eps = set_a - set_b
    unchanged_eps = set_a & set_b

    def _parse(sig: str, status: str) -> dict:
        parts = sig.split("|", 1)
        return {"method": parts[0], "url": parts[1] if len(parts) > 1 else "", "status": status}

    return {
        "new_endpoints": [_parse(s, "new") for s in sorted(new_eps)],
        "removed_endpoints": [_parse(s, "removed") for s in sorted(removed_eps)],
        "unchanged_endpoints": [_parse(s, "unchanged") for s in sorted(unchanged_eps)],
        "summary": {
            "scan_a_total": len(endpoints_a),
            "scan_b_total": len(endpoints_b),
            "new_count": len(new_eps),
            "removed_count": len(removed_eps),
            "unchanged_count": len(unchanged_eps),
        },
    }
