"""
API RIPPER — Scan Routes
CRUD and execution endpoints for security scans
"""

import logging
from datetime import datetime
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel

from backend.database import get_db, get_database_manager
from backend.models import ScanDB, FindingDB, EndpointDB, ReportDB, ExploitChainDB, ScanTraceDB, ScanStatus

logger = logging.getLogger(__name__)
router = APIRouter()


# ============================================================
# REQUEST / RESPONSE MODELS
# ============================================================

class CreateScanRequest(BaseModel):
    target_url: str
    scan_name: str
    description: Optional[str] = None
    scan_type: Optional[str] = "full"  # full, passive, api_only, quick
    exploit_mode: Optional[str] = "standard"  # standard | full_auth
    auth_config: Optional[dict] = None  # {bearer_token, api_key, cookies}

    class Config:
        json_schema_extra = {
            "example": {
                "target_url": "https://api.example.com",
                "scan_name": "API Security Audit",
                "description": "Comprehensive scan",
                "scan_type": "full",
                "exploit_mode": "standard",
                "auth_config": {"bearer_token": "optional-token-here"},
            }
        }


class ScanResponse(BaseModel):
    id: str
    target_url: str
    scan_name: str
    status: str
    scan_type: str
    endpoints_discovered: int
    vulnerabilities_found: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    progress_percentage: int
    phase_name: str
    created_at: Optional[str] = None
    completed_at: Optional[str] = None


class ProgressResponse(BaseModel):
    scan_id: str
    status: str
    current_phase: int
    total_phases: int
    phase_name: str
    endpoints_discovered: int
    vulnerabilities_found: int
    progress_percentage: int


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def _scan_to_response(scan: ScanDB, db) -> ScanResponse:
    """Convert ScanDB to ScanResponse"""
    finding_count = db.query(FindingDB).filter(FindingDB.scan_id == scan.id).count()
    endpoint_count = db.query(EndpointDB).filter(EndpointDB.scan_id == scan.id).count()

    # Severity counts
    from sqlalchemy import func
    severity_counts = dict(
        db.query(FindingDB.severity, func.count(FindingDB.id))
        .filter(FindingDB.scan_id == scan.id)
        .group_by(FindingDB.severity)
        .all()
    )

    return ScanResponse(
        id=str(scan.id),
        target_url=scan.target_url,
        scan_name=scan.name,
        status=scan.status.value if hasattr(scan.status, 'value') else str(scan.status),
        scan_type=scan.scan_type or "full",
        endpoints_discovered=endpoint_count,
        vulnerabilities_found=finding_count,
        critical_count=severity_counts.get("critical", 0),
        high_count=severity_counts.get("high", 0),
        medium_count=severity_counts.get("medium", 0),
        low_count=severity_counts.get("low", 0),
        progress_percentage=scan.progress_percentage or 0,
        phase_name=scan.phase_name or "Initialization",
        created_at=scan.created_at.isoformat() if scan.created_at else None,
        completed_at=scan.completed_at.isoformat() if scan.completed_at else None,
    )


# ============================================================
# ENDPOINTS
# ============================================================

@router.post("/scans", response_model=ScanResponse)
async def create_scan(request: CreateScanRequest, db=Depends(get_db)):
    """Create a new security scan"""
    try:
        scan = ScanDB(
            id=str(uuid4()),
            target_url=request.target_url,
            name=request.scan_name,
            description=request.description or "",
            scan_type=request.scan_type or "full",
            exploit_mode=request.exploit_mode or "standard",
            auth_config=request.auth_config or {},
            status=ScanStatus.CREATED,
            created_at=datetime.utcnow(),
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        logger.info(f"✓ Scan created: {scan.id} (mode={scan.exploit_mode})")
        return _scan_to_response(scan, db)

    except Exception as e:
        logger.error(f"✗ Failed to create scan: {e}")
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/scans", response_model=list[ScanResponse])
async def list_scans(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db=Depends(get_db),
):
    """List all scans"""
    try:
        scans = db.query(ScanDB).order_by(ScanDB.created_at.desc()).offset(offset).limit(limit).all()
        return [_scan_to_response(s, db) for s in scans]
    except Exception as e:
        logger.error(f"✗ Failed to list scans: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str, db=Depends(get_db)):
    """Get scan details"""
    scan = db.query(ScanDB).filter(ScanDB.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _scan_to_response(scan, db)


@router.post("/scans/{scan_id}/execute")
async def execute_scan(
    scan_id: str,
    background_tasks: BackgroundTasks,
    db=Depends(get_db),
):
    """Start scan execution in background"""
    scan = db.query(ScanDB).filter(ScanDB.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status not in (ScanStatus.CREATED, ScanStatus.FAILED):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot execute scan in {scan.status} state",
        )

    scan.status = ScanStatus.RUNNING
    db.commit()

    target_url = scan.target_url
    scan_name = scan.name
    exploit_mode = getattr(scan, 'exploit_mode', 'standard') or 'standard'
    auth_config = getattr(scan, 'auth_config', {}) or {}

    async def _run():
        from backend.scanner.orchestrator import run_scan
        mgr = get_database_manager()
        await run_scan(
            scan_id, target_url, scan_name, mgr.get_session,
            exploit_mode=exploit_mode,
            auth_config=auth_config,
        )

    background_tasks.add_task(_run)

    return {
        "scan_id": scan_id,
        "status": "running",
        "exploit_mode": exploit_mode,
        "message": f"Scan execution started ({exploit_mode} mode)",
    }


@router.get("/scans/{scan_id}/progress", response_model=ProgressResponse)
async def get_scan_progress(scan_id: str, db=Depends(get_db)):
    """Get real-time scan progress"""
    scan = db.query(ScanDB).filter(ScanDB.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    finding_count = db.query(FindingDB).filter(FindingDB.scan_id == scan_id).count()
    endpoint_count = db.query(EndpointDB).filter(EndpointDB.scan_id == scan_id).count()

    return ProgressResponse(
        scan_id=scan_id,
        status=scan.status.value,
        current_phase=scan.current_phase or 0,
        total_phases=scan.total_phases or 7,
        phase_name=scan.phase_name or "Initialization",
        endpoints_discovered=endpoint_count,
        vulnerabilities_found=finding_count,
        progress_percentage=scan.progress_percentage or 0,
    )


@router.post("/scans/{scan_id}/cancel")
async def cancel_scan(scan_id: str, db=Depends(get_db)):
    """Cancel a running scan"""
    scan = db.query(ScanDB).filter(ScanDB.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status != ScanStatus.RUNNING:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot cancel scan in {scan.status} state",
        )

    scan.status = ScanStatus.CANCELLED
    db.commit()
    return {"status": "cancelled", "message": "Scan cancelled"}


@router.get("/scans/{scan_id}/graph")
async def get_scan_graph(scan_id: str, db=Depends(get_db)):
    """Get knowledge graph data and executable chains for visualization"""
    scan = db.query(ScanDB).filter(ScanDB.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    kg_data = scan.knowledge_graph_data or {}
    
    # Get all findings that are chains
    chains = []
    findings = db.query(FindingDB).filter(
        FindingDB.scan_id == scan_id, 
        FindingDB.category.like("exploit_chain_%")
    ).all()
    
    for f in findings:
        for ev in f.details.get("evidence", []):
            if ev.get("type") == "executable_chain":
                chains.append(ev.get("chain"))
                
    return {
        "endpoints": kg_data.get("endpoints", []),
        "relationships": kg_data.get("relationships", []),
        "chains": chains
    }


@router.delete("/scans/{scan_id}")
async def delete_scan(scan_id: str, db=Depends(get_db)):
    """Delete a scan and all related data"""
    scan = db.query(ScanDB).filter(ScanDB.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    db.query(FindingDB).filter(FindingDB.scan_id == scan_id).delete()
    db.query(EndpointDB).filter(EndpointDB.scan_id == scan_id).delete()
    db.query(ReportDB).filter(ReportDB.scan_id == scan_id).delete()
    db.delete(scan)
    db.commit()

    return {"status": "deleted", "message": "Scan deleted"}


# ============================================================
# STATS ENDPOINT (for Dashboard)
# ============================================================

@router.get("/stats")
async def get_stats(db=Depends(get_db)):
    """Get aggregate stats for the dashboard"""
    from sqlalchemy import func

    total_scans = db.query(ScanDB).count()
    active_scans = db.query(ScanDB).filter(ScanDB.status == ScanStatus.RUNNING).count()
    completed_scans = db.query(ScanDB).filter(ScanDB.status == ScanStatus.COMPLETED).count()
    total_findings = db.query(FindingDB).filter(FindingDB.false_positive == False).count()
    total_endpoints = db.query(EndpointDB).count()

    severity_counts = dict(
        db.query(FindingDB.severity, func.count(FindingDB.id))
        .filter(FindingDB.false_positive == False)
        .group_by(FindingDB.severity)
        .all()
    )

    # Risk score — weighted severity calculation
    weights = {"critical": 40, "high": 20, "medium": 5, "low": 1, "info": 0}
    risk_score = min(100, sum(weights.get(k, 0) * v for k, v in severity_counts.items()))

    # Recent scan trend (last 10 scans)
    recent_scans = (
        db.query(ScanDB)
        .filter(ScanDB.status == ScanStatus.COMPLETED)
        .order_by(ScanDB.completed_at.desc())
        .limit(10)
        .all()
    )
    scan_trend = []
    for s in reversed(recent_scans):
        finding_count = db.query(FindingDB).filter(FindingDB.scan_id == s.id, FindingDB.false_positive == False).count()
        scan_trend.append({
            "scan_id": s.id,
            "name": s.name,
            "date": s.completed_at.isoformat() if s.completed_at else "",
            "findings": finding_count,
            "duration": s.scan_duration_seconds,
        })

    # OWASP coverage — count findings mapped to each category
    owasp_keywords = {
        "API1": ["bola", "idor"],
        "API2": ["auth", "bypass", "jwt", "session", "token"],
        "API3": ["exposure", "sensitive", "leak", "data"],
        "API4": ["rate", "limit", "dos", "throttl", "resource"],
        "API5": ["verb", "function", "method", "role"],
        "API6": ["mass", "assignment"],
        "API7": ["misconfig", "header", "cors", "ssl", "tls", "csp", "hsts"],
        "API8": ["xss", "injection", "sqli", "smuggl", "ssrf", "ssti"],
        "API9": ["version", "deprecat", "asset"],
        "API10": ["log", "monitor"],
    }
    all_findings = db.query(FindingDB).filter(FindingDB.false_positive == False).all()
    owasp_coverage = {}
    for cat_key, keywords in owasp_keywords.items():
        count = 0
        for f in all_findings:
            title_lower = (f.title or "").lower()
            if any(kw in title_lower for kw in keywords):
                count += 1
        owasp_coverage[cat_key] = count

    # v3.0: Modern vulnerability class breakdown
    vuln_class_counts = {}
    for f in all_findings:
        vc = f.vulnerability_class or _infer_vuln_class(f.title, f.category)
        if vc:
            vuln_class_counts[vc] = vuln_class_counts.get(vc, 0) + 1

    # Modern attack coverage (how many classes tested)
    modern_attack_classes = [
        "JWT", "BOLA/IDOR", "BFLA", "Mass Assignment", "Race Condition",
        "Prototype Pollution", "CORS", "Deserialization", "SSRF", "XXE",
        "File Upload", "WebSocket", "GraphQL", "Request Smuggling",
        "CRLF Injection", "Parameter Pollution", "LLM/AI", "Hidden APIs",
    ]
    classes_with_findings = sum(1 for c in modern_attack_classes if vuln_class_counts.get(c, 0) > 0)

    return {
        "total_scans": total_scans,
        "active_scans": active_scans,
        "completed_scans": completed_scans,
        "total_findings": total_findings,
        "total_endpoints": total_endpoints,
        "severity_breakdown": severity_counts,
        "risk_score": risk_score,
        "scan_trend": scan_trend,
        "owasp_coverage": owasp_coverage,
        "vulnerability_classes": vuln_class_counts,
        "modern_attack_coverage": {
            "total_classes": len(modern_attack_classes),
            "classes_tested": classes_with_findings,
            "coverage_percent": round(classes_with_findings / len(modern_attack_classes) * 100, 1),
            "classes": modern_attack_classes,
        },
    }


def _infer_vuln_class(title: str, category: str) -> str:
    """Infer vulnerability class from title/category for legacy findings."""
    t = (title or "").lower()
    c = (category or "").lower()
    combined = f"{t} {c}"
    mapping = {
        "JWT": ["jwt", "token", "alg:none", "hmac"],
        "BOLA/IDOR": ["bola", "idor", "object level"],
        "BFLA": ["bfla", "function level"],
        "Mass Assignment": ["mass assignment"],
        "Race Condition": ["race condition", "concurrent"],
        "Prototype Pollution": ["prototype pollution", "__proto__"],
        "CORS": ["cors"],
        "Deserialization": ["deserialization", "deserialize"],
        "SSRF": ["ssrf", "server-side request"],
        "XXE": ["xxe", "xml external"],
        "File Upload": ["file upload", "extension bypass"],
        "WebSocket": ["websocket", "ws://"],
        "GraphQL": ["graphql"],
        "Request Smuggling": ["smuggling"],
        "CRLF Injection": ["crlf"],
        "Parameter Pollution": ["parameter pollution", "hpp"],
        "LLM/AI": ["llm", "prompt injection", "ai"],
        "Hidden APIs": ["hidden api", "internal api"],
        "SQL Injection": ["sqli", "sql injection"],
        "XSS": ["xss", "cross-site scripting"],
        "Authentication": ["auth bypass", "authentication"],
    }
    for cls, keywords in mapping.items():
        if any(kw in combined for kw in keywords):
            return cls
    return "Other"


# ============================================================
# RESCAN ENDPOINT
# ============================================================

@router.post("/scans/{scan_id}/rescan")
async def rescan(
    scan_id: str,
    background_tasks: BackgroundTasks,
    db=Depends(get_db),
):
    """Re-run a scan with the same configuration (for regression testing)"""
    original = db.query(ScanDB).filter(ScanDB.id == scan_id).first()
    if not original:
        raise HTTPException(status_code=404, detail="Original scan not found")

    # Create a new scan cloned from original
    new_scan = ScanDB(
        id=str(uuid4()),
        target_url=original.target_url,
        name=f"{original.name} (rescan)",
        description=f"Rescan of {scan_id}",
        scan_type=original.scan_type or "full",
        status=ScanStatus.RUNNING,
        created_at=datetime.utcnow(),
        started_at=datetime.utcnow(),
        tags=original.tags or [],
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    new_id = new_scan.id
    target = new_scan.target_url
    name = new_scan.name

    async def _run():
        from backend.scanner.orchestrator import run_scan
        from backend.database import get_database_manager
        mgr = get_database_manager()
        await run_scan(new_id, target, name, mgr.get_session)

    background_tasks.add_task(_run)

    return {
        "original_scan_id": scan_id,
        "new_scan_id": new_id,
        "status": "running",
        "message": "Rescan started in background",
    }


# ============================================================
# FALSE POSITIVE TOGGLE
# ============================================================

@router.patch("/findings/{finding_id}/false-positive")
async def toggle_false_positive(finding_id: str, db=Depends(get_db)):
    """Toggle false positive status for a finding"""
    finding = db.query(FindingDB).filter(FindingDB.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.false_positive = not finding.false_positive
    db.commit()

    return {
        "finding_id": finding_id,
        "false_positive": finding.false_positive,
        "message": f"Finding {'marked' if finding.false_positive else 'unmarked'} as false positive",
    }


# ============================================================
# SCAN TAGS
# ============================================================

@router.put("/scans/{scan_id}/tags")
async def update_tags(scan_id: str, tags: list[str], db=Depends(get_db)):
    """Update tags for a scan"""
    scan = db.query(ScanDB).filter(ScanDB.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan.tags = tags
    db.commit()
    return {"scan_id": scan_id, "tags": tags}
