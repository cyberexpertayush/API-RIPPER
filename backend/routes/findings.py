"""
API RIPPER — Finding & Endpoint Routes
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from backend.database import get_db
from backend.models import FindingDB, EndpointDB, ScanDB

logger = logging.getLogger(__name__)
router = APIRouter()


# ============================================================
# RESPONSE MODELS
# ============================================================

class FindingResponse(BaseModel):
    id: str
    scan_id: str
    category: str
    module_name: str
    severity: str
    title: str
    description: str
    endpoint_url: str
    method: str
    details: dict
    remediation: str
    evidence: list = []
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    discovered_at: Optional[str] = None


class EndpointResponse(BaseModel):
    id: str
    url: str
    path: str
    method: str
    status_code: int
    requires_auth: bool


# ============================================================
# FINDING ENDPOINTS
# ============================================================

@router.get("/scans/{scan_id}/findings", response_model=list[FindingResponse])
async def get_findings(
    scan_id: str,
    severity: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db=Depends(get_db),
):
    """Get findings for a scan with optional severity/category filters"""
    scan = db.query(ScanDB).filter(ScanDB.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    query = db.query(FindingDB).filter(FindingDB.scan_id == scan_id)

    if severity:
        query = query.filter(FindingDB.severity == severity)
    if category:
        query = query.filter(FindingDB.category == category)

    findings = query.offset(offset).limit(limit).all()

    return [
        FindingResponse(
            id=f.id,
            scan_id=f.scan_id,
            category=f.category,
            module_name=f.module_name,
            severity=f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
            title=f.title,
            description=f.description or "",
            endpoint_url=f.endpoint_url or "",
            method=f.method or "GET",
            details=f.details or {},
            remediation=f.remediation or "",
            evidence=f.evidence or [],
            cwe_id=f.cwe_id,
            cvss_score=f.cvss_score,
            discovered_at=f.discovered_at.isoformat() if f.discovered_at else None,
        )
        for f in findings
    ]


@router.get("/findings")
async def get_all_findings(
    severity: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db=Depends(get_db),
):
    """Get all findings across all scans"""
    query = db.query(FindingDB)
    if severity:
        query = query.filter(FindingDB.severity == severity)
    findings = query.order_by(FindingDB.discovered_at.desc()).offset(offset).limit(limit).all()

    return [
        {
            "id": f.id,
            "scan_id": f.scan_id,
            "category": f.category,
            "module_name": f.module_name,
            "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
            "title": f.title,
            "description": f.description or "",
            "endpoint_url": f.endpoint_url or "",
            "method": f.method or "GET",
            "evidence": f.evidence or [],
            "cwe_id": f.cwe_id,
            "cvss_score": f.cvss_score,
        }
        for f in findings
    ]


# ============================================================
# ENDPOINT ROUTES
# ============================================================

@router.get("/scans/{scan_id}/endpoints", response_model=list[EndpointResponse])
async def get_endpoints(
    scan_id: str,
    limit: int = Query(500, ge=1, le=2000),
    offset: int = Query(0, ge=0),
    db=Depends(get_db),
):
    """Get discovered endpoints for a scan"""
    scan = db.query(ScanDB).filter(ScanDB.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    endpoints = (
        db.query(EndpointDB)
        .filter(EndpointDB.scan_id == scan_id)
        .offset(offset)
        .limit(limit)
        .all()
    )

    return [
        EndpointResponse(
            id=ep.id,
            url=ep.url,
            path=ep.path,
            method=ep.method,
            status_code=ep.status_code,
            requires_auth=ep.requires_auth,
        )
        for ep in endpoints
    ]


@router.get("/endpoints")
async def get_all_endpoints(
    limit: int = Query(500, ge=1, le=2000),
    offset: int = Query(0, ge=0),
    db=Depends(get_db),
):
    """Get all endpoints across all scans"""
    endpoints = db.query(EndpointDB).offset(offset).limit(limit).all()
    return [
        {
            "id": ep.id,
            "scan_id": ep.scan_id,
            "url": ep.url,
            "path": ep.path,
            "method": ep.method,
            "status_code": ep.status_code,
            "requires_auth": ep.requires_auth,
        }
        for ep in endpoints
    ]
