"""
API RIPPER — Report Routes
Generates comprehensive security reports in JSON, HTML, CSV, and Markdown formats.
"""

import csv
import io
import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from backend.database import get_db
from backend.models import ReportDB, ScanDB, FindingDB, EndpointDB

logger = logging.getLogger(__name__)
router = APIRouter()


# ── helpers ──────────────────────────────────────────────────────────

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#2563eb",
    "info": "#6b7280",
}


def _sev(f):
    """Extract severity string from a FindingDB row."""
    return f.severity.value if hasattr(f.severity, "value") else str(f.severity)


def _risk_rating(report):
    if report.critical_count > 0:
        return "CRITICAL"
    if report.high_count > 0:
        return "HIGH"
    if report.medium_count > 0:
        return "MEDIUM"
    if report.low_count > 0:
        return "LOW"
    return "CLEAN"


def _sorted_findings(db, scan_id):
    findings = db.query(FindingDB).filter(FindingDB.scan_id == scan_id).all()
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(_sev(f), 99))


# ── JSON report (executive summary) ─────────────────────────────────

@router.get("/scans/{scan_id}/report")
async def get_report(
    scan_id: str,
    format: str = Query("json"),
    db=Depends(get_db),
):
    """Get scan report in the requested format."""
    report = db.query(ReportDB).filter(ReportDB.scan_id == scan_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found. Complete a scan first.")

    scan = db.query(ScanDB).filter(ScanDB.id == scan_id).first()
    target = scan.target_url if scan else "Unknown"
    findings = _sorted_findings(db, scan_id)

    if format == "json":
        return _json_report(report, target, findings)
    elif format == "csv":
        return _csv_report(findings, target)
    elif format == "markdown":
        return _markdown_report(report, target, findings)
    elif format == "html":
        return _html_report(report, target, findings)

    return {"error": "Unknown format"}


def _json_report(report, target, findings):
    risk = _risk_rating(report)
    key_findings = []
    for rank, f in enumerate(findings, 1):
        sev = _sev(f)
        # Professional Pentest Export: Includes Evidence Chain and Multi-dimensional Signals
        key_findings.append({
            "rank": rank,
            "title": f.title,
            "severity": sev.upper(),
            "summary": f.description if f.description else "",
            "category": f.category,
            "endpoint": f.endpoint_url or "",
            "cwe": f.cwe_id or "",
            "cvss": f.cvss_score or "",
            "confidence": getattr(f, 'confidence', None),
            "evidence_chain": getattr(f, 'evidence', []) or []
        })

    recommendations = []
    for f in findings:
        if f.remediation:
            recommendations.append(f.remediation)
    # deduplicate while preserving order
    seen = set()
    deduped = []
    for r in recommendations:
        if r not in seen:
            seen.add(r)
            deduped.append(r)

    return {
        "scan_id": report.scan_id,
        "title": report.title,
        "assessment_title": report.title,
        "target": target,
        "report_date": report.created_at.isoformat() if report.created_at else "",
        "executive_summary": report.executive_summary,
        "risk_rating": risk,
        "findings_summary": {
            "total": report.total_findings,
            "critical": report.critical_count,
            "high": report.high_count,
            "medium": report.medium_count,
            "low": report.low_count,
            "info": report.info_count,
        },
        "key_findings": key_findings,
        "recommendations": deduped[:15],
        "report_data": report.report_data or {},
    }


# ── CSV ──────────────────────────────────────────────────────────────

def _csv_report(findings, target):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Severity", "Title", "Category", "Module", "Endpoint",
        "Method", "Description", "Remediation", "CWE", "CVSS",
    ])
    for f in findings:
        writer.writerow([
            _sev(f).upper(),
            f.title,
            f.category,
            f.module_name,
            f.endpoint_url or "",
            f.method or "",
            (f.description or "").replace("\n", " "),
            (f.remediation or "").replace("\n", " "),
            f.cwe_id or "",
            f.cvss_score or "",
        ])
    return output.getvalue()


# ── Markdown ─────────────────────────────────────────────────────────

def _markdown_report(report, target, findings):
    risk = _risk_rating(report)
    md = f"# {report.title}\n\n"
    md += f"**Target:** {target}  \n"
    md += f"**Date:** {report.created_at.isoformat() if report.created_at else 'N/A'}  \n"
    md += f"**Risk Rating:** {risk}\n\n"
    md += f"## Executive Summary\n\n{report.executive_summary}\n\n"
    md += "## Findings Summary\n\n"
    md += f"| Severity | Count |\n|----------|-------|\n"
    md += f"| Critical | {report.critical_count} |\n"
    md += f"| High | {report.high_count} |\n"
    md += f"| Medium | {report.medium_count} |\n"
    md += f"| Low | {report.low_count} |\n"
    md += f"| Info | {report.info_count} |\n\n"

    md += "## Detailed Findings\n\n"
    for i, f in enumerate(findings, 1):
        sev = _sev(f)
        md += f"### {i}. [{sev.upper()}] {f.title}\n\n"
        md += f"- **Category:** {f.category}\n"
        md += f"- **Module:** {f.module_name}\n"
        if f.endpoint_url:
            md += f"- **Endpoint:** `{f.endpoint_url}`\n"
        if f.cwe_id:
            md += f"- **CWE:** {f.cwe_id}\n"
        if f.cvss_score:
            md += f"- **CVSS:** {f.cvss_score}\n"
        if getattr(f, 'confidence', None) is not None:
            md += f"- **Confidence:** {f.confidence * 100:.0f}%\n"
        
        md += f"\n{f.description or 'No description.'}\n\n"
        
        # Add Evidence Chain
        evidence = getattr(f, 'evidence', [])
        if evidence:
            md += "#### Evidence Chain (VDASE Validated)\n"
            for idx, ev in enumerate(evidence, 1):
                md += f"**Step {idx}:** `{ev.get('technique', ev.get('signal_type', 'Validation Signal'))}`\n"
                md += "```json\n"
                import json
                md += json.dumps(ev, indent=2) + "\n"
                md += "```\n\n"

        if f.remediation:
            md += f"**Remediation:** {f.remediation}\n\n"
        md += "---\n\n"

    return {"markdown": md}


# ── HTML — full professional report ─────────────────────────────────

def _html_report(report, target, findings):
    risk = _risk_rating(report)

    # Group findings by severity
    by_sev = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
    for f in findings:
        sev = _sev(f)
        by_sev.setdefault(sev, []).append(f)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{report.title}</title>
<style>
  :root {{
    --bg: #0f172a; --surface: #1e293b; --surface2: #334155;
    --text: #f1f5f9; --text2: #94a3b8; --text3: #64748b;
    --accent: #38bdf8; --border: #334155;
    --critical: #dc2626; --high: #ea580c; --medium: #d97706;
    --low: #2563eb; --info: #6b7280;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: 'Segoe UI', -apple-system, sans-serif;
    background: var(--bg); color: var(--text);
    line-height: 1.6; padding: 0; margin: 0;
  }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 40px 24px; }}
  .header {{
    text-align: center; padding: 48px 0; margin-bottom: 40px;
    background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
    border-bottom: 2px solid var(--accent);
  }}
  .header h1 {{ font-size: 2rem; font-weight: 700; color: var(--accent); margin-bottom: 8px; }}
  .header .subtitle {{ color: var(--text2); font-size: 1rem; }}
  .meta-grid {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px; margin: 32px 0;
  }}
  .meta-card {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; padding: 16px;
  }}
  .meta-card .label {{ color: var(--text3); font-size: 0.75rem; text-transform: uppercase; letter-spacing: .5px; }}
  .meta-card .value {{ font-size: 1.1rem; font-weight: 600; margin-top: 4px; }}
  .severity-grid {{
    display: grid; grid-template-columns: repeat(5, 1fr);
    gap: 12px; margin: 32px 0;
  }}
  .sev-card {{
    text-align: center; padding: 20px 12px;
    background: var(--surface); border-radius: 8px;
    border-top: 3px solid var(--border);
  }}
  .sev-card .sev-count {{ font-size: 2rem; font-weight: 800; }}
  .sev-card .sev-label {{ font-size: 0.75rem; text-transform: uppercase; color: var(--text3); margin-top: 4px; }}
  .sev-critical {{ border-top-color: var(--critical); }}
  .sev-critical .sev-count {{ color: var(--critical); }}
  .sev-high {{ border-top-color: var(--high); }}
  .sev-high .sev-count {{ color: var(--high); }}
  .sev-medium {{ border-top-color: var(--medium); }}
  .sev-medium .sev-count {{ color: var(--medium); }}
  .sev-low {{ border-top-color: var(--low); }}
  .sev-low .sev-count {{ color: var(--low); }}
  .sev-info {{ border-top-color: var(--info); }}
  .sev-info .sev-count {{ color: var(--info); }}
  .section {{ margin: 40px 0; }}
  .section h2 {{
    font-size: 1.3rem; font-weight: 700; margin-bottom: 16px;
    padding-bottom: 8px; border-bottom: 1px solid var(--border);
    color: var(--accent);
  }}
  .summary-text {{ color: var(--text2); font-size: 0.95rem; line-height: 1.8; }}
  .risk-badge {{
    display: inline-block; padding: 4px 16px; border-radius: 4px;
    font-weight: 700; font-size: 0.85rem; letter-spacing: .5px;
  }}
  .risk-CRITICAL {{ background: var(--critical); color: #fff; }}
  .risk-HIGH {{ background: var(--high); color: #fff; }}
  .risk-MEDIUM {{ background: var(--medium); color: #fff; }}
  .risk-LOW {{ background: var(--low); color: #fff; }}
  .risk-CLEAN {{ background: #16a34a; color: #fff; }}
  .finding {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; margin-bottom: 16px; overflow: hidden;
  }}
  .finding-header {{
    display: flex; align-items: center; gap: 12px;
    padding: 16px 20px; border-bottom: 1px solid var(--border);
  }}
  .finding-sev {{
    padding: 3px 10px; border-radius: 4px; font-size: 0.7rem;
    font-weight: 700; text-transform: uppercase; letter-spacing: .5px;
    color: #fff; flex-shrink: 0;
  }}
  .finding-title {{ font-weight: 600; font-size: 1rem; }}
  .finding-body {{ padding: 16px 20px; }}
  .finding-meta {{
    display: flex; flex-wrap: wrap; gap: 16px;
    font-size: 0.85rem; color: var(--text3); margin-bottom: 12px;
  }}
  .finding-meta span {{ display: flex; align-items: center; gap: 4px; }}
  .finding-desc {{ color: var(--text2); font-size: 0.9rem; margin-bottom: 12px; line-height: 1.7; }}
  .finding-remediation {{
    background: var(--surface2); border-radius: 6px;
    padding: 12px 16px; font-size: 0.85rem; color: var(--text);
    border-left: 3px solid var(--accent);
  }}
  .finding-remediation strong {{ color: var(--accent); }}
  table {{ width: 100%; border-collapse: collapse; margin: 8px 0; }}
  table th, table td {{
    text-align: left; padding: 10px 14px;
    border-bottom: 1px solid var(--border); font-size: 0.85rem;
  }}
  table th {{ color: var(--text3); font-weight: 600; text-transform: uppercase; font-size: 0.7rem; letter-spacing: .5px; }}
  table td {{ color: var(--text2); }}
  .footer {{
    text-align: center; padding: 32px 0; margin-top: 48px;
    border-top: 1px solid var(--border); color: var(--text3); font-size: 0.8rem;
  }}
  @media print {{
    body {{ background: #fff; color: #111; }}
    .container {{ max-width: 100%; padding: 0; }}
    .finding {{ break-inside: avoid; }}
  }}
</style>
</head>
<body>

<div class="header">
  <h1>API RIPPER — Security Assessment Report</h1>
  <div class="subtitle">{report.title}</div>
</div>

<div class="container">

  <!-- Meta -->
  <div class="meta-grid">
    <div class="meta-card">
      <div class="label">Target</div>
      <div class="value">{target}</div>
    </div>
    <div class="meta-card">
      <div class="label">Date</div>
      <div class="value">{report.created_at.strftime('%Y-%m-%d %H:%M') if report.created_at else 'N/A'}</div>
    </div>
    <div class="meta-card">
      <div class="label">Total Findings</div>
      <div class="value">{report.total_findings}</div>
    </div>
    <div class="meta-card">
      <div class="label">Risk Rating</div>
      <div class="value"><span class="risk-badge risk-{risk}">{risk}</span></div>
    </div>
  </div>

  <!-- Severity Breakdown -->
  <div class="severity-grid">
    <div class="sev-card sev-critical"><div class="sev-count">{report.critical_count}</div><div class="sev-label">Critical</div></div>
    <div class="sev-card sev-high"><div class="sev-count">{report.high_count}</div><div class="sev-label">High</div></div>
    <div class="sev-card sev-medium"><div class="sev-count">{report.medium_count}</div><div class="sev-label">Medium</div></div>
    <div class="sev-card sev-low"><div class="sev-count">{report.low_count}</div><div class="sev-label">Low</div></div>
    <div class="sev-card sev-info"><div class="sev-count">{report.info_count}</div><div class="sev-label">Info</div></div>
  </div>

  <!-- Executive Summary -->
  <div class="section">
    <h2>Executive Summary</h2>
    <p class="summary-text">{report.executive_summary}</p>
  </div>

  <!-- Detailed Findings -->
  <div class="section">
    <h2>Detailed Findings ({len(findings)})</h2>
"""

    for i, f in enumerate(findings, 1):
        sev = _sev(f)
        color = SEVERITY_COLORS.get(sev, "#6b7280")
        desc = (f.description or "No additional details.").replace("\n", "<br>")
        endpoint_html = f'<span>📍 {f.endpoint_url}</span>' if f.endpoint_url else ""
        cwe_html = f'<span>🛡️ {f.cwe_id}</span>' if f.cwe_id else ""
        cvss_html = f'<span>📊 CVSS {f.cvss_score}</span>' if f.cvss_score else ""
        conf_html = f'<span>🎯 Conf: {getattr(f, "confidence", 0) * 100:.0f}%</span>' if getattr(f, "confidence", None) is not None else ""

        remediation_html = ""
        if f.remediation:
            remediation_html = f"""
        <div class="finding-remediation" style="margin-top: 16px;">
          <strong>Remediation:</strong> {f.remediation.replace(chr(10), '<br>')}
        </div>"""

        evidence = getattr(f, 'evidence', [])
        evidence_html = ""
        if evidence:
            import json
            evidence_html = '<div style="margin-top: 16px;"><strong>Evidence Chain (VDASE):</strong><div style="display: flex; gap: 8px; flex-wrap: wrap; margin-top: 8px;">'
            for idx, ev in enumerate(evidence, 1):
                sig_type = ev.get('signal_type', ev.get('technique', 'signal')).replace('_', ' ').upper()
                evidence_html += f'<span style="background: var(--surface2); padding: 4px 8px; border-radius: 4px; font-size: 0.8rem;">{idx}. {sig_type}</span>'
            evidence_html += '</div></div>'

        html += f"""
    <div class="finding">
      <div class="finding-header">
        <span class="finding-sev" style="background:{color}">{sev.upper()}</span>
        <span class="finding-title">{i}. {f.title}</span>
      </div>
      <div class="finding-body">
        <div class="finding-meta">
          <span>📂 {f.category}</span>
          <span>🔧 {f.module_name}</span>
          {endpoint_html}
          {cwe_html}
          {cvss_html}
          {conf_html}
        </div>
        <div class="finding-desc">{desc}</div>
        {evidence_html}
        {remediation_html}
      </div>
    </div>
"""

    # Endpoints table
    html += """
  </div>
"""

    html += """
  <div class="footer">
    Generated by API RIPPER — Advanced API Security Scanner<br>
    Report generated at """ + datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC") + """
  </div>

</div>
</body>
</html>"""

    return {"html": html}


# ── Compliance ───────────────────────────────────────────────────────

@router.get("/scans/{scan_id}/compliance")
async def get_compliance(scan_id: str, db=Depends(get_db)):
    """Get compliance mapping for a scan."""
    report = db.query(ReportDB).filter(ReportDB.scan_id == scan_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    findings = db.query(FindingDB).filter(FindingDB.scan_id == scan_id).all()

    owasp_mapping = {
        "API1 - BOLA": {"count": 0, "findings": []},
        "API2 - Broken Auth": {"count": 0, "findings": []},
        "API3 - Excessive Data Exposure": {"count": 0, "findings": []},
        "API4 - Lack of Resources": {"count": 0, "findings": []},
        "API5 - Broken Function Auth": {"count": 0, "findings": []},
        "API6 - Mass Assignment": {"count": 0, "findings": []},
        "API7 - Security Misconfiguration": {"count": 0, "findings": []},
        "API8 - Injection": {"count": 0, "findings": []},
        "API9 - Improper Asset Mgmt": {"count": 0, "findings": []},
        "API10 - Insufficient Logging": {"count": 0, "findings": []},
    }

    for f in findings:
        title = (f.title or "").lower()
        cat = (f.category or "").lower()

        mapped = False
        if "bola" in title or "idor" in title:
            owasp_mapping["API1 - BOLA"]["count"] += 1
            mapped = True
        if "auth" in title or "bypass" in title or "session" in cat:
            owasp_mapping["API2 - Broken Auth"]["count"] += 1
            mapped = True
        if "exposure" in title or "sensitive" in title or "leak" in title:
            owasp_mapping["API3 - Excessive Data Exposure"]["count"] += 1
            mapped = True
        if "rate" in title or "limit" in title or "dos" in title or "throttl" in title:
            owasp_mapping["API4 - Lack of Resources"]["count"] += 1
            mapped = True
        if "verb" in title or "function" in title or "method" in title:
            owasp_mapping["API5 - Broken Function Auth"]["count"] += 1
            mapped = True
        if "mass" in title or "assignment" in title:
            owasp_mapping["API6 - Mass Assignment"]["count"] += 1
            mapped = True
        if "misconfig" in title or "header" in title or "cors" in title or "ssl" in cat or "tls" in title:
            owasp_mapping["API7 - Security Misconfiguration"]["count"] += 1
            mapped = True
        if "xss" in title or "injection" in title or "sqli" in title or "smuggl" in title:
            owasp_mapping["API8 - Injection"]["count"] += 1
            mapped = True
        if not mapped:
            owasp_mapping["API7 - Security Misconfiguration"]["count"] += 1

    total_issues = sum(v["count"] for v in owasp_mapping.values())

    formatted = {}
    for name, data in owasp_mapping.items():
        c = data["count"]
        if c == 0:
            status = "compliant"
            action = "No issues found"
        elif c <= 2:
            status = "partial"
            action = f"{c} issue(s) require attention"
        else:
            status = "non_compliant"
            action = f"{c} issue(s) require immediate action"

        formatted[name] = {
            "status": status,
            "findings": f"{c} finding(s) mapped",
            "action_required": action,
        }

    return {
        "scan_id": scan_id,
        "compliance_frameworks": formatted,
    }


# ── Remediation Roadmap ──────────────────────────────────────────────

@router.get("/scans/{scan_id}/remediation")
async def get_remediation(scan_id: str, db=Depends(get_db)):
    """Get remediation roadmap for a scan."""
    findings = _sorted_findings(db, scan_id)
    if not findings:
        raise HTTPException(status_code=404, detail="No findings found")

    roadmap = []
    for f in findings:
        sev = _sev(f)
        roadmap.append({
            "priority": sev.upper(),
            "title": f.title,
            "category": f.category,
            "remediation": f.remediation or "Review and fix the identified vulnerability.",
            "module": f.module_name,
            "endpoint": f.endpoint_url or "",
        })

    return {
        "scan_id": scan_id,
        "total_items": len(roadmap),
        "roadmap": roadmap,
    }


# ── Agent Framework Endpoints ────────────────────────────────────────

@router.get("/scans/{scan_id}/exploit-chains")
async def get_exploit_chains(scan_id: str, db=Depends(get_db)):
    """Get exploit chains constructed by the Chain Agent."""
    from backend.models import ExploitChainDB
    chains = db.query(ExploitChainDB).filter(ExploitChainDB.scan_id == scan_id).all()
    return {
        "scan_id": scan_id,
        "total_chains": len(chains),
        "chains": [
            {
                "id": c.id,
                "name": c.name,
                "description": c.description,
                "chain_type": c.chain_type,
                "total_confidence": c.total_confidence,
                "impact": c.impact,
                "complexity": c.complexity,
                "steps": c.steps or [],
                "finding_ids": c.finding_ids or [],
                "created_at": c.created_at.isoformat() if c.created_at else "",
            }
            for c in chains
        ],
    }


@router.get("/scans/{scan_id}/agent-traces")
async def get_agent_traces(scan_id: str, limit: int = 100, db=Depends(get_db)):
    """Get execution trace entries for debugging and audit."""
    from backend.models import ScanTraceDB
    traces = (
        db.query(ScanTraceDB)
        .filter(ScanTraceDB.scan_id == scan_id)
        .order_by(ScanTraceDB.timestamp.desc())
        .limit(limit)
        .all()
    )
    return {
        "scan_id": scan_id,
        "total_traces": len(traces),
        "traces": [
            {
                "id": t.id,
                "agent": t.agent,
                "action": t.action,
                "input_data": t.input_data or {},
                "output_data": t.output_data or {},
                "signals_emitted": t.signals_emitted or [],
                "duration_ms": t.duration_ms,
                "error": t.error,
                "timestamp": t.timestamp.isoformat() if t.timestamp else "",
            }
            for t in traces
        ],
    }


@router.get("/scans/{scan_id}/structured-output")
async def get_structured_output(scan_id: str, db=Depends(get_db)):
    """
    Get the full structured analysis output matching the framework spec:
    observations, behavior_profiles, differential_findings, inferences,
    attack_paths, risk_scores, confidence_summary, recommendations.
    """
    from backend.models import ExploitChainDB
    scan = db.query(ScanDB).filter(ScanDB.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = _sorted_findings(db, scan_id)
    chains = db.query(ExploitChainDB).filter(ExploitChainDB.scan_id == scan_id).all()
    endpoints = db.query(EndpointDB).filter(EndpointDB.scan_id == scan_id).all()

    # Categorize findings by agent type
    observations = []
    behavior_profiles = {}
    differential_findings = []
    inferences = []
    exploit_results = []

    for f in findings:
        sev = _sev(f)
        finding_dict = {
            "id": f.id,
            "type": f.category,
            "title": f.title,
            "severity": sev,
            "confidence": getattr(f, "confidence", 0.5),
            "confidence_level": getattr(f, "confidence_level", "possible"),
            "endpoint": f.endpoint_url or "",
            "description": f.description or "",
            "cwe": f.cwe_id or "",
            "owasp": getattr(f, "owasp_category", "") or "",
            "remediation": f.remediation or "",
            "evidence": getattr(f, "evidence", []) or [],
            "agent_source": f.module_name or "",
        }

        source = (f.module_name or "").lower()
        if source in ("recon_agent", "schema_agent"):
            observations.append(finding_dict)
        elif source == "behavioral_agent":
            behavior_profiles[f.endpoint_url or "unknown"] = finding_dict
        elif source == "differential_agent":
            differential_findings.append(finding_dict)
        elif source in ("inference_agent", "chain_agent", "risk_agent"):
            inferences.append(finding_dict)
        elif source == "exploit_agent":
            exploit_results.append(finding_dict)
        else:
            observations.append(finding_dict)

    # Attack paths from chains
    attack_paths = [
        {
            "id": c.id,
            "name": c.name,
            "chain_type": c.chain_type,
            "confidence": c.total_confidence,
            "impact": c.impact,
            "complexity": c.complexity,
            "steps": c.steps or [],
        }
        for c in chains
    ]

    # Risk scores from endpoints
    risk_scores = {}
    for ep in endpoints:
        risk_scores[ep.url] = {
            "risk_score": getattr(ep, "risk_score", 0.0),
            "stability_score": getattr(ep, "stability_score", 1.0),
            "category": getattr(ep, "category", "unknown"),
            "requires_auth": ep.requires_auth,
        }

    # Confidence summary
    all_confs = [getattr(f, "confidence", 0.5) for f in findings]
    confidence_summary = {
        "total_findings": len(findings),
        "confirmed": sum(1 for c in all_confs if c >= 0.9),
        "likely": sum(1 for c in all_confs if 0.7 <= c < 0.9),
        "possible": sum(1 for c in all_confs if 0.4 <= c < 0.7),
        "weak": sum(1 for c in all_confs if c < 0.4),
        "avg_confidence": round(sum(all_confs) / max(len(all_confs), 1), 3),
    }

    # Deduplicated recommendations
    seen = set()
    recommendations = []
    for f in findings:
        if f.remediation and f.remediation not in seen:
            seen.add(f.remediation)
            recommendations.append(f.remediation)

    return {
        "scan_id": scan_id,
        "target": scan.target_url,
        "exploit_mode": getattr(scan, "exploit_mode", "standard"),
        "observations": observations,
        "behavior_profiles": behavior_profiles,
        "differential_findings": differential_findings,
        "inferences": inferences,
        "exploit_results": exploit_results,
        "attack_paths": attack_paths,
        "risk_scores": risk_scores,
        "confidence_summary": confidence_summary,
        "recommendations": recommendations[:20],
    }
