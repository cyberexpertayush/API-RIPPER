"""
API RIPPER v2.0 — Agent Coordinator (Scan Orchestrator)

This replaces the old linear module-execution pipeline with a
multi-agent reasoning system. It spawns agents in dependency order,
manages the message bus and knowledge graph lifecycle, monitors
agent health, detects convergence, and produces the final structured output.

The old `run_scan()` interface is preserved for backward compatibility
with the existing routes and WebSocket system.

Exploitation Modes:
  - STANDARD:  Safe, non-destructive (default)
  - FULL_AUTH: Owner-authorized deep exploitation (no restrictions)
"""

import asyncio
import importlib
import logging
import os
import sys
import traceback
import time
from datetime import datetime
from typing import Optional, Callable, Any, Dict, List
from uuid import uuid4

# ── Keep arsec_modules in sys.path for legacy module support ──
_ARSEC_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "arsec_modules"
)
if _ARSEC_DIR not in sys.path:
    sys.path.insert(0, _ARSEC_DIR)

from backend.models import (
    ScanDB, FindingDB, EndpointDB, ScanStatus, Severity,
)
from backend.scanner.knowledge_graph import KnowledgeGraph
from backend.agents.message_bus import MessageBus
from backend.agents.base_agent import ExploitMode, ConfidenceLevel

logger = logging.getLogger(__name__)

# ── Broadcast callback (WebSocket integration) ──────────────
_broadcast_callback: Optional[Callable] = None


def set_broadcast_callback(callback: Callable):
    """Set a callback for broadcasting scan progress over WebSocket."""
    global _broadcast_callback
    _broadcast_callback = callback


async def broadcast_progress(scan_id: str, data: dict):
    """Broadcast progress to WebSocket listeners."""
    if _broadcast_callback:
        try:
            await _broadcast_callback(scan_id, data)
        except Exception as e:
            logger.warning(f"Broadcast failed: {e}")


# ── Agent Registry ──────────────────────────────────────────

# Agents run in this order. Each phase can depend on previous phases.
AGENT_PHASES = [
    {
        "phase": 1,
        "name": "Reconnaissance & Decoding",
        "agents": ["recon_agent"],
        "description": "Deep API surface discovery, endpoint decoding, tech fingerprinting",
    },
    {
        "phase": 2,
        "name": "Behavioral Profiling",
        "agents": ["behavioral_agent"],
        "description": "Build behavioral models, detect anomalies, map error surfaces",
    },
    {
        "phase": 3,
        "name": "Differential Analysis",
        "agents": ["differential_agent"],
        "description": "Compare responses across controlled variations",
    },
    {
        "phase": 4,
        "name": "Schema & Data Exposure",
        "agents": ["schema_agent"],
        "description": "Infer API schemas, detect sensitive data exposure",
    },
    {
        "phase": 5,
        "name": "Business Logic & State",
        "agents": ["business_logic_agent"],
        "description": "Model API workflows, detect race conditions and bypasses",
    },
    {
        "phase": 6,
        "name": "Modern API Attack Surface",
        "agents": ["modern_api_agent"],
        "description": "JWT attacks, BOLA/BFLA, prototype pollution, deserialization, WebSocket, file upload, SSRF, CORS, race conditions, LLM injection",
    },
    {
        "phase": 7,
        "name": "Inference & Correlation",
        "agents": ["inference_agent"],
        "description": "Cross-signal correlation, hypothesis formation",
    },
    {
        "phase": 8,
        "name": "Chain Analysis & Risk Scoring",
        "agents": ["chain_agent", "risk_agent"],
        "description": "Multi-step attack paths, risk scoring",
    },
    {
        "phase": 9,
        "name": "Validation & Exploitation",
        "agents": ["exploit_agent"],
        "description": "Proof-of-concept execution, differential confirmation",
    },
]

# Maximum total phases (including dynamically injected ones) to prevent infinite loop
MAX_TOTAL_PHASES = 15
# Maximum time per agent (seconds)
AGENT_TIMEOUT = 300  # 5 minutes per agent (down from 30 min)


def _load_agent(agent_name: str, knowledge_graph, message_bus, config: dict):
    """Dynamically load an agent class from backend.agents package."""
    try:
        module = importlib.import_module(f"backend.agents.{agent_name}")
        # Convention: module name 'recon_agent' → class 'ReconAgent'
        class_name = "".join(word.capitalize() for word in agent_name.split("_"))
        agent_class = getattr(module, class_name)
        return agent_class(knowledge_graph, message_bus, config)
    except (ImportError, AttributeError) as e:
        logger.warning(f"Agent '{agent_name}' not available: {e}")
        return None


def _is_scan_cancelled(db_session_factory, scan_id: str) -> bool:
    """Check if scan has been cancelled by the user (uses fresh session)."""
    db = None
    try:
        db = db_session_factory()
        scan = db.query(ScanDB).filter(ScanDB.id == scan_id).first()
        if scan and scan.status == ScanStatus.CANCELLED:
            return True
        return False
    except Exception:
        return False
    finally:
        if db:
            db.close()


def _update_scan_progress(db_session_factory, scan_id: str, **kwargs):
    """Update scan record with progress info (uses fresh session to avoid stale state)."""
    db = None
    try:
        db = db_session_factory()
        scan = db.query(ScanDB).filter(ScanDB.id == scan_id).first()
        if scan:
            for key, value in kwargs.items():
                if hasattr(scan, key):
                    setattr(scan, key, value)
            db.commit()
    except Exception as e:
        logger.error(f"Failed to update scan progress: {e}")
        if db:
            try:
                db.rollback()
            except Exception:
                pass
    finally:
        if db:
            db.close()


# ── Main Scan Entry Point ───────────────────────────────────

async def run_scan(
    scan_id: str,
    target_url: str,
    scan_name: str,
    db_session_factory,
    exploit_mode: str = "standard",
    auth_config: Dict[str, Any] = None,
):
    """
    Execute a full multi-agent security analysis against the target URL.

    This is the main entry point called from background tasks.
    It spawns all agents in dependency order, manages the shared
    knowledge graph and message bus, and persists results to the database.

    Args:
        scan_id:            UUID of the scan record
        target_url:         URL to scan
        scan_name:          Human-readable scan name
        db_session_factory: Callable returning a new DB session
        exploit_mode:       "standard" or "full_auth"
        auth_config:        Optional auth credentials (bearer token, api key, cookies)
    """
    knowledge_graph = KnowledgeGraph()
    message_bus = MessageBus()

    # Resource Governor (shared across all agents)
    from backend.agents.resource_governor import ResourceGovernor
    governor = ResourceGovernor()

    # Agent configuration
    config = {
        "target_url": target_url,
        "scan_id": scan_id,
        "scan_name": scan_name,
        "exploit_mode": exploit_mode,
        "auth_config": auth_config or {},
        "request_delay_ms": 100,
        "max_variations_per_endpoint": 10,
        "max_total_diff_tests": 1000,
        "governor": governor,
    }

    total_findings = []
    total_endpoints = []
    agent_traces = []
    agent_health_log = {}
    agent_metrics = {}      # Per-agent observability
    phase_timings = []       # Track how long each phase takes
    start_time = time.time()

    try:
        # Mark scan as running
        _update_scan_progress(db_session_factory, scan_id,
                              status=ScanStatus.RUNNING,
                              started_at=datetime.utcnow())

        # Broadcast scan started
        await broadcast_progress(scan_id, {
            "type": "scan_started",
            "target_url": target_url,
            "scan_name": scan_name,
            "exploit_mode": exploit_mode,
        })

        # ── Run agents phase by phase (Adaptive Strategy) ─────────
        from backend.scanner.strategy_engine import StrategyEngine
        strategy = StrategyEngine(AGENT_PHASES)

        modules_run = 0
        modules_failed = 0
        phases_executed = 0

        while True:
            # ── CANCELLATION CHECK ─────────────────────────────
            if _is_scan_cancelled(db_session_factory, scan_id):
                await broadcast_progress(scan_id, {
                    "type": "live_output",
                    "line": "⛔ Scan cancelled by user",
                    "level": "warning",
                })
                _update_scan_progress(db_session_factory, scan_id,
                                      status=ScanStatus.CANCELLED,
                                      completed_at=datetime.utcnow(),
                                      phase_name="Cancelled")
                await broadcast_progress(scan_id, {
                    "type": "scan_complete",
                    "findings_count": len(total_findings),
                    "endpoints_count": knowledge_graph.endpoint_count(),
                    "cancelled": True,
                })
                return

            # ── INFINITE LOOP PROTECTION ───────────────────────
            if phases_executed >= MAX_TOTAL_PHASES:
                logger.warning(f"Scan {scan_id}: Hit max phase limit ({MAX_TOTAL_PHASES}), stopping")
                await broadcast_progress(scan_id, {
                    "type": "live_output",
                    "line": f"⚠ Max phase limit ({MAX_TOTAL_PHASES}) reached — completing scan",
                    "level": "warning",
                })
                break

            phase_info = strategy.get_next_phase(knowledge_graph, message_bus, governor)
            if not phase_info:
                break

            phases_executed += 1
            phase_start = time.time()
            phase_num = phase_info["phase"]
            phase_name = phase_info["name"]
            total_phases = strategy.get_total_phases()

            # Calculate progress percentage
            progress = min(95, int((phases_executed - 1) / max(total_phases, 1) * 100))

            # Calculate ETA based on previous phase timings
            eta_seconds = 0
            if phase_timings:
                avg_phase_time = sum(phase_timings) / len(phase_timings)
                remaining_phases = total_phases - phases_executed + 1
                eta_seconds = int(avg_phase_time * remaining_phases)

            # Update scan progress in DB
            _update_scan_progress(db_session_factory, scan_id,
                                  current_phase=phase_num,
                                  phase_name=phase_name,
                                  total_phases=total_phases,
                                  progress_percentage=progress)

            # Broadcast phase update with detailed progress
            await broadcast_progress(scan_id, {
                "type": "phase_update",
                "phase": phase_num,
                "phase_name": phase_name,
                "progress": progress,
                "findings_count": len(total_findings),
                "endpoints_count": knowledge_graph.endpoint_count(),
                "total_phases": total_phases,
                "phases_completed": phases_executed - 1,
                "phases_remaining": total_phases - phases_executed + 1,
                "modules_run": modules_run,
                "modules_failed": modules_failed,
                "elapsed_seconds": int(time.time() - start_time),
                "eta_seconds": eta_seconds,
            })

            await broadcast_progress(scan_id, {
                "type": "live_output",
                "line": f"═══ Phase {phases_executed}/{total_phases}: {phase_name} ═══",
                "level": "phase",
            })

            # Run each agent in this phase
            for agent_name in phase_info["agents"]:
                # Check cancellation before each agent
                if _is_scan_cancelled(db_session_factory, scan_id):
                    break

                await broadcast_progress(scan_id, {
                    "type": "live_output",
                    "line": f"▶ Starting {agent_name}...",
                    "level": "module_start",
                    "module": agent_name,
                })

                agent = _load_agent(agent_name, knowledge_graph, message_bus, config)

                if agent is None:
                    modules_failed += 1
                    await broadcast_progress(scan_id, {
                        "type": "live_output",
                        "line": f"⚠ {agent_name}: Not available (skipped)",
                        "level": "warning",
                        "module": agent_name,
                    })
                    continue

                agent_start = time.time()
                try:
                    # Execute the agent's full reasoning pipeline with timeout
                    findings = await asyncio.wait_for(
                        agent.run(),
                        timeout=AGENT_TIMEOUT,
                    )
                    modules_run += 1
                    agent_duration = round(time.time() - agent_start, 1)

                    # Collect results
                    if findings:
                        total_findings.extend(findings)

                    # Log agent health
                    agent_health_log[agent_name] = agent.health.to_dict()
                    agent_traces.extend(agent.trace)

                    # Broadcast results
                    findings_count = len(findings) if findings else 0
                    await broadcast_progress(scan_id, {
                        "type": "live_output",
                        "line": f"✓ {agent_name}: {findings_count} findings, {agent.health.actions_completed} actions ({agent_duration}s)",
                        "level": "success" if findings_count > 0 else "info",
                        "module": agent_name,
                    })

                    # Broadcast individual findings
                    for finding in (findings or []):
                        if finding.confidence >= 0.4:  # Only broadcast significant findings
                            await broadcast_progress(scan_id, {
                                "type": "live_output",
                                "line": f"  [{finding.severity.upper()}] {finding.title} (confidence: {finding.confidence:.0%})",
                                "level": "finding",
                                "module": agent_name,
                            })

                except (asyncio.TimeoutError, asyncio.CancelledError):
                    modules_failed += 1
                    agent_duration = round(time.time() - agent_start, 1)
                    agent_health_log[agent_name] = {"status": "failed", "errors": [f"Timeout ({AGENT_TIMEOUT}s)"]}
                    # Collect partial results if any
                    if hasattr(agent, 'findings') and agent.findings:
                        total_findings.extend(agent.findings)
                        logger.info(f"Collected {len(agent.findings)} partial findings from timed-out {agent_name}")
                    if hasattr(agent, 'trace'):
                        agent_traces.extend(agent.trace)
                    await broadcast_progress(scan_id, {
                        "type": "live_output",
                        "line": f"⏱ {agent_name}: Timed out after {AGENT_TIMEOUT}s (partial results saved)",
                        "level": "error",
                        "module": agent_name,
                    })

                except BaseException as e:
                    modules_failed += 1
                    agent_duration = round(time.time() - agent_start, 1)
                    logger.error(f"Agent {agent_name} failed: {e}", exc_info=True)
                    agent_health_log[agent_name] = {"status": "failed", "errors": [str(e)]}
                    # Collect partial results if any
                    if hasattr(agent, 'findings') and agent.findings:
                        total_findings.extend(agent.findings)
                    if hasattr(agent, 'trace'):
                        agent_traces.extend(agent.trace)
                    await broadcast_progress(scan_id, {
                        "type": "live_output",
                        "line": f"✗ {agent_name}: Failed — {str(e)[:120]}",
                        "level": "error",
                        "module": agent_name,
                    })

            # Track phase timing for ETA calculation
            phase_duration = time.time() - phase_start
            phase_timings.append(phase_duration)

            # ── Agent Metrics (Observability) ─────────────────
            for agent_name_done in phase_info["agents"]:
                agent_metrics[agent_name_done] = {
                    "requests_used": governor.get_agent_usage(agent_name_done),
                    "signals_generated": message_bus.stats().get("per_agent_counts", {}).get(agent_name_done, 0),
                    "execution_phase": phase_num,
                }

            # ── Resource/Time Abort Check ───────────────────
            if governor.is_time_expired():
                await broadcast_progress(scan_id, {
                    "type": "live_output",
                    "line": "⏱ Scan time limit reached — completing scan with results so far",
                    "level": "warning",
                })
                break

        # ── Final cancellation check ──────────────────────────
        if _is_scan_cancelled(db_session_factory, scan_id):
            return

        # ── Persist findings to database ────────────────────
        await broadcast_progress(scan_id, {
            "type": "live_output",
            "line": "═══ Saving results to database ═══",
            "level": "phase",
        })

        db = db_session_factory()
        try:
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

            for finding in total_findings:
                if finding.confidence < 0.2:
                    continue  # Skip noise

                severity_str = finding.severity.lower()
                severity_counts[severity_str] = severity_counts.get(severity_str, 0) + 1

                try:
                    sev = getattr(Severity, severity_str.upper(), Severity.INFO)
                except AttributeError:
                    sev = Severity.INFO

                db_finding = FindingDB(
                    id=finding.id,
                    scan_id=scan_id,
                    title=finding.title or finding.type,
                    description=finding.description,
                    severity=sev,
                    category=finding.type,
                    module_name=finding.agent_source,
                    endpoint_url=finding.endpoint,
                    method=finding.method,
                    confidence=finding.confidence,
                    evidence=finding.evidence,
                    cwe_id=finding.cwe,
                    owasp_category=finding.owasp,
                    remediation=finding.remediation,
                    false_positive=False,
                )
                db.add(db_finding)

            # Persist discovered endpoints from Knowledge Graph
            for ep_data in knowledge_graph.get_all_endpoints():
                for method in ep_data.get("methods", ["GET"]):
                    db_endpoint = EndpointDB(
                        id=str(uuid4()),
                        scan_id=scan_id,
                        url=ep_data["url"],
                        path=_extract_path(ep_data["url"]),
                        method=method,
                        status_code=0,
                        category=ep_data.get("classification", "unknown"),
                    )
                    db.add(db_endpoint)

            # Persist exploit chains
            from backend.models import ExploitChainDB, ScanTraceDB, ReportDB
            for finding in total_findings:
                if finding.chain_id and finding.evidence:
                    for ev in finding.evidence:
                        chain_data = ev.get("chain") if isinstance(ev, dict) else None
                        if chain_data and isinstance(chain_data, dict):
                            db_chain = ExploitChainDB(
                                id=chain_data.get("id", str(uuid4())),
                                scan_id=scan_id,
                                name=chain_data.get("name", ""),
                                description=finding.description or "",
                                chain_type=chain_data.get("chain_type", ""),
                                total_confidence=chain_data.get("total_confidence", 0.0),
                                impact=chain_data.get("impact", "medium"),
                                complexity=chain_data.get("complexity", "medium"),
                                steps=chain_data.get("steps", []),
                                finding_ids=chain_data.get("finding_ids", []),
                            )
                            db.add(db_chain)

            # Persist agent execution traces
            for trace_entry in agent_traces[:500]:  # Cap at 500 traces
                t = trace_entry.to_dict() if hasattr(trace_entry, 'to_dict') else trace_entry
                db_trace = ScanTraceDB(
                    id=str(uuid4()),
                    scan_id=scan_id,
                    agent=t.get("agent", "unknown") if isinstance(t, dict) else getattr(trace_entry, 'agent', 'unknown'),
                    action=t.get("action", "") if isinstance(t, dict) else getattr(trace_entry, 'action', ''),
                    input_data=t.get("input", {}) if isinstance(t, dict) else getattr(trace_entry, 'input_data', {}),
                    output_data=t.get("output", {}) if isinstance(t, dict) else getattr(trace_entry, 'output_data', {}),
                    signals_emitted=t.get("signals_emitted", []) if isinstance(t, dict) else getattr(trace_entry, 'signals_emitted', []),
                    duration_ms=t.get("duration_ms", 0.0) if isinstance(t, dict) else getattr(trace_entry, 'duration_ms', 0.0),
                    error=t.get("error") if isinstance(t, dict) else getattr(trace_entry, 'error', None),
                )
                db.add(db_trace)

            # Generate executive summary
            top_issues = []
            for f in sorted(total_findings, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.severity, 4))[:5]:
                top_issues.append(f"{f.severity.upper()}: {f.title}")

            duration = time.time() - start_time
            exec_summary = (
                f"API RIPPER v2.0 multi-agent security analysis of {target_url} "
                f"discovered {len([f for f in total_findings if f.confidence >= 0.2])} findings across "
                f"{knowledge_graph.endpoint_count()} endpoints. "
                f"Mode: {'FULL AUTHORIZATION' if exploit_mode == 'full_auth' else 'STANDARD'}. "
                f"Agents deployed: {modules_run}/{modules_run + modules_failed}. "
                f"Duration: {int(duration)}s. "
            )
            if top_issues:
                exec_summary += "Top issues: " + "; ".join(top_issues[:3]) + "."

            # Create report record
            db_report = ReportDB(
                id=str(uuid4()),
                scan_id=scan_id,
                title=f"Security Assessment: {scan_name}",
                executive_summary=exec_summary,
                total_findings=len([f for f in total_findings if f.confidence >= 0.2]),
                critical_count=severity_counts.get("critical", 0),
                high_count=severity_counts.get("high", 0),
                medium_count=severity_counts.get("medium", 0),
                low_count=severity_counts.get("low", 0),
                info_count=severity_counts.get("info", 0),
                report_data={
                    "exploit_mode": exploit_mode,
                    "agents_run": modules_run,
                    "agents_failed": modules_failed,
                    "knowledge_graph_stats": knowledge_graph.stats(),
                    "message_bus_stats": message_bus.stats(),
                    "agent_health": agent_health_log,
                    "phase_timings": phase_timings,
                    "total_duration_seconds": int(duration),
                },
            )
            db.add(db_report)

            # Update scan record
            scan = db.query(ScanDB).filter(ScanDB.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.progress_percentage = 100
                scan.phase_name = "Completed"
                scan.scan_duration_seconds = int(duration)
                scan.knowledge_graph_data = knowledge_graph.to_dict()
                scan.agent_health_log = agent_health_log
                scan.message_bus_stats = message_bus.stats()

            db.commit()
        except Exception as e:
            logger.error(f"Failed to persist results: {e}", exc_info=True)
            db.rollback()
        finally:
            db.close()

        # Generate JSON Report file
        try:
            reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")
            os.makedirs(reports_dir, exist_ok=True)
            report_file = os.path.join(reports_dir, f"{scan_id}.json")

            report_payload = {
                "scan_id": scan_id,
                "scan_name": scan_name,
                "target_url": target_url,
                "exploit_mode": exploit_mode,
                "status": "COMPLETED",
                "duration_seconds": int(duration),
                "executive_summary": exec_summary,
                "severity_counts": severity_counts,
                "metrics": {
                    "agents_run": modules_run,
                    "agents_failed": modules_failed,
                    "endpoints_discovered": knowledge_graph.endpoint_count()
                },
                "findings": [f.to_dict() if hasattr(f, 'to_dict') else f.__dict__ for f in total_findings if f.confidence >= 0.2],
                "agent_health": agent_health_log
            }

            import json
            with open(report_file, "w") as f:
                json.dump(report_payload, f, indent=2, default=str)
            logger.info(f"Report generated successfully: {report_file}")

        except Exception as e:
            logger.error(f"Failed to generate JSON report: {e}")

        # Broadcast completion
        await broadcast_progress(scan_id, {
            "type": "scan_complete",
            "findings_count": len([f for f in total_findings if f.confidence >= 0.2]),
            "endpoints_count": knowledge_graph.endpoint_count(),
            "severity_counts": severity_counts,
            "modules_run": modules_run,
            "modules_failed": modules_failed,
            "duration_seconds": int(duration),
            "knowledge_graph_stats": knowledge_graph.stats(),
            "message_bus_stats": message_bus.stats(),
        })

        logger.info(
            f"Scan {scan_id} completed: {len(total_findings)} findings, "
            f"{knowledge_graph.endpoint_count()} endpoints, {int(duration)}s"
        )

    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}", exc_info=True)
        _update_scan_progress(db_session_factory, scan_id,
                              status=ScanStatus.FAILED,
                              completed_at=datetime.utcnow(),
                              phase_name=f"Failed: {str(e)[:100]}")

        await broadcast_progress(scan_id, {
            "type": "scan_failed",
            "error": str(e),
        })

    finally:
        knowledge_graph.clear()
        message_bus.clear()


def _extract_path(url: str) -> str:
    """Extract the path component from a URL."""
    try:
        from urllib.parse import urlparse
        return urlparse(url).path or "/"
    except Exception:
        return "/"
