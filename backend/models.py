"""
API RIPPER v2.0 — Database Models
SQLAlchemy models for the multi-agent security framework.
Supports: Scans, Findings, Endpoints, Exploit Chains, Agent Traces.
"""

from sqlalchemy import (
    Column, String, Integer, Float, Text, DateTime, Enum as SAEnum,
    ForeignKey, JSON, Boolean
)
from sqlalchemy.orm import relationship, declarative_base
from datetime import datetime
import enum
import uuid

Base = declarative_base()


class ScanStatus(str, enum.Enum):
    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


def gen_uuid():
    return str(uuid.uuid4())


class ScanDB(Base):
    """Security scan record"""
    __tablename__ = "scans"

    id = Column(String, primary_key=True, default=gen_uuid)
    target_url = Column(String, nullable=False)
    name = Column(String, nullable=False)
    description = Column(Text, default="")
    status = Column(SAEnum(ScanStatus), default=ScanStatus.CREATED)
    scan_type = Column(String, default="full")  # full, passive, api_only, quick

    # v2.0: Exploitation mode
    exploit_mode = Column(String, default="standard")  # standard | full_auth
    auth_config = Column(JSON, default=dict)  # {bearer_token, api_key, cookies}

    # Progress tracking
    current_phase = Column(Integer, default=0)
    total_phases = Column(Integer, default=7)
    phase_name = Column(String, default="Initialization")
    progress_percentage = Column(Integer, default=0)

    # Advanced metadata
    risk_score = Column(Float, default=0.0)  # 0-100 overall risk score
    tags = Column(JSON, default=list)  # user-defined tags for filtering
    scan_duration_seconds = Column(Integer, nullable=True)  # total scan duration

    # v2.0: Agent framework data
    knowledge_graph_data = Column(JSON, default=dict)  # serialized KG snapshot
    agent_health_log = Column(JSON, default=dict)      # per-agent health
    message_bus_stats = Column(JSON, default=dict)      # signal stats

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    # Relationships
    findings = relationship("FindingDB", back_populates="scan", cascade="all, delete-orphan")
    endpoints = relationship("EndpointDB", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("ReportDB", back_populates="scan", cascade="all, delete-orphan")
    exploit_chains = relationship("ExploitChainDB", back_populates="scan", cascade="all, delete-orphan")
    traces = relationship("ScanTraceDB", back_populates="scan", cascade="all, delete-orphan")


class FindingDB(Base):
    """Security finding / vulnerability"""
    __tablename__ = "findings"

    id = Column(String, primary_key=True, default=gen_uuid)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)

    # Finding details
    category = Column(String, nullable=False)  # e.g. "API Security", "XSS", "CORS"
    module_name = Column(String, nullable=False)  # which ARSec module found it
    severity = Column(SAEnum(Severity), default=Severity.INFO)
    title = Column(String, nullable=False)
    description = Column(Text, default="")
    endpoint_url = Column(String, default="")
    method = Column(String, default="GET")

    # Structured details
    details = Column(JSON, default=dict)
    remediation = Column(Text, default="")
    cwe_id = Column(String, nullable=True)
    cvss_score = Column(Float, nullable=True)

    # Advanced metadata
    owasp_category = Column(String, nullable=True)  # OWASP API Top 10 category
    false_positive = Column(Boolean, default=False)  # marked as false positive
    confidence = Column(Float, default=0.5)  # 0.0-1.0 confidence score
    confidence_level = Column(String, default="possible")  # weak|possible|likely|confirmed
    evidence = Column(JSON, default=list)  # list of HTTP request/response evidence pairs
    supporting_signals = Column(JSON, default=list)  # signal IDs that support this finding
    exploit_mode_required = Column(String, default="standard")  # standard|full_auth
    chain_id = Column(String, nullable=True)  # link to ExploitChainDB

    # v3.0: Modern API vulnerability classification
    vulnerability_class = Column(String, nullable=True)  # JWT, BOLA, BFLA, Prototype Pollution, etc.
    attack_vector = Column(String, nullable=True)  # OWASP API Top 10 mapping

    # Timestamps
    discovered_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    scan = relationship("ScanDB", back_populates="findings")


class EndpointDB(Base):
    """Discovered API endpoint"""
    __tablename__ = "endpoints"

    id = Column(String, primary_key=True, default=gen_uuid)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)

    url = Column(String, nullable=False)
    path = Column(String, default="/")
    method = Column(String, default="GET")
    status_code = Column(Integer, default=0)
    response_size = Column(Integer, default=0)
    content_type = Column(String, default="")
    requires_auth = Column(Boolean, default=False)
    category = Column(String, default="unknown")  # auth, data_read, data_write, admin, public
    stability_score = Column(Float, default=1.0)   # 0.0-1.0 from behavioral agent
    risk_score = Column(Float, default=0.0)         # from risk agent

    discovered_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("ScanDB", back_populates="endpoints")


class ReportDB(Base):
    """Generated scan report"""
    __tablename__ = "reports"

    id = Column(String, primary_key=True, default=gen_uuid)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)

    title = Column(String, default="Security Scan Report")
    executive_summary = Column(Text, default="")

    # Counts
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)

    # Data
    report_data = Column(JSON, default=dict)

    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("ScanDB", back_populates="reports")


class ExploitChainDB(Base):
    """Multi-step exploit chain constructed by the Chain Agent"""
    __tablename__ = "exploit_chains"

    id = Column(String, primary_key=True, default=gen_uuid)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)

    name = Column(String, default="")
    description = Column(Text, default="")
    chain_type = Column(String, default="")  # data_breach, privilege_escalation, rce, etc.
    total_confidence = Column(Float, default=0.0)
    impact = Column(String, default="medium")  # critical, high, medium, low
    complexity = Column(String, default="medium")  # low, medium, high

    # Ordered list of steps
    steps = Column(JSON, default=list)  # [{action, finding_id, evidence}]
    finding_ids = Column(JSON, default=list)  # linked FindingDB IDs

    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("ScanDB", back_populates="exploit_chains")


class ScanTraceDB(Base):
    """Execution trace entry for full audit trail"""
    __tablename__ = "scan_traces"

    id = Column(String, primary_key=True, default=gen_uuid)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)

    agent = Column(String, nullable=False)
    action = Column(String, nullable=False)
    input_data = Column(JSON, default=dict)
    output_data = Column(JSON, default=dict)
    signals_emitted = Column(JSON, default=list)
    duration_ms = Column(Float, default=0.0)
    error = Column(Text, nullable=True)

    timestamp = Column(DateTime, default=datetime.utcnow)

    scan = relationship("ScanDB", back_populates="traces")
