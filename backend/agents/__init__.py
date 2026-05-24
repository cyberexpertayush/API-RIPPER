"""
API RIPPER v4.0 — Agent Framework Package
All autonomous security analysis agents + elite engines + infrastructure.
"""

from backend.agents.base_agent import BaseAgent, Finding, ExploitMode, ConfidenceLevel
from backend.agents.message_bus import MessageBus, Signal, SIGNAL_WEIGHTS, MAX_SIGNALS_PER_AGENT
from backend.agents.resource_governor import ResourceGovernor
from backend.agents.waf_handler import WAFDetector, WAFBypass, WAFProfile
from backend.agents.historical_memory import HistoricalMemory

# Elite Intelligence Components
from backend.agents.mutation_engine import ContextualMutationEngine
from backend.agents.attack_patterns import AttackPattern, ATTACK_PATTERNS
from backend.agents.business_logic_agent import BusinessLogicAgent
from backend.agents.response_classifier import ResponseClassifier, ResponseClass

# Phase 2: Observation Agents
from backend.agents.recon_agent import ReconAgent
from backend.agents.behavioral_agent import BehavioralAgent
from backend.agents.differential_agent import DifferentialAgent

# Phase 3: Intelligence Agents
from backend.agents.schema_agent import SchemaAgent
from backend.agents.auth_agent import AuthAgent
from backend.agents.inference_agent import InferenceAgent
from backend.agents.chain_agent import ChainAgent

# Phase 4: Risk & Exploitation
from backend.agents.risk_agent import RiskAgent
from backend.agents.exploit_agent import ExploitAgent

# Phase 5: v4.0 Elite Engines
from backend.agents.accuracy_engine import AccuracyEngine, FindingVerifier, BaselineManager
from backend.agents.waf_evasion_engine import WAFEvasionEngine, EncodingPrimitive, EncodingChain
from backend.agents.deep_injection_engine import DeepInjectionEngine, OOBTracker, TimeOracleAnalyzer
from backend.agents.cloud_security_engine import CloudSecurityEngine, CloudFinding

# Utilities
from backend.agents.request_decoder import RequestDecoder

# Agent registry for dynamic loading by orchestrator
AGENT_REGISTRY = {
    "recon_agent": ReconAgent,
    "behavioral_agent": BehavioralAgent,
    "differential_agent": DifferentialAgent,
    "schema_agent": SchemaAgent,
    "business_logic_agent": BusinessLogicAgent,
    "auth_agent": AuthAgent,
    "inference_agent": InferenceAgent,
    "chain_agent": ChainAgent,
    "risk_agent": RiskAgent,
    "exploit_agent": ExploitAgent,
}

__all__ = [
    "BaseAgent", "Finding", "ExploitMode", "ConfidenceLevel",
    "MessageBus", "Signal", "SIGNAL_WEIGHTS", "MAX_SIGNALS_PER_AGENT",
    "ResourceGovernor", "WAFDetector", "WAFBypass", "WAFProfile",
    "HistoricalMemory", "ContextualMutationEngine", "AttackPattern", "ATTACK_PATTERNS",
    "ResponseClassifier", "ResponseClass",
    "ReconAgent", "BehavioralAgent", "DifferentialAgent",
    "SchemaAgent", "BusinessLogicAgent", "AuthAgent", "InferenceAgent", "ChainAgent",
    "RiskAgent", "ExploitAgent",
    # v4.0 Elite Engines
    "AccuracyEngine", "FindingVerifier", "BaselineManager",
    "WAFEvasionEngine", "EncodingPrimitive", "EncodingChain",
    "DeepInjectionEngine", "OOBTracker", "TimeOracleAnalyzer",
    "CloudSecurityEngine", "CloudFinding",
    "RequestDecoder", "AGENT_REGISTRY",
]
