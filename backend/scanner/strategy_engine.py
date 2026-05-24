"""
API RIPPER v2.0 — Adaptive Strategy Engine
Breaks the static phase loop. Evaluates the Knowledge Graph and Message Bus
between phases to dynamically shift the attack strategy.
"""

import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class StrategyEngine:
    def __init__(self, initial_phases: List[Dict]):
        self.pending_phases = list(initial_phases)
        self.executed_phases = []
        self.strategy_shifts = []

    def get_next_phase(self, knowledge_graph, message_bus, governor) -> Dict:
        """Evaluate context and yield the next phase, modifying the plan if needed."""
        self._evaluate_strategy_shifts(knowledge_graph, message_bus, governor)
        
        if not self.pending_phases:
            return None
            
        next_phase = self.pending_phases.pop(0)
        self.executed_phases.append(next_phase)
        return next_phase

    def _evaluate_strategy_shifts(self, kg, mb, gov):
        """Analyze KG and MB to inject or skip phases."""
        if not self.pending_phases:
            return
            
        MAX_STRATEGY_CHANGES = 5
        if len(self.strategy_shifts) >= MAX_STRATEGY_CHANGES:
            logger.warning(f"[Strategy] Max strategy changes ({MAX_STRATEGY_CHANGES}) reached. Locking strategy.")
            return

        current_phase_num = self.executed_phases[-1]["phase"] if self.executed_phases else 0
        
        # 1. WAF Detected -> Shift Strategy
        signals = mb.get_all_signals()
        waf_signals = [s for s in signals if s.type == "WAF_DETECTED"]
        if waf_signals and "WAF_EVASION" not in self.strategy_shifts:
            self.strategy_shifts.append("WAF_EVASION")
            logger.warning("[Strategy] WAF detected. Shifting to evasion strategy. Reducing concurrency.")
            # Inject a pause/delay or modify governor
            gov.increase_delay(500) # Add 500ms delay per request
            
        # 2. Auth Boundary Detected -> Inject Auth Intelligence Agent
        auth_boundaries = kg.get_auth_boundaries()
        if auth_boundaries and "AUTH_INTELLIGENCE" not in self.strategy_shifts:
            # Check if auth_agent is already in the pipeline
            has_auth_agent = any("auth_agent" in p["agents"] for p in self.pending_phases)
            if not has_auth_agent:
                self.strategy_shifts.append("AUTH_INTELLIGENCE")
                logger.info("[Strategy] Auth boundary detected. Injecting Auth Intelligence Phase.")
                # Inject right after the current phase
                auth_phase = {
                    "phase": current_phase_num + 0.5,
                    "name": "Auth Intelligence",
                    "agents": ["auth_agent"],
                    "description": "Dynamic shift: Deep inspect authentication tokens and boundaries."
                }
                self.pending_phases.insert(0, auth_phase)
                
        # 3. Schema Extracted -> Stop Brute Forcing
        # If schema agent succeeded in mapping everything, skip deep fuzzing if it was planned
        if "schema_agent" in [a for p in self.executed_phases for a in p["agents"]]:
            tech_profile = kg.get_tech_profile()
            if tech_profile.get("schema_mapped") and "BRUTE_FORCE_SKIP" not in self.strategy_shifts:
                self.strategy_shifts.append("BRUTE_FORCE_SKIP")
                logger.info("[Strategy] Schema mapped via definition. Skipping endpoint brute forcing.")
                # If there's a brute force phase, remove it (we don't have one explicitly named right now, but this is the logic)

    def get_total_phases(self):
        return len(self.executed_phases) + len(self.pending_phases)
