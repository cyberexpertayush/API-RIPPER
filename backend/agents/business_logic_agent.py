"""
API RIPPER v2.0 — Business Logic Agent (State Machine Modeling)
Models API workflows to detect race conditions, illegal state
transitions, and multi-step abuse (e.g., bypassing a payment step).

OBSERVE: Analyze endpoint sequences from the Knowledge Graph.
PROFILE: Build a StateMachineModel mapping workflows.
DIFF: Detect illegal or bypassable transitions.
INFER: Emit signals for business logic flaws.
"""

import logging
from typing import Any, Dict, List, Set
from uuid import uuid4

from backend.agents.base_agent import BaseAgent, Finding

logger = logging.getLogger(__name__)

class StateMachineModel:
    """
    Models the workflow of an API based on endpoint paths and relationships.
    """
    def __init__(self):
        self.states: Set[str] = set()
        self.transitions: Dict[str, Set[str]] = {} # source_state -> set(target_states)
        self.entry_points: Set[str] = set()
        self.exit_points: Set[str] = set()
        self.state_endpoints: Dict[str, str] = {} # state -> endpoint_url
        
    def add_transition(self, source: str, target: str):
        self.states.add(source)
        self.states.add(target)
        if source not in self.transitions:
            self.transitions[source] = set()
        self.transitions[source].add(target)

    def to_dict(self) -> dict:
        return {
            "states": list(self.states),
            "transitions": {k: list(v) for k, v in self.transitions.items()},
            "entry_points": list(self.entry_points),
            "exit_points": list(self.exit_points),
        }

class BusinessLogicAgent(BaseAgent):
    """
    Analyzes API business logic and state workflows to find bypasses.
    """
    name = "business_logic_agent"

    async def observe(self) -> Dict[str, Any]:
        """Step 1: Collect endpoints and relationships from KG."""
        endpoints = self.kg.get_all_endpoints()
        relationships = self.kg.get_relationships()
        return {"endpoints": endpoints, "relationships": relationships}

    async def profile(self, data: Dict[str, Any]) -> StateMachineModel:
        """Step 2: Build a State Machine Model from endpoints and track Data Flows."""
        from backend.scanner.knowledge_graph import DataFlow
        model = StateMachineModel()
        endpoints = data.get("endpoints", [])
        relationships = data.get("relationships", [])

        # Step 2a: Heuristics for state detection based on URL paths
        for ep in endpoints:
            url = ep.get("url", "")
            method = ep.get("methods", ["GET"])[0] if ep.get("methods") else "GET"
            
            # Simple state naming heuristic (e.g., /api/cart/checkout -> checkout)
            parts = [p for p in url.split("/") if p and not p.isdigit() and "{" not in p]
            if not parts:
                continue
                
            state_name = f"{method}_{parts[-1]}"
            model.states.add(state_name)
            model.state_endpoints[state_name] = url
            
            # Entry points are typically GET requests or object creations
            if method in ["GET", "POST"]:
                if len(parts) <= 2:
                    model.entry_points.add(state_name)

        # Step 2b: Full Data Flow Tracking (ID source -> ID reuse)
        self._track_data_flows(endpoints)

        # Build transitions from data flows
        # Re-fetch data flows from KG now that we just updated them
        all_data_flows = self.kg.get_data_flows()
        for flow in all_data_flows:
            src_url = flow.get("source")
            tgt_url = flow.get("target")
            
            src_state = self._url_to_state(src_url, endpoints)
            tgt_state = self._url_to_state(tgt_url, endpoints)
            
            if src_state and tgt_state and src_state != tgt_state:
                model.add_transition(src_state, tgt_state)

        # Infer missing transitions (e.g., checkout -> payment)
        self._infer_implicit_workflows(model)
        
        return model

    def _track_data_flows(self, endpoints: List[Dict]):
        """Analyze endpoint schemas to track where IDs originate and where they are reused."""
        from backend.scanner.knowledge_graph import DataFlow

        # 1. Map where fields originate (responses)
        # origin_map: field_name -> list(url)
        origin_map = {}
        for ep in endpoints:
            url = ep.get("url", "")
            schema = ep.get("response_schema", {})
            if schema and isinstance(schema, dict):
                # Typically, POST/GET return objects
                for key in schema.keys():
                    if "id" in key.lower() or key.lower() in ["uuid", "token", "reference", "ref"]:
                        if key not in origin_map:
                            origin_map[key] = []
                        origin_map[key].append(url)

        # 2. Map where fields are used (parameters)
        for ep in endpoints:
            tgt_url = ep.get("url", "")
            params = ep.get("parameters", {})
            for param_name in params.keys():
                # If this parameter name was seen as an output from another endpoint
                if param_name in origin_map:
                    for src_url in origin_map[param_name]:
                        if src_url != tgt_url:
                            # We found a Data Flow!
                            flow = DataFlow(
                                source_endpoint=src_url,
                                target_endpoint=tgt_url,
                                shared_fields=[param_name],
                                flow_type="id_reference",
                                confidence=0.8
                            )
                            self.kg.add_data_flow(flow)
                            # Add to Correlation Graph
                            self.kg.add_correlation(src_url, "endpoint", tgt_url, "endpoint", f"supplies_{param_name}_to", 0.8)

    def _url_to_state(self, url: str, endpoints: List[Dict]) -> str:
        for ep in endpoints:
            if ep.get("url") == url:
                parts = [p for p in url.split("/") if p and not p.isdigit() and "{" not in p]
                if parts:
                    method = ep.get("methods", ["GET"])[0]
                    return f"{method}_{parts[-1]}"
        return ""

    def _infer_implicit_workflows(self, model: StateMachineModel):
        """Identify common workflow patterns based on state names."""
        common_flows = [
            ["POST_cart", "POST_checkout", "POST_payment", "GET_order"],
            ["POST_register", "POST_verify", "POST_login"],
            ["POST_upload", "POST_process", "GET_result"]
        ]
        
        for flow in common_flows:
            # Check if these states exist in our model
            existing_states = [s for s in flow if s in model.states]
            if len(existing_states) >= 2:
                # Link them up based on the template
                for i in range(len(existing_states) - 1):
                    model.add_transition(existing_states[i], existing_states[i+1])

    async def differential_analyze(self, model: StateMachineModel) -> List[Dict]:
        """Step 3: Detect illegal transitions or bypasses."""
        bypasses = []
        
        # Look for disconnected high-value states (e.g., a payment endpoint not connected to cart)
        high_value_keywords = ["payment", "checkout", "transfer", "admin", "process", "verify"]
        
        for state in model.states:
            is_high_value = any(kw in state.lower() for kw in high_value_keywords)
            if not is_high_value:
                continue
                
            # Check if this state can be reached from an entry point
            if not self._is_reachable(model, state):
                bypasses.append({
                    "type": "workflow_bypass",
                    "state": state,
                    "endpoint": model.state_endpoints.get(state),
                    "reason": "High-value endpoint has no enforced prerequisites (unreachable in standard flow but exists)."
                })
                
        # Look for circular dependencies (potential infinite loops / resource exhaustion)
        cycles = self._find_cycles(model)
        if cycles:
            for cycle in cycles:
                bypasses.append({
                    "type": "business_logic_cycle",
                    "states": cycle,
                    "reason": f"Circular workflow detected, potential for logic loops."
                })

        return bypasses
        
    def _is_reachable(self, model: StateMachineModel, target_state: str) -> bool:
        """Simple BFS to check if target_state is reachable from ANY entry point."""
        if target_state in model.entry_points:
            return True
            
        visited = set()
        queue = list(model.entry_points)
        
        while queue:
            current = queue.pop(0)
            if current == target_state:
                return True
            visited.add(current)
            for neighbor in model.transitions.get(current, []):
                if neighbor not in visited:
                    queue.append(neighbor)
        return False

    def _find_cycles(self, model: StateMachineModel) -> List[List[str]]:
        """Detect circular dependencies in the workflow."""
        visited = set()
        rec_stack = set()
        cycles = []
        
        def dfs(node, path):
            visited.add(node)
            rec_stack.add(node)
            path.append(node)
            
            for neighbor in model.transitions.get(node, []):
                if neighbor not in visited:
                    dfs(neighbor, list(path))
                elif neighbor in rec_stack:
                    cycle_start = path.index(neighbor)
                    cycles.append(path[cycle_start:])
                    
            rec_stack.remove(node)
            
        for node in model.states:
            if node not in visited:
                dfs(node, [])
                
        return cycles

    async def infer(self, bypasses: List[Dict]) -> List[Finding]:
        """Step 4: Emit findings for detected business logic flaws."""
        findings = []
        
        for bypass in bypasses:
            if bypass["type"] == "workflow_bypass":
                findings.append(Finding(
                    type="business_logic_bypass",
                    title=f"Business Logic Bypass: {bypass['state']}",
                    description=(
                        f"The endpoint '{bypass['endpoint']}' performs a high-value action "
                        f"but does not appear to enforce preceding workflow steps. "
                        f"An attacker might access this directly, skipping prerequisites (e.g., payment)."
                    ),
                    severity="high",
                    confidence=0.75,
                    endpoint=bypass["endpoint"],
                    cwe="CWE-840",
                    owasp="API6:2023",
                    remediation="Implement strict state validation server-side. Ensure the user has completed necessary prior steps before allowing this action.",
                    evidence=[{"type": "state_machine_analysis", "details": bypass}],
                    exploit_mode_required=self.exploit_mode.value
                ))
                self.emit_signal("WORKFLOW_BYPASS", bypass, confidence=0.75, priority=2)
                
            elif bypass["type"] == "business_logic_cycle":
                cycle_str = " -> ".join(bypass["states"])
                findings.append(Finding(
                    type="logic_cycle_detected",
                    title=f"Logic Cycle Detected",
                    description=f"A circular dependency was detected in the API workflow: {cycle_str}. This could lead to infinite loops or resource exhaustion.",
                    severity="medium",
                    confidence=0.6,
                    endpoint=model.state_endpoints.get(bypass["states"][0], ""),
                    remediation="Review workflow logic to prevent cyclical state transitions.",
                    evidence=[{"type": "cycle", "states": bypass["states"]}],
                ))

        return findings
