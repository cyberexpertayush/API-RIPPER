"""
API RIPPER v2.0 — Real Attack Pattern Library (Elite Level)
Standardized, executable attack definitions for the engine.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Callable

@dataclass
class AttackPattern:
    """
    Defines a real-world, executable attack chain.
    Used by ChainAgent to build chains and ExploitAgent to execute them.
    """
    id: str
    name: str
    description: str
    impact: str  # critical, high, medium, low
    required_signals: List[str]
    optional_signals: List[str]
    # List of logical steps required to execute the attack
    execution_steps: List[Dict[str, Any]]
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "impact": self.impact,
            "required_signals": self.required_signals,
            "optional_signals": self.optional_signals,
            "execution_steps": self.execution_steps,
        }

# Elite Attack Patterns Library
ATTACK_PATTERNS = {
    "bola_idor_data_extraction": AttackPattern(
        id="bola_idor_data_extraction",
        name="BOLA/IDOR Mass Data Extraction",
        description="Exploits Broken Object Level Authorization (IDOR) to sequentially access and extract data belonging to other users.",
        impact="critical",
        required_signals=["broken_object_level_authorization"],
        optional_signals=["sensitive_data_exposure"],
        execution_steps=[
            {
                "action": "identify_target_id",
                "description": "Identify the target resource ID field in the request (URL or Body).",
            },
            {
                "action": "enumerate_ids",
                "description": "Mutate the ID (sequential or UUID guessing) and send 10-20 requests.",
            },
            {
                "action": "validate_data_extraction",
                "description": "Analyze responses. If >1 response contains valid data different from the base response, BOLA is confirmed.",
            }
        ]
    ),
    
    "bfla_admin_escalation": AttackPattern(
        id="bfla_admin_escalation",
        name="BFLA Admin Privilege Escalation",
        description="Exploits Broken Function Level Authorization to access administrative endpoints using standard user credentials.",
        impact="critical",
        required_signals=["security_misconfiguration"],
        optional_signals=["broken_authentication_with_data_leak", "endpoint_discovered"],
        execution_steps=[
            {
                "action": "identify_admin_endpoints",
                "description": "Identify endpoints matching admin/internal patterns.",
            },
            {
                "action": "send_unauthorized_request",
                "description": "Send request to admin endpoint using standard user token or no token.",
            },
            {
                "action": "method_override_attack",
                "description": "If blocked, retry using X-HTTP-Method-Override or similar headers.",
            },
            {
                "action": "validate_escalation",
                "description": "If response is 200/201 and contains sensitive admin data or state change succeeds, BFLA is confirmed.",
            }
        ]
    ),
    
    "mass_assignment_account_takeover": AttackPattern(
        id="mass_assignment_account_takeover",
        name="Mass Assignment to Account Takeover",
        description="Injects unexpected fields (e.g., 'role':'admin' or 'is_admin':true) during object creation or update.",
        impact="high",
        required_signals=["schema_inconsistency"],
        optional_signals=["hidden_param"],
        execution_steps=[
            {
                "action": "identify_update_endpoint",
                "description": "Identify POST/PUT/PATCH endpoint for user or object updates.",
            },
            {
                "action": "inject_privilege_fields",
                "description": "Inject privilege-escalation fields (e.g., {\"role\": \"admin\", \"is_admin\": true}) into the payload.",
            },
            {
                "action": "validate_mass_assignment",
                "description": "Check if the server accepted the fields (e.g., by fetching the object again or checking response).",
            }
        ]
    ),
    
    "jwt_alg_confusion": AttackPattern(
        id="jwt_alg_confusion",
        name="JWT Algorithm Confusion / None Auth Bypass",
        description="Manipulates JWT tokens to bypass authentication (e.g., setting 'alg' to 'none' or modifying payload).",
        impact="critical",
        required_signals=["broken_authentication_with_data_leak"],
        optional_signals=[],
        execution_steps=[
            {
                "action": "extract_jwt",
                "description": "Extract JWT from Authorization header or cookies.",
            },
            {
                "action": "forge_none_jwt",
                "description": "Modify header 'alg' to 'none', strip signature, and optionally elevate claims (e.g., 'sub': 'admin').",
            },
            {
                "action": "send_forged_jwt",
                "description": "Send request to protected endpoint with forged JWT.",
            },
            {
                "action": "validate_jwt_bypass",
                "description": "If response is 200 and returns protected data, bypass is confirmed.",
            }
        ]
    ),
    
    "race_condition_state_corruption": AttackPattern(
        id="race_condition_state_corruption",
        name="Race Condition (State Corruption)",
        description="Sends highly concurrent requests to exploit TOCTOU (Time-of-Check to Time-of-Use) logic flaws.",
        impact="high",
        required_signals=["fragile_endpoint"],
        optional_signals=[],
        execution_steps=[
            {
                "action": "identify_state_change_endpoint",
                "description": "Identify an endpoint that changes state (e.g., transfer funds, apply discount, claim item).",
            },
            {
                "action": "send_concurrent_burst",
                "description": "Send 10-20 requests simultaneously using asyncio.gather.",
            },
            {
                "action": "validate_race_condition",
                "description": "Analyze responses. If multiple requests succeed when only one should have, race condition is confirmed.",
            }
        ]
    )
}
