"""
API RIPPER v2.0 — Auth Intelligence Agent (Phase 3)
Deep-dives into authentication mechanisms. Analyzes JWT structures,
token entropy, role-based access mapping, and privilege escalation paths.
"""

import base64
import json
import logging
import math
from typing import Any, Dict, List, Optional

from backend.agents.base_agent import BaseAgent, Finding

logger = logging.getLogger(__name__)

class AuthAgent(BaseAgent):
    """
    Analyzes Authentication tokens, JWT structures, and Authorization headers.
    """
    name = "auth_agent"

    async def observe(self) -> Dict[str, Any]:
        """Step 1: Gather tokens from config and Knowledge Graph."""
        auth_config = self.config.get("auth_config", {})
        bearer_token = auth_config.get("bearer_token")
        
        # We can also pull tokens seen in data flows or headers, but for now we focus on the provided token
        return {
            "bearer_token": bearer_token,
            "endpoints": self.kg.get_all_endpoints()
        }

    async def profile(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Step 2: Deep inspect the JWT or Token."""
        token = data.get("bearer_token")
        profile = {
            "token_type": "unknown",
            "is_jwt": False,
            "jwt_header": None,
            "jwt_payload": None,
            "entropy": 0.0,
            "weaknesses": []
        }

        if not token:
            return profile

        # Check if JWT
        parts = str(token).split(".")
        if len(parts) == 3:
            profile["is_jwt"] = True
            profile["token_type"] = "jwt"
            
            try:
                # Add padding if needed
                header_b64 = parts[0] + "=" * ((4 - len(parts[0]) % 4) % 4)
                payload_b64 = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
                
                profile["jwt_header"] = json.loads(base64.urlsafe_b64decode(header_b64).decode())
                profile["jwt_payload"] = json.loads(base64.urlsafe_b64decode(payload_b64).decode())
                
                # Analyze JWT Weaknesses
                alg = profile["jwt_header"].get("alg", "").lower()
                if alg == "none":
                    profile["weaknesses"].append("jwt_alg_none_supported")
                elif alg.startswith("hs"):
                    profile["weaknesses"].append("jwt_symmetric_signature") # Requires brute force check later

                # Check for sensitive data in payload
                payload_str = str(profile["jwt_payload"]).lower()
                if "password" in payload_str or "secret" in payload_str:
                    profile["weaknesses"].append("jwt_sensitive_data_exposure")
                    
                # Check for explicit roles
                if "role" in profile["jwt_payload"] or "admin" in profile["jwt_payload"]:
                    role_val = profile["jwt_payload"].get("role", "")
                    # Don't blindly assume role=admin means exploitable; verify first
                    if role_val == "admin":
                        profile["weaknesses"].append("jwt_exposes_admin_role_unverified")
                    else:
                        profile["weaknesses"].append("jwt_exposes_privileges")
                    self.kg.update_tech_profile({"auth_roles_in_jwt": True}, self.name, 1.0)
                    
            except Exception as e:
                logger.warning(f"[auth_agent] Failed to parse JWT: {e}")
        else:
            # Standard opaque token analysis
            profile["token_type"] = "opaque"
            profile["entropy"] = self._calculate_entropy(token)
            
            # Prevent false positives on short string entropy
            if len(token) >= 16 and profile["entropy"] < 3.5:
                # Also ensure it's not just a standard UUID or base64 structure which might have lower naive entropy
                if "-" not in token:
                    profile["weaknesses"].append("low_token_entropy")

        self.kg.update_tech_profile({"auth_profile": profile}, self.name, 0.9)
        return profile

    async def differential_analyze(self, profile: Dict[str, Any]) -> List[Dict]:
        """Step 3: Correlate token weaknesses with endpoints."""
        anomalies = []
        for weakness in profile.get("weaknesses", []):
            anomalies.append({
                "type": weakness,
                "profile": profile
            })
        return anomalies

    async def infer(self, anomalies: List[Dict]) -> List[Finding]:
        """Step 4: Emit findings for auth weaknesses."""
        findings = []
        
        for anomaly in anomalies:
            weakness = anomaly["type"]
            profile = anomaly["profile"]
            
            if weakness == "jwt_alg_none_supported":
                findings.append(Finding(
                    type="jwt_alg_none",
                    title="JWT 'alg: none' Vulnerability Risk",
                    description="The application uses JWTs. The 'alg: none' attack should be attempted to bypass signature verification.",
                    severity="critical",
                    confidence=0.8,
                    endpoint="global",
                    cwe="CWE-287",
                    owasp="API2:2023",
                    evidence=[{"jwt_header": profile["jwt_header"]}]
                ))
                self.emit_signal("JWT_WEAKNESS", {"type": "alg_none"}, confidence=0.8, target="exploit_agent")
                
            elif weakness == "jwt_sensitive_data_exposure":
                findings.append(Finding(
                    type="jwt_data_exposure",
                    title="Sensitive Data Exposed in JWT Payload",
                    description="The JWT payload contains sensitive keys (e.g., password, secret). JWTs are base64 encoded, not encrypted, meaning anyone who captures the token can read this data.",
                    severity="high",
                    confidence=0.9,
                    endpoint="global",
                    cwe="CWE-312",
                    owasp="API3:2023",
                    evidence=[{"jwt_payload": profile["jwt_payload"]}]
                ))

            elif weakness == "low_token_entropy":
                findings.append(Finding(
                    type="low_token_entropy",
                    title="Low Token Entropy Detected",
                    description=f"The authentication token has low entropy ({profile['entropy']:.2f}). This makes it susceptible to brute-force or prediction attacks.",
                    severity="high",
                    confidence=0.8,
                    endpoint="global",
                    cwe="CWE-330",
                    owasp="API2:2023",
                    evidence=[{"entropy": profile["entropy"]}]
                ))

        return findings

    def _calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not data:
            return 0.0
        entropy = 0
        for x in set(data):
            p_x = float(data.count(x)) / len(data)
            entropy += - p_x * math.log2(p_x)
        return entropy
