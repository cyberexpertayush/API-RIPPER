"""
API RIPPER v2.0 — Response Classification Engine (Phase 3)
Moves beyond raw HTTP status codes. Classifies responses into semantic
states (e.g., AUTH_REQUIRED, RESOURCE_EXISTS, RATE_LIMITED) to enable
smarter fuzzing, cleaner signals, and better differential intelligence.
"""

import json
import re
from enum import Enum
from typing import Dict, Any, Optional

class ResponseClass(str, Enum):
    SUCCESS = "SUCCESS"                      # 200/201/204 with valid data
    RESOURCE_EXISTS = "RESOURCE_EXISTS"      # Used when checking IDs/emails (e.g. 409 Conflict, or 200 with specific body)
    RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND" # 404, or 200 with empty data
    AUTH_REQUIRED = "AUTH_REQUIRED"          # 401, or 200 with "Please login"
    FORBIDDEN = "FORBIDDEN"                  # 403, missing privileges
    RATE_LIMITED = "RATE_LIMITED"            # 429, or WAF block
    INPUT_REJECTED = "INPUT_REJECTED"        # 400, validation error
    ERROR_STATE = "ERROR_STATE"              # 500, unhandled exception, SQL syntax error
    UNKNOWN = "UNKNOWN"

class ResponseClassifier:
    """Classifies an HTTP response into semantic categories."""
    
    @staticmethod
    def classify(status: int, headers: Dict[str, str], body: str, latency_ms: float) -> ResponseClass:
        body_lower = body.lower()
        
        # 1. Check for explicit error states (Unhandled exceptions)
        error_signatures = ["syntax error", "traceback", "exception", "sql syntax", "stacktrace", "internal server error"]
        if status >= 500 or any(sig in body_lower for sig in error_signatures):
            return ResponseClass.ERROR_STATE
            
        # 2. Check for Rate Limiting / WAF
        if status == 429 or "too many requests" in body_lower or "waf" in headers.get("server", "").lower() or status == 406:
            return ResponseClass.RATE_LIMITED
            
        # 3. Check Authentication / Authorization
        if status == 401 or "unauthorized" in body_lower or "token expired" in body_lower or "please login" in body_lower:
            return ResponseClass.AUTH_REQUIRED
            
        if status == 403 or "forbidden" in body_lower or "access denied" in body_lower:
            return ResponseClass.FORBIDDEN
            
        # 4. Check Resource States
        if status == 404 or "not found" in body_lower:
            return ResponseClass.RESOURCE_NOT_FOUND
            
        if status == 409 or "already exists" in body_lower or "duplicate" in body_lower:
            return ResponseClass.RESOURCE_EXISTS
            
        # 5. Check Input Validation
        if status == 400 or status == 422 or "validation" in body_lower or "invalid" in body_lower:
            return ResponseClass.INPUT_REJECTED
            
        # 6. Success / Data return
        if 200 <= status < 300:
            # Differentiate empty 200 from actual success
            if not body.strip() or body.strip() == "[]" or body.strip() == "{}":
                return ResponseClass.RESOURCE_NOT_FOUND  # Often APIs return 200 [] for no results
            return ResponseClass.SUCCESS
            
        return ResponseClass.UNKNOWN

    @staticmethod
    def extract_error_signature(body: str) -> Optional[str]:
        """Extracts the semantic error signature for clustering (Differential Intel v2)."""
        body_lower = body.lower()
        
        # Look for SQL errors
        if "sql" in body_lower:
            return "sql_error_signature"
            
        # Try to extract the top-level error message from JSON
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                # Common error keys
                for key in ["error", "message", "detail", "msg", "err"]:
                    if key in data:
                        val = data[key]
                        if isinstance(val, str):
                            # Remove dynamic variables (e.g. "User 123 not found" -> "User not found")
                            clean_val = re.sub(r'\d+', '', val)
                            clean_val = re.sub(r'[a-f0-9-]{36}', '', clean_val)
                            return clean_val.strip()[:50]
        except Exception:
            pass
            
        # Fallback to regex for traceback
        match = re.search(r'(Traceback \(most recent call last\):.*?)\n', body, re.IGNORECASE)
        if match:
            return "python_traceback"
            
        match = re.search(r'(java\.lang\.[a-zA-Z]+Exception)', body)
        if match:
            return match.group(1)
            
        return None
