"""
API RIPPER — Module Registry
Maps ARSec scanning modules to callable functions with metadata.
"""

import logging
from typing import Dict, List, Callable, Any

logger = logging.getLogger(__name__)


class ScanModule:
    """Represents a single scanning module"""

    def __init__(
        self,
        name: str,
        category: str,
        phase: int,
        description: str,
        callable_fn: Callable = None,
        callable_name: str = "",
        import_path: str = "",
        is_async: bool = False,
    ):
        self.name = name
        self.category = category
        self.phase = phase
        self.description = description
        self.callable_fn = callable_fn
        self.callable_name = callable_name
        self.import_path = import_path
        self.is_async = is_async


# ============================================================
# Module definitions — organized by scan phase
# ============================================================

PHASE_NAMES = {
    1: "Reconnaissance",
    2: "Fingerprinting",
    3: "Discovery",
    4: "Vulnerability Scanning",
    5: "API Security Testing",
    6: "Advanced Analysis",
    7: "Exploit Verification",
}

MODULE_DEFINITIONS: List[Dict[str, Any]] = [
    # Phase 1 — Reconnaissance
    {
        "name": "fetch_requests",
        "category": "Reconnaissance",
        "phase": 1,
        "description": "HTTP request analysis and response inspection",
        "import_path": "backend.arsec_modules.modules.fetch_requests",
        "callable_name": "do_requests",
    },
    {
        "name": "urltoip",
        "category": "Reconnaissance",
        "phase": 1,
        "description": "URL to IP resolution",
        "import_path": "backend.arsec_modules.modules.urltoip",
        "callable_name": "get_ip",
    },
    {
        "name": "geolocation",
        "category": "Reconnaissance",
        "phase": 1,
        "description": "IP geolocation scanning",
        "import_path": "backend.arsec_modules.plugins.geolocation",
        "callable_name": "scan_ip",
    },

    # Phase 2 — Fingerprinting
    {
        "name": "headers",
        "category": "Fingerprinting",
        "phase": 2,
        "description": "HTTP header analysis",
        "import_path": "backend.arsec_modules.utils.headers",
        "callable_name": "get_headers",
    },
    {
        "name": "techscanner",
        "category": "Fingerprinting",
        "phase": 2,
        "description": "Technology stack detection",
        "import_path": "backend.arsec_modules.utils.techscanner",
        "callable_name": "Tech",
    },
    {
        "name": "cmsscanner",
        "category": "Fingerprinting",
        "phase": 2,
        "description": "CMS identification and misconfiguration scanning",
        "import_path": "backend.arsec_modules.utils.cmsscanner",
        "callable_name": "main",
    },
    {
        "name": "wafscanner",
        "category": "Fingerprinting",
        "phase": 2,
        "description": "WAF detection and fingerprinting",
        "import_path": "backend.arsec_modules.utils.wafscanner",
        "callable_name": "main",
    },
    {
        "name": "phpcheck",
        "category": "Fingerprinting",
        "phase": 2,
        "description": "PHP identification",
        "import_path": "backend.arsec_modules.plugins.phpcheck",
        "callable_name": "php_ident",
    },
    {
        "name": "optionscheck",
        "category": "Fingerprinting",
        "phase": 2,
        "description": "HTTP OPTIONS method analysis",
        "import_path": "backend.arsec_modules.plugins.optionscheck",
        "callable_name": "Get_Options",
    },

    # Phase 3 — Discovery
    {
        "name": "crawler",
        "category": "Discovery",
        "phase": 3,
        "description": "Web crawler for endpoint discovery",
        "import_path": "backend.arsec_modules.utils.crawler",
        "callable_name": "scan",
    },
    {
        "name": "robots",
        "category": "Discovery",
        "phase": 3,
        "description": "robots.txt analysis",
        "import_path": "backend.arsec_modules.plugins.robots",
        "callable_name": "robots_scan",
    },
    {
        "name": "sitemap",
        "category": "Discovery",
        "phase": 3,
        "description": "Sitemap analysis",
        "import_path": "backend.arsec_modules.plugins.sitemap",
        "callable_name": "sitemap",
    },
    {
        "name": "source",
        "category": "Discovery",
        "phase": 3,
        "description": "Page source analysis",
        "import_path": "backend.arsec_modules.utils.source",
        "callable_name": "page_source",
    },
    {
        "name": "param_finder",
        "category": "Discovery",
        "phase": 3,
        "description": "Parameter discovery",
        "import_path": "backend.arsec_modules.utils.param_finder",
        "callable_name": "get_params",
    },
    {
        "name": "javascript_scanner",
        "category": "Discovery",
        "phase": 3,
        "description": "JavaScript file analysis for endpoints and secrets",
        "import_path": "backend.arsec_modules.utils.javascript_scanner",
        "callable_name": "spider",
    },
    {
        "name": "auth_tokens",
        "category": "Discovery",
        "phase": 3,
        "description": "Authentication token leak detection",
        "import_path": "backend.arsec_modules.plugins.auth_tokens",
        "callable_name": "auth_tokens",
    },
    {
        "name": "cookies_check",
        "category": "Discovery",
        "phase": 3,
        "description": "Cookie security analysis",
        "import_path": "backend.arsec_modules.plugins.cookies_check",
        "callable_name": "phpsessid_session",
    },
    {
        "name": "favicon",
        "category": "Discovery",
        "phase": 3,
        "description": "Favicon hash identification",
        "import_path": "backend.arsec_modules.plugins.favicon",
        "callable_name": "favicon_hash",
    },

    # Phase 4 — Vulnerability Scanning
    {
        "name": "corsmisconfig",
        "category": "Vulnerability Scanning",
        "phase": 4,
        "description": "CORS misconfiguration detection",
        "import_path": "backend.arsec_modules.vuln_db.corsmisconfig",
        "callable_name": "cors_scan",
    },
    {
        "name": "hostheader_injection",
        "category": "Vulnerability Scanning",
        "phase": 4,
        "description": "Host header injection testing",
        "import_path": "backend.arsec_modules.vuln_db.hostheader_injection",
        "callable_name": "host_header_injection",
    },
    {
        "name": "xss",
        "category": "Vulnerability Scanning",
        "phase": 4,
        "description": "Cross-Site Scripting (XSS) scanning",
        "import_path": "backend.arsec_modules.vuln_db.xss",
        "callable_name": "scan",
    },
    {
        "name": "openredirect",
        "category": "Vulnerability Scanning",
        "phase": 4,
        "description": "Open redirect detection",
        "import_path": "backend.arsec_modules.vuln_db.openredirect",
        "callable_name": "scan",
    },
    {
        "name": "path_traversal",
        "category": "Vulnerability Scanning",
        "phase": 4,
        "description": "Path traversal vulnerability scanning",
        "import_path": "backend.arsec_modules.utils.path_traversal",
        "callable_name": "path_traversal_scan",
    },
    {
        "name": "crossdomain",
        "category": "Vulnerability Scanning",
        "phase": 4,
        "description": "Crossdomain.xml misconfiguration",
        "import_path": "backend.arsec_modules.vuln_db.crossdomain",
        "callable_name": "crossdomain_misconfig",
    },
    {
        "name": "head_vuln",
        "category": "Vulnerability Scanning",
        "phase": 4,
        "description": "HEAD method authentication bypass",
        "import_path": "backend.arsec_modules.vuln_db.head_vuln",
        "callable_name": "head_auth_bypass",
    },
    {
        "name": "cache_poisoning",
        "category": "Vulnerability Scanning",
        "phase": 4,
        "description": "Cache poisoning / DoS detection",
        "import_path": "backend.arsec_modules.vuln_db.cache_poisoning",
        "callable_name": "cache_dos_scan",
    },
    {
        "name": "broken_links",
        "category": "Vulnerability Scanning",
        "phase": 4,
        "description": "Broken link analysis",
        "import_path": "backend.arsec_modules.vuln_db.broken_links",
        "callable_name": "scan",
    },
    {
        "name": "webservers_vulns",
        "category": "Vulnerability Scanning",
        "phase": 4,
        "description": "Web server vulnerability scanning",
        "import_path": "backend.arsec_modules.vuln_db.webservers_vulns",
        "callable_name": "Servers_scan",
    },

    # Phase 5 — API Security Testing
    {
        "name": "api_scanner",
        "category": "API Security",
        "phase": 5,
        "description": "Swagger/OpenAPI detection",
        "import_path": "backend.arsec_modules.utils.api_scanner",
        "callable_name": "swagger_ui",
    },
    {
        "name": "api_fuzzer",
        "category": "API Security",
        "phase": 5,
        "description": "API endpoint fuzzing",
        "import_path": "backend.arsec_modules.utils.api_fuzzer",
        "callable_name": "main",
    },
    {
        "name": "api_security",
        "category": "API Security",
        "phase": 5,
        "description": "Comprehensive API security testing (BOLA, verb tampering, mass assignment, rate limiting)",
        "import_path": "backend.arsec_modules.vuln_db.api_security",
        "callable_name": "api_security_scan",
    },
    {
        "name": "graphql_security",
        "category": "API Security",
        "phase": 5,
        "description": "GraphQL security testing (introspection, depth DoS, auth bypass)",
        "import_path": "backend.arsec_modules.vuln_db.graphql_security",
        "callable_name": "graphql_security_scan",
    },

    # Phase 6 — Advanced Analysis
    {
        "name": "cloud_security",
        "category": "Advanced Analysis",
        "phase": 6,
        "description": "Cloud misconfiguration scanning (AWS, Azure, GCP)",
        "import_path": "backend.arsec_modules.vuln_db.cloud_security",
        "callable_name": "cloud_security_scan",
    },
    {
        "name": "request_smuggling",
        "category": "Advanced Analysis",
        "phase": 6,
        "description": "HTTP request smuggling detection",
        "import_path": "backend.arsec_modules.vuln_db.request_smuggling",
        "callable_name": "request_smuggling_scan",
    },
    {
        "name": "session_management",
        "category": "Advanced Analysis",
        "phase": 6,
        "description": "Session management security analysis",
        "import_path": "backend.arsec_modules.vuln_db.session_management",
        "callable_name": "session_management_scan",
    },
    {
        "name": "ssl_scanner",
        "category": "Advanced Analysis",
        "phase": 6,
        "description": "SSL/TLS security analysis",
        "import_path": "backend.arsec_modules.vuln_db.ssl_scanner",
        "callable_name": "ssl_scan",
    },
    {
        "name": "nmap_vuln",
        "category": "Advanced Analysis",
        "phase": 6,
        "description": "Nmap vulnerability scanning",
        "import_path": "backend.arsec_modules.vuln_db.nmap_vuln",
        "callable_name": "vulners_scan",
    },
    {
        "name": "portscanner",
        "category": "Advanced Analysis",
        "phase": 6,
        "description": "Port scanning",
        "import_path": "backend.arsec_modules.utils.portscanner",
        "callable_name": "portscanner",
    },

    # ── NEW: Advanced Security Modules ────────────────────────────

    # Phase 4 — Vulnerability Scanning (new modules)
    {
        "name": "security_headers_analyzer",
        "category": "Vulnerability Scanning",
        "phase": 4,
        "description": "Comprehensive HTTP security headers audit with A+ to F grading (CSP, HSTS, CORS, cookies)",
        "import_path": "backend.arsec_modules.vuln_db.security_headers_analyzer",
        "callable_name": "security_headers_scan",
    },
    {
        "name": "sensitive_data_exposure",
        "category": "Vulnerability Scanning",
        "phase": 4,
        "description": "Deep sensitive data exposure scanning (PII, secrets, stack traces, .env/.git exposure)",
        "import_path": "backend.arsec_modules.vuln_db.sensitive_data_exposure",
        "callable_name": "sensitive_data_scan",
    },

    # Phase 5 — API Security Testing (new modules)
    {
        "name": "jwt_analyzer",
        "category": "API Security",
        "phase": 5,
        "description": "Advanced JWT security analysis (algorithm confusion, key brute-force, claim tampering, kid injection)",
        "import_path": "backend.arsec_modules.vuln_db.jwt_analyzer",
        "callable_name": "jwt_security_scan",
    },
    {
        "name": "rate_limit_tester",
        "category": "API Security",
        "phase": 5,
        "description": "Rate limiting detection with bypass testing (IP spoofing, URL encoding, concurrent exhaustion)",
        "import_path": "backend.arsec_modules.vuln_db.rate_limit_tester",
        "callable_name": "rate_limit_scan",
    },
    {
        "name": "idor_scanner",
        "category": "API Security",
        "phase": 5,
        "description": "Advanced IDOR/BOLA scanner (sequential ID enumeration, response fingerprinting, nested resource testing)",
        "import_path": "backend.arsec_modules.vuln_db.idor_scanner",
        "callable_name": "idor_scan",
    },

    # Phase 7 — Exploit Verification (existing + new)
    {
        "name": "auth_bypass_tester",
        "category": "Exploits",
        "phase": 7,
        "description": "Advanced authentication bypass (header manipulation, verb tampering, path traversal bypass, role injection)",
        "import_path": "backend.arsec_modules.vuln_db.auth_bypass_tester",
        "callable_name": "auth_bypass_scan",
    },
    {
        "name": "f5bigip_scanner",
        "category": "Exploits",
        "phase": 7,
        "description": "F5 BIG-IP vulnerability scanning",
        "import_path": "backend.arsec_modules.exploits.f5bigip_scanner",
        "callable_name": "scan_vuln",
    },
    {
        "name": "shellshock",
        "category": "Exploits",
        "phase": 7,
        "description": "Shellshock vulnerability detection",
        "import_path": "backend.arsec_modules.plugins.shellshock",
        "callable_name": "shellshock_scan",
    },

    # ── NEW v3.0: Modern API Attack Modules ─────────────────────────

    {
        "name": "advanced_jwt_attacks",
        "category": "Modern API Security",
        "phase": 5,
        "description": "Full JWT attack suite: alg:none, weak HMAC brute-force, kid injection (SQLi/path traversal), jku injection, token confusion, expired token bypass, missing signature validation",
        "import_path": "backend.arsec_modules.vuln_db.advanced_jwt_attacks",
        "callable_name": "advanced_jwt_scan",
        "is_async": True,
    },
    {
        "name": "bola_bfla_scanner",
        "category": "Modern API Security",
        "phase": 5,
        "description": "BOLA/IDOR + BFLA + Mass Assignment + Race Condition detection with statistical validation",
        "import_path": "backend.arsec_modules.vuln_db.bola_bfla_scanner",
        "callable_name": "bola_bfla_scan",
        "is_async": True,
    },
    {
        "name": "modern_api_scanner",
        "category": "Modern API Security",
        "phase": 6,
        "description": "Prototype pollution, CORS advanced, deserialization (Java/YAML/PHP/.NET), parameter pollution, HTTP method attacks, CRLF injection, advanced SSRF",
        "import_path": "backend.arsec_modules.vuln_db.modern_api_scanner",
        "callable_name": "modern_vuln_scan",
        "is_async": True,
    },
    {
        "name": "advanced_attack_scanner",
        "category": "Modern API Security",
        "phase": 6,
        "description": "WebSocket attacks, file upload (SVG XSS, extension bypass, XXE via SVG, polyglot), webhook SSRF, LLM prompt injection, API versioning issues, hidden API discovery, XXE",
        "import_path": "backend.arsec_modules.vuln_db.advanced_attack_scanner",
        "callable_name": "advanced_attack_scan",
        "is_async": True,
    },
]


def get_modules_by_phase(phase: int) -> List[Dict]:
    """Get all modules for a given phase"""
    return [m for m in MODULE_DEFINITIONS if m["phase"] == phase]


def get_all_modules() -> List[Dict]:
    """Get all module definitions"""
    return MODULE_DEFINITIONS


def get_module_by_name(name: str) -> Dict:
    """Get module definition by name"""
    for m in MODULE_DEFINITIONS:
        if m["name"] == name:
            return m
    return None
