# API RIPPER v4.0

> **Advanced Autonomous API Security Scanner Platform**
> Created by **Ayush Sharma** | Frontend: React + TypeScript + Ant Design | Backend: FastAPI + ARSec v4.0 Engine

⚠️ **Attribution Notice:** This project is created and maintained by **Ayush Sharma**. If you use, fork, or distribute this project, you must retain the original author attribution. Removal of the "Developed by Ayush Sharma" watermark or the About page is not permitted.

---

## ⚡ Quick Start

### Option 1: PowerShell Script (recommended)
```powershell
cd "API RIPPER"
.\start.ps1
```

### Option 2: Manual Start

**Terminal 1 — Backend:**
```bash
cd "API RIPPER"
python -m venv venv
.\venv\Scripts\activate (for widnwos users only)
source venv/bin/activate (for linux & mac users only)
pip install -r backend/requirements.txt
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

**Terminal 2 — Frontend:**
```bash
cd "API RIPPER/frontend"
npm install
npm run dev
```

### Access
- **Web UI:** http://localhost:5173
- **API Docs:** http://127.0.0.1:8000/docs
- **Health Check:** http://127.0.0.1:8000/health

---

## 🏗️ Architecture

```
API RIPPER/
├── backend/                      # FastAPI + ARSec Scanner Engine
│   ├── main.py                   # App entry point
│   ├── config.py                 # Settings (pydantic-settings)
│   ├── database.py               # SQLite + SQLAlchemy
│   ├── models.py                 # DB models (Scan, Finding, Endpoint, Report, ExploitChain)
│   ├── routes/                   # REST API routes
│   │   ├── scans.py              # Scan CRUD + execution + graph
│   │   ├── findings.py           # Findings + endpoints
│   │   ├── reports.py            # Reports + compliance
│   │   ├── comparison.py         # Scan comparison
│   │   └── websocket.py          # Real-time scan progress
│   ├── scanner/                  # Scan engine
│   │   ├── orchestrator.py       # 7-phase scan pipeline
│   │   ├── module_registry.py    # 40+ ARSec module registry
│   │   └── result_collector.py   # Output capture & parsing
│   ├── agents/                   # Multi-agent AI pipeline
│   └── arsec_modules/            # ARSec v4.0 scanning modules
│       ├── modules/              # Core (fetch_requests, urltoip)
│       ├── utils/                # Scanners (path_traversal, waf, cms, port)
│       ├── plugins/              # Plugins (robots, favicon, cookies)
│       ├── vuln_db/              # Vulnerability scanners (XSS, SSRF, SQLi, API)
│       ├── exploits/             # Exploit checks (shellshock, f5bigip)
│       ├── parsers/              # Output parsers (nmap, nuclei)
│       └── wordlists/            # Wordlists
└── frontend/                     # React + TypeScript + Vite
    ├── src/
    │   ├── pages/                # 13 pages (Dashboard, Scans, Findings, About, etc.)
    │   ├── components/           # Layout, Sidebar, Header
    │   ├── services/             # API client, WebSocket
    │   └── store/                # Zustand state management
    └── package.json
```

---

## 🔬 Security Modules (13 modules, 70+ techniques)

| Module | Category | Techniques | OWASP Mapping |
|--------|----------|------------|---------------|
| SQL Injection Engine | Injection | Error-based, Union, Blind Boolean, Time-based, OOB, Second-order | API8:2023 |
| XSS Scanner | Injection | Reflected, Stored, DOM, Mutation, CSP Bypass, Template Injection | API8:2023 |
| Authentication Bypass | Auth | JWT alg:none, Key Confusion, Claim Tampering, Session Fixation, OAuth2 | API2:2023 |
| BOLA/IDOR Scanner | AuthZ | Horizontal/Vertical Escalation, UUID Enum, Predictable IDs | API1:2023 |
| BFLA Scanner | AuthZ | Function-Level Bypass, Admin API, Role Manipulation, Method Tampering | API5:2023 |
| SSRF Detector | Server-Side | Internal Discovery, Cloud Metadata, DNS Rebinding, URL Schema Bypass | API8:2023 |
| Rate Limiting Analyzer | Resource | Rate Limit Test, IP/Token Limits, Concurrent Flooding, Resource Exhaust | API4:2023 |
| Mass Assignment Scanner | Data | Property Injection, Nested Object, Array Pollution, Schema Diff | API6:2023 |
| Security Headers Auditor | Config | CORS, CSP, HSTS, X-Frame-Options, Cache-Control, Referrer-Policy | API7:2023 |
| Sensitive Data Exposure | Data | PII Detection, API Key Leak, Stack Trace, Debug Mode, Path Disclosure | API3:2023 |
| WAF Evasion Engine | Advanced | Polymorphic Payloads, Unicode Encoding, Chunked Transfer, Comment Injection | N/A |
| Deep Injection Engine | Advanced | Blind OOB, Time Oracle, DNS Callback, SSTI, NoSQL Injection, LDAP | API8:2023 |
| Cloud Security Auditor | Cloud | S3 Bucket, Azure Blob, GCP Storage, Cloud Metadata, IAM, Serverless | API7:2023 |

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/scans` | Create a new scan |
| `GET` | `/api/v1/scans` | List all scans |
| `GET` | `/api/v1/scans/{id}` | Get scan details |
| `POST` | `/api/v1/scans/{id}/execute` | Start scan execution |
| `GET` | `/api/v1/scans/{id}/progress` | Get scan progress |
| `POST` | `/api/v1/scans/{id}/cancel` | Cancel running scan |
| `DELETE` | `/api/v1/scans/{id}` | Delete scan |
| `GET` | `/api/v1/scans/{id}/findings` | Get findings |
| `GET` | `/api/v1/scans/{id}/endpoints` | Get endpoints |
| `GET` | `/api/v1/scans/{id}/graph` | Get attack chain graph |
| `GET` | `/api/v1/scans/{id}/report` | Get report |
| `GET` | `/api/v1/scans/{id}/compliance` | OWASP compliance |
| `GET` | `/api/v1/stats` | Dashboard stats |
| `WS` | `/ws/scan/{id}` | Live scan progress |

---

## 🛠️ Tech Stack

- **Backend:** Python 3.11+, FastAPI, SQLAlchemy, SQLite, uvicorn
- **Scanner Engine:** ARSec v4.0 (13 security modules, 70+ techniques)
- **Multi-Agent Pipeline:** Behavioral, Inference, Chain, WAF Evasion, Deep Injection agents
- **Frontend:** React 19, TypeScript, Vite 6, Ant Design 5, D3.js, Zustand
- **Real-time:** WebSocket for live scan progress

---

## 👤 Author

**Ayush Sharma** — Security Researcher & Full-Stack Developer

This project is open-source. You may use and modify it, but you **must** retain the original author attribution.

---

*© 2024–2026 Ayush Sharma. All rights reserved.*
