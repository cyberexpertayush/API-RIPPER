/* ============================================================
   Settings — Configuration, Connection Status & Technique Analyzer
   v4.0 — Upgraded with comprehensive security module matrix
   ============================================================ */

import React, { useState, useEffect } from 'react';
import { Input, Switch, Button, Tag, Descriptions, message, Progress, Tooltip, Badge } from 'antd';
import {
  SettingOutlined,
  ApiOutlined,
  LinkOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  SyncOutlined,
  SafetyCertificateOutlined,
  ThunderboltOutlined,
  BugOutlined,
  LockOutlined,
  ExperimentOutlined,
  CloudOutlined,
  CodeOutlined,
  UserOutlined,
  GlobalOutlined,
} from '@ant-design/icons';
import { websocketService } from '@/services/websocketService';

/* ─── Security Module Definitions ─────────────────────────── */
interface SecurityModule {
  name: string;
  category: string;
  icon: React.ReactNode;
  techniques: string[];
  owaspMapping: string;
  status: 'active' | 'passive' | 'experimental';
  version: string;
}

const SECURITY_MODULES: SecurityModule[] = [
  {
    name: 'SQL Injection Engine',
    category: 'Injection',
    icon: <BugOutlined />,
    techniques: ['Error-based SQLi', 'Union-based SQLi', 'Blind Boolean SQLi', 'Time-based Blind SQLi', 'Out-of-Band SQLi', 'Second-order SQLi'],
    owaspMapping: 'API8:2023',
    status: 'active',
    version: '3.8',
  },
  {
    name: 'XSS Scanner',
    category: 'Injection',
    icon: <CodeOutlined />,
    techniques: ['Reflected XSS', 'Stored XSS', 'DOM-based XSS', 'Mutation XSS', 'CSP Bypass Vectors', 'Template Injection to XSS'],
    owaspMapping: 'API8:2023',
    status: 'active',
    version: '3.8',
  },
  {
    name: 'Authentication Bypass',
    category: 'Authentication',
    icon: <LockOutlined />,
    techniques: ['JWT Algorithm Confusion (alg:none)', 'JWT Key Confusion (RS256→HS256)', 'JWT Claim Tampering', 'Session Fixation', 'Credential Stuffing Detection', 'OAuth2 Flow Abuse'],
    owaspMapping: 'API2:2023',
    status: 'active',
    version: '3.8',
  },
  {
    name: 'BOLA/IDOR Scanner',
    category: 'Authorization',
    icon: <UserOutlined />,
    techniques: ['Horizontal Privilege Escalation', 'Vertical Privilege Escalation', 'Object-Level Authorization Bypass', 'UUID/ID Enumeration', 'Predictable Resource ID'],
    owaspMapping: 'API1:2023',
    status: 'active',
    version: '3.8',
  },
  {
    name: 'BFLA Scanner',
    category: 'Authorization',
    icon: <SafetyCertificateOutlined />,
    techniques: ['Function-Level Authorization Bypass', 'Admin API Access', 'Role Manipulation', 'Method Tampering (GET→PUT)', 'Hidden Admin Endpoints'],
    owaspMapping: 'API5:2023',
    status: 'active',
    version: '3.8',
  },
  {
    name: 'SSRF Detector',
    category: 'Server-Side',
    icon: <GlobalOutlined />,
    techniques: ['Internal Service Discovery', 'Cloud Metadata (169.254.169.254)', 'DNS Rebinding', 'URL Schema Bypass (file://, gopher://)', 'Redirect-based SSRF'],
    owaspMapping: 'API8:2023',
    status: 'active',
    version: '3.8',
  },
  {
    name: 'Rate Limiting Analyzer',
    category: 'Resource',
    icon: <ThunderboltOutlined />,
    techniques: ['Endpoint Rate Limit Testing', 'IP-based vs Token-based Limits', 'Concurrent Request Flooding', 'Resource Exhaustion Detection', 'Retry-After Header Analysis'],
    owaspMapping: 'API4:2023',
    status: 'active',
    version: '3.8',
  },
  {
    name: 'Mass Assignment Scanner',
    category: 'Data',
    icon: <ExperimentOutlined />,
    techniques: ['Property Injection (role, isAdmin)', 'Nested Object Manipulation', 'Array Parameter Pollution', 'Hidden Field Discovery', 'Schema Diff Analysis'],
    owaspMapping: 'API6:2023',
    status: 'active',
    version: '3.8',
  },
  {
    name: 'Security Headers Auditor',
    category: 'Configuration',
    icon: <SafetyCertificateOutlined />,
    techniques: ['CORS Misconfiguration', 'CSP Policy Analysis', 'HSTS Enforcement Check', 'X-Frame-Options Validation', 'Cache-Control Audit', 'Referrer-Policy Check'],
    owaspMapping: 'API7:2023',
    status: 'passive',
    version: '3.8',
  },
  {
    name: 'Sensitive Data Exposure',
    category: 'Data',
    icon: <BugOutlined />,
    techniques: ['PII Detection (SSN, Credit Card)', 'API Key Leakage', 'Stack Trace Exposure', 'Debug Mode Detection', 'Verbose Error Analysis', 'Internal Path Disclosure'],
    owaspMapping: 'API3:2023',
    status: 'passive',
    version: '3.8',
  },
  {
    name: 'WAF Evasion Engine',
    category: 'Advanced',
    icon: <ThunderboltOutlined />,
    techniques: ['Polymorphic Payload Synthesis', 'Unicode/URL Encoding Chains', 'Chunked Transfer Encoding', 'Comment Injection Bypass', 'Case Mutation', 'Double-URL Encoding'],
    owaspMapping: 'N/A',
    status: 'active',
    version: '4.0',
  },
  {
    name: 'Deep Injection Engine',
    category: 'Advanced',
    icon: <ExperimentOutlined />,
    techniques: ['Blind OOB Detection', 'Time-based Oracle', 'DNS Callback Verification', 'SSTI (Jinja2/Twig/Freemarker)', 'NoSQL Injection', 'LDAP Injection'],
    owaspMapping: 'API8:2023',
    status: 'active',
    version: '4.0',
  },
  {
    name: 'Cloud Security Auditor',
    category: 'Cloud',
    icon: <CloudOutlined />,
    techniques: ['S3 Bucket Misconfiguration', 'Azure Blob Public Access', 'GCP Storage ACL Check', 'Cloud Metadata SSRF', 'IAM Misconfiguration Signals', 'Serverless Function Probing'],
    owaspMapping: 'API7:2023',
    status: 'experimental',
    version: '4.0',
  },
];

const OWASP_API_TOP10 = [
  { id: 'API1:2023', name: 'Broken Object Level Authorization', color: '#ff4757' },
  { id: 'API2:2023', name: 'Broken Authentication', color: '#ff4757' },
  { id: 'API3:2023', name: 'Broken Object Property Level Auth', color: '#ff8c42' },
  { id: 'API4:2023', name: 'Unrestricted Resource Consumption', color: '#ff8c42' },
  { id: 'API5:2023', name: 'Broken Function Level Authorization', color: '#ffc312' },
  { id: 'API6:2023', name: 'Unrestricted Access to Sensitive Business Flows', color: '#ffc312' },
  { id: 'API7:2023', name: 'Server Side Request Forgery', color: '#ffc312' },
  { id: 'API8:2023', name: 'Security Misconfiguration', color: '#3b82f6' },
  { id: 'API9:2023', name: 'Improper Inventory Management', color: '#3b82f6' },
  { id: 'API10:2023', name: 'Unsafe Consumption of APIs', color: '#a855f7' },
];

const STATUS_COLORS = {
  active: '#00e87b',
  passive: '#3b82f6',
  experimental: '#a855f7',
};

const Settings: React.FC = () => {
  const [apiUrl] = useState('/api/v1 (proxied to http://127.0.0.1:8000)');
  const [wsUrl] = useState('/ws (proxied to ws://127.0.0.1:8000)');
  const [backendStatus, setBackendStatus] = useState<'checking' | 'online' | 'offline'>('checking');
  const [expandedModule, setExpandedModule] = useState<string | null>(null);
  const [showOwaspMap, setShowOwaspMap] = useState(false);

  const checkBackendHealth = async () => {
    setBackendStatus('checking');
    try {
      const response = await fetch('/health', { signal: AbortSignal.timeout(5000) });
      setBackendStatus(response.ok ? 'online' : 'offline');
    } catch {
      setBackendStatus('offline');
    }
  };

  useEffect(() => { checkBackendHealth(); }, []);

  const totalTechniques = SECURITY_MODULES.reduce((acc, m) => acc + m.techniques.length, 0);
  const activeModules = SECURITY_MODULES.filter((m) => m.status === 'active').length;
  const categories = [...new Set(SECURITY_MODULES.map((m) => m.category))];

  return (
    <div className="fade-in">
      <div className="page-header">
        <h1><SettingOutlined style={{ marginRight: 8 }} />Settings & Analyzer</h1>
        <p>Configure backend connection, review security modules and OWASP API Top 10 coverage</p>
      </div>

      <div style={{ maxWidth: 960, display: 'flex', flexDirection: 'column', gap: 'var(--space-6)' }}>

        {/* ── Connection Status ──────────────────────────────── */}
        <div className="card">
          <h3 className="section-title"><ApiOutlined /> Backend Connection</h3>
          <Descriptions column={1} size="small" labelStyle={{ color: 'var(--text-tertiary)', fontWeight: 600 }} contentStyle={{ color: 'var(--text-primary)' }}>
            <Descriptions.Item label="Backend Status">
              {backendStatus === 'checking' ? (
                <Tag icon={<SyncOutlined spin />} color="processing">Checking...</Tag>
              ) : backendStatus === 'online' ? (
                <Tag icon={<CheckCircleOutlined />} color="success">Online</Tag>
              ) : (
                <Tag icon={<CloseCircleOutlined />} color="error">Offline</Tag>
              )}
            </Descriptions.Item>
            <Descriptions.Item label="WebSocket">
              {websocketService.isConnected ? (
                <Tag icon={<CheckCircleOutlined />} color="success">Connected</Tag>
              ) : (
                <Tag icon={<CloseCircleOutlined />} color="default">Disconnected</Tag>
              )}
            </Descriptions.Item>
            <Descriptions.Item label="API Endpoint">
              <span className="mono" style={{ fontSize: 'var(--text-xs)' }}>{apiUrl}</span>
            </Descriptions.Item>
            <Descriptions.Item label="WebSocket Endpoint">
              <span className="mono" style={{ fontSize: 'var(--text-xs)' }}>{wsUrl}</span>
            </Descriptions.Item>
            <Descriptions.Item label="Health Check">
              <span className="mono" style={{ fontSize: 'var(--text-xs)' }}>/health (proxied to http://127.0.0.1:8000/health)</span>
            </Descriptions.Item>
          </Descriptions>
          <Button type="default" icon={<SyncOutlined />} onClick={checkBackendHealth} style={{ marginTop: 'var(--space-3)' }}>
            Test Connection
          </Button>
        </div>

        {/* ── Engine Stats ───────────────────────────────────── */}
        <div className="stats-grid">
          <div className="stat-card">
            <span className="stat-label">Security Modules</span>
            <span className="stat-value">{SECURITY_MODULES.length}</span>
          </div>
          <div className="stat-card">
            <span className="stat-label">Active Modules</span>
            <span className="stat-value" style={{ color: 'var(--accent-primary)' }}>{activeModules}</span>
          </div>
          <div className="stat-card">
            <span className="stat-label">Total Techniques</span>
            <span className="stat-value">{totalTechniques}</span>
          </div>
          <div className="stat-card">
            <span className="stat-label">OWASP Coverage</span>
            <span className="stat-value" style={{ color: 'var(--accent-secondary)' }}>
              {OWASP_API_TOP10.filter((o) => SECURITY_MODULES.some((m) => m.owaspMapping === o.id)).length}/10
            </span>
          </div>
        </div>

        {/* ── Security Module Analyzer ───────────────────────── */}
        <div className="card">
          <h3 className="section-title" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span><SafetyCertificateOutlined /> Security Technique Analyzer</span>
            <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
              {Object.entries(STATUS_COLORS).map(([status, color]) => (
                <Tag key={status} style={{ borderRadius: 12 }} color={color}>
                  {status === 'active' ? '● Active' : status === 'passive' ? '○ Passive' : '◇ Experimental'}
                </Tag>
              ))}
            </div>
          </h3>

          {categories.map((category) => (
            <div key={category} style={{ marginBottom: 'var(--space-4)' }}>
              <div style={{
                fontSize: 'var(--text-xs)', fontWeight: 700, color: 'var(--text-tertiary)',
                textTransform: 'uppercase', letterSpacing: '0.08em',
                marginBottom: 'var(--space-2)', paddingBottom: 'var(--space-1)',
                borderBottom: '1px solid var(--border-subtle)',
              }}>
                {category}
              </div>

              {SECURITY_MODULES.filter((m) => m.category === category).map((mod) => (
                <div
                  key={mod.name}
                  style={{
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-sm)',
                    marginBottom: 'var(--space-2)',
                    overflow: 'hidden',
                    transition: 'border-color 200ms',
                    borderColor: expandedModule === mod.name ? 'var(--accent-primary)' : undefined,
                  }}
                >
                  <div
                    onClick={() => setExpandedModule(expandedModule === mod.name ? null : mod.name)}
                    style={{
                      display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                      padding: 'var(--space-2) var(--space-3)',
                      cursor: 'pointer', background: 'var(--bg-surface)',
                      transition: 'background 150ms',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                      <span style={{ color: STATUS_COLORS[mod.status], fontSize: 16 }}>{mod.icon}</span>
                      <span style={{ fontWeight: 600, fontSize: 'var(--text-sm)' }}>{mod.name}</span>
                      <Tag style={{ borderRadius: 12, fontSize: 10, lineHeight: '16px', padding: '0 6px' }} color={STATUS_COLORS[mod.status]}>
                        {mod.status}
                      </Tag>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                      <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)' }}>
                        {mod.techniques.length} techniques
                      </span>
                      <Tag style={{ fontSize: 10, borderRadius: 4 }}>{mod.owaspMapping}</Tag>
                      <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)' }}>v{mod.version}</span>
                    </div>
                  </div>

                  {expandedModule === mod.name && (
                    <div style={{ padding: 'var(--space-3)', background: 'var(--bg-card)', borderTop: '1px solid var(--border-subtle)' }}>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-2)' }}>
                        {mod.techniques.map((tech) => (
                          <Tag
                            key={tech}
                            style={{
                              borderRadius: 12,
                              background: 'var(--bg-hover)',
                              border: '1px solid var(--border-subtle)',
                              padding: '2px 10px',
                              fontSize: 'var(--text-xs)',
                            }}
                          >
                            {tech}
                          </Tag>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          ))}
        </div>

        {/* ── OWASP API Top 10 Coverage ──────────────────────── */}
        <div className="card">
          <h3 className="section-title"><SafetyCertificateOutlined /> OWASP API Security Top 10 (2023) Coverage</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
            {OWASP_API_TOP10.map((item) => {
              const coveredModules = SECURITY_MODULES.filter((m) => m.owaspMapping === item.id);
              const isCovered = coveredModules.length > 0;
              return (
                <div
                  key={item.id}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 'var(--space-3)',
                    padding: 'var(--space-2) var(--space-3)',
                    borderRadius: 'var(--radius-sm)',
                    border: `1px solid ${isCovered ? 'rgba(0,232,123,0.2)' : 'var(--border-subtle)'}`,
                    background: isCovered ? 'rgba(0,232,123,0.04)' : 'transparent',
                  }}
                >
                  {isCovered ? (
                    <CheckCircleOutlined style={{ color: '#00e87b', fontSize: 16, flexShrink: 0 }} />
                  ) : (
                    <CloseCircleOutlined style={{ color: 'var(--text-tertiary)', fontSize: 16, flexShrink: 0 }} />
                  )}
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                      <Tag style={{ borderRadius: 4, fontSize: 10, fontWeight: 700, fontFamily: 'var(--font-mono)' }} color={item.color}>
                        {item.id}
                      </Tag>
                      <span style={{ fontSize: 'var(--text-sm)', fontWeight: 500 }}>{item.name}</span>
                    </div>
                    {isCovered && (
                      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', marginTop: 2 }}>
                        Covered by: {coveredModules.map((m) => m.name).join(', ')}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* ── API Configuration ──────────────────────────────── */}
        <div className="card">
          <h3 className="section-title"><LinkOutlined /> API Configuration</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
            <div>
              <label style={{ display: 'block', fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', marginBottom: 'var(--space-2)', fontWeight: 600 }}>
                API Base URL
              </label>
              <Input
                value={apiUrl}
                placeholder="http://127.0.0.1:8000/api/v1"
                disabled
              />
              <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', marginTop: 4, display: 'block' }}>
                Configured via VITE_API_BASE environment variable. Default: http://127.0.0.1:8000/api/v1
              </span>
            </div>
            <div>
              <label style={{ display: 'block', fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', marginBottom: 'var(--space-2)', fontWeight: 600 }}>
                WebSocket URL
              </label>
              <Input
                value={wsUrl}
                placeholder="ws://127.0.0.1:8000"
                disabled
              />
              <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', marginTop: 4, display: 'block' }}>
                WebSocket server for real-time scan updates. Default: ws://127.0.0.1:8000
              </span>
            </div>
          </div>
        </div>

        {/* ── About ──────────────────────────────────────────── */}
        <div className="card">
          <h3 className="section-title"><SettingOutlined /> About</h3>
          <Descriptions column={1} size="small" labelStyle={{ color: 'var(--text-tertiary)', fontWeight: 600 }} contentStyle={{ color: 'var(--text-primary)' }}>
            <Descriptions.Item label="Application">API RIPPER — Advanced API Security Scanner</Descriptions.Item>
            <Descriptions.Item label="Version">4.0.0</Descriptions.Item>
            <Descriptions.Item label="Scanner Engine">ARSec v4.0 ({SECURITY_MODULES.length} security modules, {totalTechniques} techniques)</Descriptions.Item>
            <Descriptions.Item label="Frontend">React 19 + TypeScript + Vite + Zustand + Ant Design 5</Descriptions.Item>
            <Descriptions.Item label="Backend">FastAPI + SQLAlchemy + SQLite + WebSocket + Multi-Agent Pipeline</Descriptions.Item>
            <Descriptions.Item label="Created By">
              <span style={{ color: 'var(--accent-primary)', fontWeight: 600 }}>Ayush Sharma</span>
            </Descriptions.Item>
          </Descriptions>
        </div>
      </div>
    </div>
  );
};

export default Settings;
