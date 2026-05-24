/* ============================================================
   Threat Intelligence — OWASP Top 10 heatmap + risk trends
   ============================================================ */

import React, { useEffect, useState } from 'react';
import { Spin, Tag, Tooltip, Progress } from 'antd';
import {
  RadarChartOutlined, AlertOutlined, SafetyCertificateOutlined,
  RiseOutlined, DashboardOutlined,
} from '@ant-design/icons';
import { statsApi } from '@/services/apiClient';

const OWASP_API_TOP_10 = [
  { key: 'API1', name: 'Broken Object Level Authorization', short: 'BOLA', icon: '🔓' },
  { key: 'API2', name: 'Broken Authentication', short: 'BrokenAuth', icon: '🔑' },
  { key: 'API3', name: 'Excessive Data Exposure', short: 'DataExposure', icon: '📤' },
  { key: 'API4', name: 'Lack of Resources & Rate Limiting', short: 'RateLimitng', icon: '⚡' },
  { key: 'API5', name: 'Broken Function Level Authorization', short: 'FuncAuth', icon: '🚪' },
  { key: 'API6', name: 'Mass Assignment', short: 'MassAssign', icon: '📝' },
  { key: 'API7', name: 'Security Misconfiguration', short: 'Misconfig', icon: '⚙️' },
  { key: 'API8', name: 'Injection', short: 'Injection', icon: '💉' },
  { key: 'API9', name: 'Improper Assets Management', short: 'AssetMgmt', icon: '📦' },
  { key: 'API10', name: 'Insufficient Logging & Monitoring', short: 'Logging', icon: '📊' },
];

const ThreatIntelligence: React.FC = () => {
  const [stats, setStats] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    statsApi.get()
      .then((res: any) => setStats(res))
      .catch(() => setStats(null))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div style={{ padding: 40, textAlign: 'center' }}><Spin size="large" /></div>;

  const owaspCoverage = stats?.owasp_coverage || {};
  const riskScore = stats?.risk_score || 0;
  const scanTrend = stats?.scan_trend || [];
  const severityBreakdown = stats?.severity_breakdown || {};

  // Calculate OWASP coverage percentage
  const coveredCategories = OWASP_API_TOP_10.filter(c => (owaspCoverage[c.key] || 0) > 0).length;
  const coveragePercent = Math.round((coveredCategories / 10) * 100);

  // Risk grade
  const riskGrade = riskScore >= 80 ? 'F' : riskScore >= 60 ? 'D' : riskScore >= 40 ? 'C' : riskScore >= 20 ? 'B' : 'A';
  const gradeColor = { A: '#00e87b', B: '#3b82f6', C: '#ffc312', D: '#ff8c42', F: '#ff4757' }[riskGrade] || '#00e87b';

  return (
    <div className="fade-in">
      <div className="page-header">
        <h1><RadarChartOutlined style={{ marginRight: 8 }} />Threat Intelligence</h1>
        <p>OWASP API Top 10 coverage, risk scoring, and vulnerability trends</p>
      </div>

      {/* Top Row — Risk Score + Coverage */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 'var(--space-4)', marginBottom: 'var(--space-5)' }}>
        {/* Risk Score Ring */}
        <div className="card" style={{ textAlign: 'center', padding: 'var(--space-6)' }}>
          <div style={{ position: 'relative', display: 'inline-block' }}>
            <Progress
              type="dashboard"
              percent={100 - riskScore}
              format={() => <span style={{ fontSize: 28, fontWeight: 800, color: gradeColor }}>{riskGrade}</span>}
              strokeColor={gradeColor}
              trailColor="var(--bg-surface)"
              size={160}
              strokeWidth={8}
            />
          </div>
          <div style={{ marginTop: 'var(--space-2)' }}>
            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 600 }}>Security Score</div>
            <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', marginTop: 2 }}>
              Risk Level: <span style={{ color: gradeColor, fontWeight: 700 }}>{riskScore}/100</span>
            </div>
          </div>
        </div>

        {/* OWASP Coverage */}
        <div className="card" style={{ textAlign: 'center', padding: 'var(--space-6)' }}>
          <div style={{ position: 'relative', display: 'inline-block' }}>
            <Progress
              type="dashboard"
              percent={coveragePercent}
              format={() => <span style={{ fontSize: 28, fontWeight: 800, color: 'var(--accent-secondary)' }}>{coveragePercent}%</span>}
              strokeColor="var(--accent-secondary)"
              trailColor="var(--bg-surface)"
              size={160}
              strokeWidth={8}
            />
          </div>
          <div style={{ marginTop: 'var(--space-2)' }}>
            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 600 }}>OWASP Coverage</div>
            <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', marginTop: 2 }}>
              {coveredCategories}/10 categories tested
            </div>
          </div>
        </div>

        {/* Quick Stats */}
        <div className="card" style={{ padding: 'var(--space-5)', display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: 'var(--space-3)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 600 }}>Severity Breakdown</span>
          </div>
          {['critical', 'high', 'medium', 'low', 'info'].map((sev) => {
            const count = severityBreakdown[sev] || 0;
            const max = Math.max(...Object.values(severityBreakdown as Record<string, number>), 1);
            const colors: Record<string, string> = { critical: '#ff4757', high: '#ff8c42', medium: '#ffc312', low: '#00e87b', info: '#3b82f6' };
            return (
              <div key={sev} style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                <span style={{ fontSize: 'var(--text-xs)', fontWeight: 600, textTransform: 'uppercase', width: 60, color: colors[sev] }}>{sev}</span>
                <div style={{ flex: 1, height: 6, background: 'var(--bg-surface)', borderRadius: 3, overflow: 'hidden' }}>
                  <div style={{ width: `${(count / max) * 100}%`, height: '100%', background: colors[sev], borderRadius: 3, transition: 'width 0.5s ease' }} />
                </div>
                <span style={{ fontSize: 'var(--text-xs)', fontWeight: 700, fontFamily: 'var(--font-mono)', width: 28, textAlign: 'right' }}>{count}</span>
              </div>
            );
          })}
        </div>
      </div>

      {/* OWASP API Top 10 Heatmap */}
      <div className="card" style={{ marginBottom: 'var(--space-5)' }}>
        <h3 className="section-title"><SafetyCertificateOutlined style={{ marginRight: 6 }} />OWASP API Security Top 10 — Coverage Heatmap</h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 'var(--space-3)' }}>
          {OWASP_API_TOP_10.map((cat) => {
            const count = owaspCoverage[cat.key] || 0;
            const intensity = Math.min(count / 5, 1);
            const bgColor = count === 0 ? 'rgba(0, 232, 123, 0.08)' : `rgba(255, 71, 87, ${0.1 + intensity * 0.4})`;
            const borderColor = count === 0 ? 'rgba(0, 232, 123, 0.3)' : `rgba(255, 71, 87, ${0.3 + intensity * 0.5})`;
            const textColor = count === 0 ? 'var(--accent-primary)' : '#ff4757';
            return (
              <Tooltip key={cat.key} title={`${cat.name}: ${count} finding(s)`}>
                <div style={{
                  background: bgColor, border: `1px solid ${borderColor}`,
                  borderRadius: 'var(--radius-md)', padding: 'var(--space-4)',
                  textAlign: 'center', cursor: 'pointer',
                  transition: 'all 200ms', position: 'relative',
                }}>
                  <div style={{ fontSize: 24, marginBottom: 'var(--space-1)' }}>{cat.icon}</div>
                  <div style={{ fontSize: 'var(--text-xs)', fontWeight: 700, color: 'var(--text-primary)' }}>{cat.key}</div>
                  <div style={{ fontSize: 10, color: 'var(--text-tertiary)', marginTop: 2 }}>{cat.short}</div>
                  <div style={{
                    position: 'absolute', top: 6, right: 6,
                    fontSize: 10, fontWeight: 800, color: textColor,
                    fontFamily: 'var(--font-mono)',
                  }}>{count}</div>
                </div>
              </Tooltip>
            );
          })}
        </div>
      </div>

      {/* Scan Trend Timeline */}
      {scanTrend.length > 0 && (
        <div className="card">
          <h3 className="section-title"><RiseOutlined style={{ marginRight: 6 }} />Vulnerability Trend (Last {scanTrend.length} Scans)</h3>
          <div style={{ display: 'flex', alignItems: 'flex-end', gap: 'var(--space-2)', height: 160, padding: 'var(--space-2) 0' }}>
            {scanTrend.map((s: any, i: number) => {
              const maxFindings = Math.max(...scanTrend.map((x: any) => x.findings || 0), 1);
              const height = Math.max(((s.findings || 0) / maxFindings) * 130, 4);
              const isLast = i === scanTrend.length - 1;
              return (
                <Tooltip key={s.scan_id} title={`${s.name}: ${s.findings} findings${s.duration ? ` (${s.duration}s)` : ''}`}>
                  <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
                    <span style={{ fontSize: 10, fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>{s.findings}</span>
                    <div style={{
                      width: '100%', maxWidth: 40, height, borderRadius: '4px 4px 0 0',
                      background: isLast ? 'var(--accent-primary)' : 'var(--accent-secondary)',
                      opacity: isLast ? 1 : 0.6,
                      transition: 'height 0.5s ease',
                    }} />
                    <span style={{ fontSize: 9, color: 'var(--text-tertiary)', writingMode: 'vertical-lr', transform: 'rotate(180deg)', maxHeight: 60, overflow: 'hidden' }}>
                      {(s.name || '').substring(0, 12)}
                    </span>
                  </div>
                </Tooltip>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};

export default ThreatIntelligence;
