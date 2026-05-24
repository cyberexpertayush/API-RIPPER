/* ============================================================
   Dashboard — Real-time scan feed + global stats overview
   ============================================================ */

import React, { useEffect, useRef, useState, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { Progress, Empty } from 'antd';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import {
  SecurityScanOutlined,
  ApiOutlined,
  BugOutlined,
  WarningOutlined,
  ThunderboltOutlined,
  RadarChartOutlined,
  LoadingOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  CaretRightOutlined,
} from '@ant-design/icons';
import { useStatsStore, useAssessmentStore } from '@/store';

/* ── Types ────────────────────────────────────────────────── */

interface LiveLine {
  id: number;
  text: string;
  level: string;
  module?: string;
  timestamp: Date;
}

interface ScanProgress {
  status: string;
  phase: number;
  phaseName: string;
  progress: number;
  findingsCount: number;
  endpointsCount: number;
  severityCounts: Record<string, number>;
  modulesRun: number;
  modulesFailed: number;
  totalModules: number;
  targetUrl: string;
  scanName: string;
}

/* ── Constants ────────────────────────────────────────────── */

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ff4757',
  HIGH: '#ff8c42',
  MEDIUM: '#ffc312',
  LOW: '#00e87b',
  INFO: '#3b82f6',
};

const LINE_COLORS: Record<string, string> = {
  finding: '#00e87b',
  success: '#00e87b',
  warning: '#ffc312',
  error: '#ff4757',
  phase: '#a78bfa',
  module_start: '#64748b',
  info: '#8b949e',
};

/* ── Component ────────────────────────────────────────────── */

const Dashboard: React.FC = () => {
  const { stats, fetchStats } = useStatsStore();
  const { assessments, fetchAssessments } = useAssessmentStore();

  // Live feed state
  const [liveLines, setLiveLines] = useState<LiveLine[]>([]);
  const [scanProgress, setScanProgress] = useState<ScanProgress | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [isScanActive, setIsScanActive] = useState(false);
  const terminalRef = useRef<HTMLDivElement>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const lineIdRef = useRef(0);
  const reconnectRef = useRef<number | null>(null);
  const handleWsMsgRef = useRef<(msg: any) => void>(() => {});

  // Auto-scroll terminal to bottom
  const scrollToBottom = useCallback(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, []);

  // Add a line to the live feed
  const addLine = useCallback((text: string, level: string = 'info', module?: string) => {
    lineIdRef.current += 1;
    const newLine: LiveLine = {
      id: lineIdRef.current,
      text,
      level,
      module,
      timestamp: new Date(),
    };
    setLiveLines(prev => {
      const updated = [...prev, newLine];
      // Keep last 500 lines to prevent memory bloat
      return updated.length > 500 ? updated.slice(-500) : updated;
    });
    // Schedule scroll after render
    setTimeout(scrollToBottom, 50);
  }, [scrollToBottom]);

  // Connect to the global live WebSocket
  const connectWebSocket = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    try {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/ws/live`;

      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        setIsConnected(true);
        console.log('[Dashboard] Live feed connected');
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          handleWsMsgRef.current(msg);
        } catch (e) {
          console.error('[Dashboard] Parse error:', e);
        }
      };

      ws.onerror = () => {
        setIsConnected(false);
      };

      ws.onclose = () => {
        setIsConnected(false);
        wsRef.current = null;
        // Reconnect after 3 seconds
        reconnectRef.current = window.setTimeout(() => {
          connectWebSocket();
        }, 3000);
      };
    } catch (e) {
      console.error('[Dashboard] WS connect error:', e);
    }
  }, []);

  // Handle incoming WebSocket messages
  const handleWsMessage = useCallback((msg: any) => {
    const msgType = msg.type;

    if (msgType === 'pong') return;

    if (msgType === 'scan_started') {
      setIsScanActive(true);
      setLiveLines([]); // Clear previous scan output
      lineIdRef.current = 0;
      setScanProgress({
        status: 'running',
        phase: 0,
        phaseName: 'Initialization',
        progress: 0,
        findingsCount: 0,
        endpointsCount: 0,
        severityCounts: {},
        modulesRun: 0,
        modulesFailed: 0,
        totalModules: 0,
        targetUrl: msg.target_url || '',
        scanName: msg.scan_name || '',
      });
      addLine(`Mode: ${msg.exploit_mode === 'full_auth' ? '🔓 FULL AUTHORIZATION (deep exploitation)' : '🛡️ STANDARD (safe analysis)'}`, 'phase');
    }

    if (msgType === 'live_output') {
      addLine(msg.line || '', msg.level || 'info', msg.module);
    }

    if (msgType === 'phase_update' || msgType === 'module_complete') {
      setScanProgress(prev => ({
        ...(prev || {} as ScanProgress),
        status: msg.status || prev?.status || 'running',
        phase: msg.phase ?? prev?.phase ?? 0,
        phaseName: msg.phase_name || prev?.phaseName || '',
        progress: msg.progress ?? prev?.progress ?? 0,
        findingsCount: msg.findings_count ?? prev?.findingsCount ?? 0,
        endpointsCount: msg.endpoints_count ?? prev?.endpointsCount ?? 0,
        severityCounts: msg.severity_counts || prev?.severityCounts || {},
        modulesRun: msg.modules_run ?? prev?.modulesRun ?? 0,
        modulesFailed: msg.modules_failed ?? prev?.modulesFailed ?? 0,
        totalModules: msg.total_modules ?? prev?.totalModules ?? 0,
      }));
    }

    if (msgType === 'scan_complete') {
      setIsScanActive(false);
      setScanProgress(prev => ({
        ...(prev || {} as ScanProgress),
        status: 'completed',
        progress: 100,
        findingsCount: msg.findings_count ?? prev?.findingsCount ?? 0,
        endpointsCount: msg.endpoints_count ?? prev?.endpointsCount ?? 0,
        severityCounts: msg.severity_counts || prev?.severityCounts || {},
        modulesRun: msg.modules_run ?? prev?.modulesRun ?? 0,
        modulesFailed: msg.modules_failed ?? prev?.modulesFailed ?? 0,
      }));
      // Refresh stats after scan completes
      fetchStats();
      fetchAssessments(0, 10);
    }

    if (msgType === 'scan_failed') {
      setIsScanActive(false);
      setScanProgress(prev => ({
        ...(prev || {} as ScanProgress),
        status: 'failed',
      }));
    }
  }, [addLine, fetchStats, fetchAssessments]);

  // Keep the message handler ref up-to-date
  handleWsMsgRef.current = handleWsMessage;

  // Hydrate history from HTTP buffer, then connect WebSocket for live updates
  useEffect(() => {
    fetchStats();
    fetchAssessments(0, 10);

    // Step 1: Fetch buffered history via HTTP (reliable, no timing issues)
    const hydrate = async () => {
      try {
        const res = await fetch('/api/live-buffer');
        if (res.ok) {
          const messages: any[] = await res.json();
          if (messages.length > 0) {
            console.log(`[Dashboard] Hydrating ${messages.length} buffered messages`);
            for (const msg of messages) {
              handleWsMsgRef.current(msg);
            }
          }
        }
      } catch (e) {
        console.warn('[Dashboard] Buffer fetch failed:', e);
      }

      // Step 2: Connect WebSocket for new messages AFTER hydration
      connectWebSocket();
    };

    hydrate();

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
      if (reconnectRef.current) {
        clearTimeout(reconnectRef.current);
      }
    };
  }, []);

  // Keep ping alive
  useEffect(() => {
    const interval = setInterval(() => {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send('ping');
      }
    }, 25000);
    return () => clearInterval(interval);
  }, []);

  const severityData = stats
    ? [
        { name: 'Critical', value: stats.critical_vulnerabilities, color: SEVERITY_COLORS.CRITICAL },
        { name: 'High', value: stats.high_vulnerabilities, color: SEVERITY_COLORS.HIGH },
        {
          name: 'Other',
          value: Math.max(0, stats.total_vulnerabilities - stats.critical_vulnerabilities - stats.high_vulnerabilities),
          color: SEVERITY_COLORS.MEDIUM,
        },
      ].filter((d) => d.value > 0)
    : [];

  return (
    <div className="fade-in">
      <div className="page-header">
        <h1>Security Dashboard</h1>
        <p>Multi-Agent API Security Reasoning Framework — Real-time analysis</p>
      </div>

      {/* Stats Cards */}
      <div className="stats-grid" style={{ marginBottom: 'var(--space-6)' }}>
        <div className="stat-card">
          <span className="stat-label">Total Assessments</span>
          <span className="stat-value">{stats?.total_assessments ?? '—'}</span>
          <SecurityScanOutlined style={{ fontSize: 20, color: 'var(--accent-secondary)', position: 'absolute', top: 16, right: 16 }} />
        </div>
        <div className="stat-card">
          <span className="stat-label">Endpoints Discovered</span>
          <span className="stat-value">{stats?.total_endpoints?.toLocaleString() ?? '—'}</span>
          <ApiOutlined style={{ fontSize: 20, color: 'var(--accent-primary)', position: 'absolute', top: 16, right: 16 }} />
        </div>
        <div className="stat-card">
          <span className="stat-label">Vulnerabilities Found</span>
          <span className="stat-value">{stats?.total_vulnerabilities ?? '—'}</span>
          <BugOutlined style={{ fontSize: 20, color: 'var(--severity-high)', position: 'absolute', top: 16, right: 16 }} />
        </div>
        <div className="stat-card critical">
          <span className="stat-label">Critical Findings</span>
          <span className="stat-value">{stats?.critical_vulnerabilities ?? '—'}</span>
          <WarningOutlined style={{ fontSize: 20, color: 'var(--severity-critical)', position: 'absolute', top: 16, right: 16 }} />
        </div>
      </div>

      {/* Security Overview Row */}
      <div style={{ display: 'grid', gridTemplateColumns: '220px 1fr 1fr', gap: 'var(--space-4)', marginBottom: 'var(--space-6)' }}>
        {/* Risk Score Ring */}
        <div className="card" style={{ textAlign: 'center', padding: 'var(--space-4)', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
          {(() => {
            const riskScore = (stats as any)?.risk_score ?? 0;
            const grade = riskScore >= 80 ? 'F' : riskScore >= 60 ? 'D' : riskScore >= 40 ? 'C' : riskScore >= 20 ? 'B' : 'A';
            const color = { A: '#00e87b', B: '#3b82f6', C: '#ffc312', D: '#ff8c42', F: '#ff4757' }[grade] || '#00e87b';
            return (
              <>
                <Progress
                  type="dashboard"
                  percent={100 - riskScore}
                  format={() => <span style={{ fontSize: 26, fontWeight: 800, color }}>{grade}</span>}
                  strokeColor={color}
                  trailColor="var(--bg-surface)"
                  size={120}
                  strokeWidth={8}
                />
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', marginTop: 4, textTransform: 'uppercase', fontWeight: 600 }}>Security Grade</div>
              </>
            );
          })()}
        </div>

        {/* Severity Breakdown Bars */}
        <div className="card" style={{ padding: 'var(--space-4)', display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: 'var(--space-2)' }}>
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 600, marginBottom: 'var(--space-1)' }}>Severity Breakdown</div>
          {(['critical', 'high', 'medium', 'low', 'info'] as const).map((sev) => {
            const sevBreakdown = (stats as any)?.severity_breakdown || {};
            const count = sevBreakdown[sev] || 0;
            const max = Math.max(...Object.values(sevBreakdown as Record<string, number>), 1);
            const colors: Record<string, string> = { critical: '#ff4757', high: '#ff8c42', medium: '#ffc312', low: '#00e87b', info: '#3b82f6' };
            return (
              <div key={sev} style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                <span style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', width: 48, color: colors[sev] }}>{sev}</span>
                <div style={{ flex: 1, height: 5, background: 'var(--bg-surface)', borderRadius: 3, overflow: 'hidden' }}>
                  <div style={{ width: `${(count / max) * 100}%`, height: '100%', background: colors[sev], borderRadius: 3, transition: 'width 0.6s ease' }} />
                </div>
                <span style={{ fontSize: 10, fontWeight: 700, fontFamily: 'var(--font-mono)', width: 24, textAlign: 'right' }}>{count}</span>
              </div>
            );
          })}
        </div>

        {/* OWASP Mini Heatmap */}
        <div className="card" style={{ padding: 'var(--space-4)' }}>
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 600, marginBottom: 'var(--space-2)' }}>OWASP API Top 10</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 'var(--space-1)' }}>
            {['API1','API2','API3','API4','API5','API6','API7','API8','API9','API10'].map((key) => {
              const owaspCoverage = (stats as any)?.owasp_coverage || {};
              const count = owaspCoverage[key] || 0;
              const bg = count === 0 ? 'rgba(0, 232, 123, 0.08)' : `rgba(255, 71, 87, ${Math.min(0.1 + (count / 5) * 0.35, 0.5)})`;
              return (
                <div key={key} title={`${key}: ${count} findings`} style={{
                  background: bg, borderRadius: 4, padding: '6px 0',
                  textAlign: 'center', cursor: 'pointer', transition: 'all 150ms',
                  fontSize: 9, fontWeight: 700, color: count > 0 ? '#ff4757' : 'var(--text-tertiary)',
                }}>{key.replace('API', '')}</div>
              );
            })}
          </div>
          <Link to="/threat-intel" className="btn btn-secondary btn-sm" style={{ marginTop: 'var(--space-3)', width: '100%', justifyContent: 'center', fontSize: 11 }}>
            <RadarChartOutlined /> View Full Report
          </Link>
        </div>
      </div>

      {/* Modern API Attack Coverage */}
      <div className="card" style={{ marginBottom: 'var(--space-6)', padding: 'var(--space-4)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--space-3)' }}>
          <div>
            <h3 className="section-title" style={{ margin: 0 }}>Modern API Attack Coverage</h3>
            <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)' }}>
              {((stats as any)?.modern_attack_coverage?.coverage_percent ?? 0)}% of {((stats as any)?.modern_attack_coverage?.total_classes ?? 18)} attack classes tested
            </span>
          </div>
          <div style={{ fontSize: 'var(--text-lg)', fontWeight: 800, color: 'var(--accent-primary)', fontFamily: 'var(--font-mono)' }}>
            {((stats as any)?.modern_attack_coverage?.classes_tested ?? 0)}/{((stats as any)?.modern_attack_coverage?.total_classes ?? 18)}
          </div>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 'var(--space-2)' }}>
          {((stats as any)?.modern_attack_coverage?.classes || [
            'JWT', 'BOLA/IDOR', 'BFLA', 'Mass Assignment', 'Race Condition', 'Prototype Pollution',
            'CORS', 'Deserialization', 'SSRF', 'XXE', 'File Upload', 'WebSocket',
            'GraphQL', 'Request Smuggling', 'CRLF Injection', 'Parameter Pollution', 'LLM/AI', 'Hidden APIs',
          ]).map((cls: string) => {
            const vulnClasses = (stats as any)?.vulnerability_classes || {};
            const count = vulnClasses[cls] || 0;
            const isActive = count > 0;
            return (
              <div key={cls} title={`${cls}: ${count} findings`} style={{
                background: isActive
                  ? `rgba(255, 71, 87, ${Math.min(0.15 + count * 0.08, 0.5)})`
                  : 'rgba(0, 232, 123, 0.06)',
                borderRadius: 6,
                padding: '8px 4px',
                textAlign: 'center',
                fontSize: 9,
                fontWeight: 700,
                color: isActive ? '#ff4757' : 'var(--text-tertiary)',
                border: isActive ? '1px solid rgba(255, 71, 87, 0.3)' : '1px solid transparent',
                transition: 'all 200ms ease',
              }}>
                <div>{cls}</div>
                {isActive && <div style={{ fontSize: 14, marginTop: 2 }}>{count}</div>}
              </div>
            );
          })}
        </div>
      </div>

      {/* Live Scan Feed + Charts */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 'var(--space-6)', marginBottom: 'var(--space-6)' }}>

        {/* ── Live Scan Terminal Feed ────────────────────── */}
        <div className="card live-feed-card">
          <div className="live-feed-header">
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
              <RadarChartOutlined style={{ fontSize: 18, color: 'var(--accent-primary)' }} />
              <h3 className="section-title" style={{ margin: 0 }}>Live Scan Feed</h3>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
              {isScanActive && scanProgress && (
                <span className="live-feed-badge running">
                  <LoadingOutlined spin /> Phase {scanProgress.phase}: {scanProgress.phaseName}
                </span>
              )}
              {!isScanActive && scanProgress?.status === 'completed' && (
                <span className="live-feed-badge completed">
                  <CheckCircleOutlined /> Completed
                </span>
              )}
              {!isScanActive && scanProgress?.status === 'failed' && (
                <span className="live-feed-badge failed">
                  <CloseCircleOutlined /> Failed
                </span>
              )}
              <span className={`live-feed-dot ${isConnected ? 'connected' : 'disconnected'}`} />
            </div>
          </div>

          {/* Progress bar during active scan */}
          {isScanActive && scanProgress && (
            <div className="live-feed-progress">
              <Progress
                percent={scanProgress.progress}
                size="small"
                strokeColor={{
                  '0%': '#a78bfa',
                  '100%': '#00e87b',
                }}
                trailColor="#21262d"
                format={(pct) => `${pct}%`}
              />
              <div className="live-feed-stats">
                <span><BugOutlined /> {scanProgress.findingsCount} findings</span>
                <span><ApiOutlined /> {scanProgress.endpointsCount} endpoints</span>
                <span>
                  {scanProgress.modulesRun}/{scanProgress.totalModules} modules
                  {scanProgress.modulesFailed > 0 && (
                    <span style={{ color: 'var(--severity-high)', marginLeft: 4 }}>
                      ({scanProgress.modulesFailed} failed)
                    </span>
                  )}
                </span>
              </div>
            </div>
          )}

          {/* Scan completion summary */}
          {!isScanActive && scanProgress?.status === 'completed' && (
            <div className="live-feed-summary">
              <div className="severity-pills">
                {Object.entries(scanProgress.severityCounts || {}).map(([sev, count]) => (
                  count > 0 && (
                    <span key={sev} className={`severity-pill ${sev}`}>
                      {sev}: {count}
                    </span>
                  )
                ))}
              </div>
              <span className="live-feed-stats-text">
                {scanProgress.findingsCount} findings • {scanProgress.endpointsCount} endpoints • {scanProgress.modulesRun - scanProgress.modulesFailed}/{scanProgress.modulesRun} modules OK
              </span>
            </div>
          )}

          {/* Terminal output area */}
          <div className="live-feed-terminal" ref={terminalRef}>
            {liveLines.length === 0 ? (
              <div className="live-feed-empty">
                <RadarChartOutlined style={{ fontSize: 32, opacity: 0.3 }} />
                <p>No active scan. Start an assessment to see real-time output.</p>
                <Link to="/assessments" className="btn btn-primary btn-sm" style={{ marginTop: 8 }}>
                  <ThunderboltOutlined /> New Assessment
                </Link>
              </div>
            ) : (
              liveLines.map((line) => (
                <div
                  key={line.id}
                  className={`live-line live-line-${line.level}`}
                  style={{ color: LINE_COLORS[line.level] || LINE_COLORS.info }}
                >
                  <span className="live-line-prefix">
                    {line.level === 'phase' ? '═══' :
                     line.level === 'module_start' ? ' →' :
                     line.level === 'error' ? '[-]' :
                     line.level === 'warning' ? '[!]' :
                     line.level === 'finding' || line.level === 'success' ? '[+]' :
                     '[*]'}
                  </span>
                  <span className="live-line-text">
                    {line.text.replace(/^\[\+\]\s*-?\s*|\[\-\]\s*-?\s*|\[\*\]\s*-?\s*|\[\!\]\s*-?\s*/g, '')}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>

        {/* ── Right Column: Charts + Quick Actions ──────── */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-6)' }}>

          {/* Severity Distribution */}
          <div className="card">
            <h3 className="section-title">Severity Distribution</h3>
            {severityData.length > 0 ? (
              <ResponsiveContainer width="100%" height={180}>
                <PieChart>
                  <Pie
                    data={severityData}
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={70}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {severityData.map((entry, i) => (
                      <Cell key={i} fill={entry.color} stroke="transparent" />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ background: '#161b22', border: '1px solid #30363d', borderRadius: 8 }}
                    labelStyle={{ color: '#e6edf3' }}
                    itemStyle={{ color: '#8b949e' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <Empty description="No vulnerability data" />
            )}
            <div style={{ display: 'flex', justifyContent: 'center', gap: 'var(--space-4)', marginTop: 'var(--space-2)' }}>
              {severityData.map((d) => (
                <div key={d.name} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 'var(--text-xs)' }}>
                  <span style={{ width: 8, height: 8, borderRadius: '50%', background: d.color }} />
                  <span style={{ color: 'var(--text-secondary)' }}>{d.name}: {d.value}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Quick Actions */}
          <div className="card">
            <h3 className="section-title">Quick Actions</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
              <Link to="/assessments" className="btn btn-primary" style={{ justifyContent: 'center' }}>
                <ThunderboltOutlined /> New Assessment
              </Link>
              <Link to="/exploitation" className="btn btn-secondary" style={{ justifyContent: 'center' }}>
                <ThunderboltOutlined /> Exploitation
              </Link>
              <Link to="/findings" className="btn btn-secondary" style={{ justifyContent: 'center' }}>
                <BugOutlined /> View Findings
              </Link>
              <Link to="/reports" className="btn btn-secondary" style={{ justifyContent: 'center' }}>
                <SecurityScanOutlined /> Generate Report
              </Link>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Assessments */}
      <div className="card">
        <h3 className="section-title">Recent Assessments</h3>
        {assessments.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Title</th>
                <th>Target</th>
                <th>Status</th>
                <th>Progress</th>
                <th>Findings</th>
              </tr>
            </thead>
            <tbody>
              {assessments.slice(0, 8).map((a) => (
                <tr key={a.id}>
                  <td className="mono">#{a.id}</td>
                  <td>
                    <Link to={`/assessments/${a.id}`} style={{ color: 'var(--text-primary)', fontWeight: 500 }}>
                      {a.assessment_name || 'Untitled Assessment'}
                    </Link>
                  </td>
                  <td className="mono" style={{ color: 'var(--text-secondary)', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {a.target_url}
                  </td>
                  <td>
                    <span className={`status-badge ${a.status}`}>{a.status}</span>
                  </td>
                  <td style={{ minWidth: 120 }}>
                    <Progress
                      percent={a.progress_percent}
                      size="small"
                      strokeColor={a.status === 'failed' ? '#ff4757' : '#00e87b'}
                      trailColor="#21262d"
                      showInfo={false}
                    />
                  </td>
                  <td>
                    <span style={{ color: a.critical_count > 0 ? 'var(--severity-critical)' : 'var(--text-secondary)' }}>
                      {a.total_findings ?? 0}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <Empty
            description={<span style={{ color: 'var(--text-tertiary)' }}>No assessments yet. Start your first security assessment!</span>}
          />
        )}
      </div>
    </div>
  );
};

export default Dashboard;
