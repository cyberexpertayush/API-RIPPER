/* ============================================================
   Assessment Detail — Tabbed view with live WebSocket updates
   ============================================================ */

import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { Tabs, Progress, Tag, Descriptions, Empty, Spin, Button, Space, message } from 'antd';
import { PlayCircleOutlined, StopOutlined, ReloadOutlined } from '@ant-design/icons';
import { useAssessmentStore, useFindingsStore } from '@/store';
import { websocketService } from '@/services/websocketService';
import { apiClient } from '@/services/apiClient';
import { AttackGraph } from '@/components/AttackGraph';

const AssessmentDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const assessmentId = id;
  const { currentAssessment, fetchAssessment, updateProgress, loading } = useAssessmentStore();
  const { executeAssessment, cancelAssessment } = useAssessmentStore();
  const { findings, fetchFindings } = useFindingsStore();
  const [wsStatus, setWsStatus] = useState<string>('disconnected');
  const [endpoints, setEndpoints] = useState<any[]>([]);
  const [graphData, setGraphData] = useState<any>({ endpoints: [], relationships: [], chains: [] });

  useEffect(() => {
    if (assessmentId) {
      fetchAssessment(assessmentId);
      fetchFindings(assessmentId);
      fetchEndpoints(assessmentId);
      fetchGraph(assessmentId);
    }
    return () => { websocketService.disconnect(); };
  }, [assessmentId]);

  const fetchEndpoints = async (scanId: string) => {
    try {
      const data: any = await apiClient.get(`/scans/${scanId}/endpoints`);
      setEndpoints(Array.isArray(data) ? data : []);
    } catch { setEndpoints([]); }
  };

  const fetchGraph = async (scanId: string) => {
    try {
      const data: any = await apiClient.get(`/scans/${scanId}/graph`);
      setGraphData(data);
    } catch { setGraphData({ endpoints: [], relationships: [], chains: [] }); }
  };

  // Connect WebSocket for live updates
  useEffect(() => {
    if (currentAssessment && currentAssessment.status === 'running') {
      websocketService.connect(assessmentId).catch(() => {});
      setWsStatus('connecting');

      websocketService.on('connected', () => setWsStatus('connected'));
      websocketService.on('message', (msg: any) => {
        if (assessmentId) {
          updateProgress(assessmentId, {
            status: msg.status || currentAssessment.status,
            progress_percent: msg.progress || msg.progress_percentage || currentAssessment.progress_percent,
            phase_name: msg.phase_name || currentAssessment.phase_name,
            total_findings: msg.findings_count || currentAssessment.total_findings,
          });

          // Reload findings when scan completes
          if (msg.status === 'completed') {
            setWsStatus('completed');
            fetchAssessment(assessmentId);
            fetchFindings(assessmentId);
            fetchEndpoints(assessmentId);
            fetchGraph(assessmentId);
          }
        }
      });

      return () => { websocketService.disconnect(); };
    }
  }, [currentAssessment?.status]);

  // Polling fallback for progress
  useEffect(() => {
    if (!currentAssessment || currentAssessment.status !== 'running') return;
    const interval = setInterval(() => {
      if (assessmentId) {
        fetchAssessment(assessmentId);
        fetchFindings(assessmentId);
        fetchGraph(assessmentId);
      }
    }, 5000);
    return () => clearInterval(interval);
  }, [currentAssessment?.status]);

  const handleExecute = async () => {
    if (assessmentId) {
      await executeAssessment(assessmentId);
      message.success('Scan started!');
      fetchAssessment(assessmentId);
    }
  };

  const handleCancel = async () => {
    if (assessmentId) {
      await cancelAssessment(assessmentId);
      message.info('Scan cancelled');
      fetchAssessment(assessmentId);
    }
  };

  if (loading && !currentAssessment) {
    return <div style={{ display: 'flex', justifyContent: 'center', padding: '40px' }}><Spin size="large" /></div>;
  }

  if (!currentAssessment) {
    return <Empty description="Scan not found" />;
  }

  const a = currentAssessment;

  const tabItems = [
    {
      key: 'overview',
      label: 'Overview',
      children: (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-6)' }}>
          <div className="card">
            <h3 className="section-title">Scan Details</h3>
            <Descriptions column={1} size="small" labelStyle={{ color: 'var(--text-tertiary)' }} contentStyle={{ color: 'var(--text-primary)' }}>
              <Descriptions.Item label="Target">{a.target_url}</Descriptions.Item>
              <Descriptions.Item label="Status"><span className={`status-badge ${a.status}`}>{a.status}</span></Descriptions.Item>
              <Descriptions.Item label="Phase">{a.phase_name || '—'}</Descriptions.Item>
              <Descriptions.Item label="Scan Type">{a.scan_type || 'full'}</Descriptions.Item>
              <Descriptions.Item label="Created">{a.created_at || '—'}</Descriptions.Item>
              <Descriptions.Item label="Completed">{a.completed_at || '—'}</Descriptions.Item>
            </Descriptions>
            <div style={{ marginTop: 'var(--space-4)', display: 'flex', gap: 'var(--space-2)' }}>
              {(a.status === 'created' || a.status === 'failed') && (
                <Button type="primary" icon={<PlayCircleOutlined />} onClick={handleExecute}>
                  {a.status === 'failed' ? 'Retry Scan' : 'Start Scan'}
                </Button>
              )}
              {a.status === 'running' && (
                <Button danger icon={<StopOutlined />} onClick={handleCancel}>Cancel Scan</Button>
              )}
              <Button icon={<ReloadOutlined />} onClick={() => { if (assessmentId) { fetchAssessment(assessmentId); fetchFindings(assessmentId); } }}>
                Refresh
              </Button>
            </div>
          </div>
          <div>
            <div className="card" style={{ marginBottom: 'var(--space-4)' }}>
              <h3 className="section-title">Progress</h3>
              <Progress
                percent={a.progress_percent || a.progress_percentage || 0}
                strokeColor={{ '0%': '#3b82f6', '100%': '#00e87b' }}
                trailColor="#21262d"
                size={[undefined as unknown as number, 12]}
              />
              <div style={{ marginTop: 'var(--space-2)', fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
                {a.phase_name || 'Waiting to start'}
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 'var(--space-3)' }}>
                <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)' }}>
                  Endpoints: {a.endpoints_discovered ?? endpoints.length ?? 0}
                </span>
                <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)' }}>
                  Findings: {a.total_findings ?? a.vulnerabilities_found ?? 0}
                </span>
              </div>
            </div>
            <div className="stats-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
              <div className="stat-card"><span className="stat-label">Total Findings</span><span className="stat-value">{a.total_findings ?? a.vulnerabilities_found ?? 0}</span></div>
              <div className="stat-card critical"><span className="stat-label">Critical</span><span className="stat-value">{a.critical_count ?? 0}</span></div>
              <div className="stat-card"><span className="stat-label">High</span><span className="stat-value" style={{ color: 'var(--severity-high)' }}>{a.high_count ?? 0}</span></div>
              <div className="stat-card"><span className="stat-label">Medium</span><span className="stat-value" style={{ color: 'var(--severity-medium)' }}>{a.medium_count ?? 0}</span></div>
            </div>
          </div>
        </div>
      ),
    },
    {
      key: 'findings',
      label: `Findings (${findings.length})`,
      children: (
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          {findings.length > 0 ? (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Title</th>
                  <th>Category</th>
                  <th>Module</th>
                  <th>Severity</th>
                  <th>Endpoint</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f: any) => (
                  <tr key={f.id}>
                    <td style={{ fontWeight: 500 }}>{f.title}</td>
                    <td className="mono" style={{ fontSize: 'var(--text-xs)' }}>{f.category || f.vulnerability_type || '—'}</td>
                    <td className="mono" style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>{f.module_name || '—'}</td>
                    <td><span className={`severity-badge ${(f.severity || 'info').toLowerCase()}`}>{f.severity}</span></td>
                    <td className="mono" style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {f.endpoint_url || f.endpoint || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Empty description="No findings yet" style={{ padding: 40 }} />
          )}
        </div>
      ),
    },
    {
      key: 'endpoints',
      label: `Endpoints (${endpoints.length})`,
      children: (
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          {endpoints.length > 0 ? (
            <table className="data-table">
              <thead>
                <tr><th>URL</th><th>Path</th><th>Method</th><th>Status</th><th>Auth</th></tr>
              </thead>
              <tbody>
                {endpoints.map((e: any) => (
                  <tr key={e.id}>
                    <td className="mono" style={{ fontSize: 'var(--text-xs)', maxWidth: 250, overflow: 'hidden', textOverflow: 'ellipsis' }}>{e.url}</td>
                    <td className="mono">{e.path || '/'}</td>
                    <td><span className={`method-badge ${e.method}`}>{e.method}</span></td>
                    <td>{e.status_code || '—'}</td>
                    <td>{e.requires_auth ? <Tag color="orange">Required</Tag> : <Tag>None</Tag>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Empty description="No endpoints discovered" style={{ padding: 40 }} />
          )}
        </div>
      ),
    },
    {
      key: 'attack_surface',
      label: 'Attack Surface & Chains',
      children: (
        <div style={{ marginTop: 'var(--space-4)' }}>
          <AttackGraph 
            endpoints={graphData?.endpoints || []} 
            relationships={graphData?.relationships || []} 
            chains={graphData?.chains || []} 
          />
        </div>
      ),
    },
  ];

  return (
    <div className="fade-in">
      <div className="page-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
          <Link to="/assessments" style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-sm)' }}>← Scans</Link>
          <span style={{ color: 'var(--text-tertiary)' }}>/</span>
          <h1 style={{ margin: 0 }}>{a.assessment_name || `Scan #${a.id?.substring(0, 8)}`}</h1>
          <span className={`status-badge ${a.status}`}>{a.status}</span>
          {(wsStatus === 'connected' || a.status === 'running') && (
            <span style={{ fontSize: 'var(--text-xs)', color: 'var(--status-running)', display: 'flex', alignItems: 'center', gap: 4 }}>
              <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--status-running)', animation: 'pulse 1.5s infinite' }} />
              Live
            </span>
          )}
        </div>
      </div>

      <Tabs items={tabItems} defaultActiveKey="overview" />
    </div>
  );
};

export default AssessmentDetail;
