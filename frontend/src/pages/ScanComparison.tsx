/* ============================================================
   Scan Comparison — Side-by-side scan diff viewer
   ============================================================ */

import React, { useEffect, useState } from 'react';
import { Select, Empty, Spin, Tag, Tabs, Statistic } from 'antd';
import {
  SwapOutlined, PlusCircleOutlined, CheckCircleOutlined,
  MinusCircleOutlined, ArrowUpOutlined, ArrowDownOutlined,
} from '@ant-design/icons';
import { useAssessmentStore } from '@/store';
import { comparisonApi } from '@/services/apiClient';

const SEV_COLORS: Record<string, string> = {
  CRITICAL: '#ff4757', HIGH: '#ff8c42', MEDIUM: '#ffc312', LOW: '#00e87b', INFO: '#3b82f6',
};

interface FindingDiff {
  id: string; title: string; severity: string;
  category: string; module_name: string;
  endpoint_url?: string; description?: string;
}

const ScanComparison: React.FC = () => {
  const { assessments, fetchAssessments } = useAssessmentStore();
  const [scanA, setScanA] = useState<string | undefined>();
  const [scanB, setScanB] = useState<string | undefined>();
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => { fetchAssessments(); }, []);

  useEffect(() => {
    if (scanA && scanB && scanA !== scanB) {
      setLoading(true);
      comparisonApi.compareFindings(scanA, scanB)
        .then((res: any) => setResult(res))
        .catch(() => setResult(null))
        .finally(() => setLoading(false));
    }
  }, [scanA, scanB]);

  const renderFindingList = (items: FindingDiff[], type: 'new' | 'fixed' | 'persistent') => {
    const colorMap = { new: '#ff4757', fixed: '#00e87b', persistent: 'var(--text-tertiary)' };
    const iconMap = { new: <PlusCircleOutlined />, fixed: <CheckCircleOutlined />, persistent: <MinusCircleOutlined /> };
    const labelMap = { new: 'NEW', fixed: 'FIXED', persistent: 'UNCHANGED' };

    if (!items?.length) return <Empty description={`No ${type} findings`} style={{ padding: 24 }} />;

    return (
      <div style={{ maxHeight: 'calc(100vh - 400px)', overflow: 'auto' }}>
        {items.map((f) => (
          <div
            key={f.id}
            style={{
              display: 'flex', alignItems: 'flex-start', gap: 'var(--space-3)',
              padding: 'var(--space-3) var(--space-4)',
              borderBottom: '1px solid var(--border-subtle)',
              borderLeft: `3px solid ${colorMap[type]}`,
            }}
          >
            <span style={{ color: colorMap[type], flexShrink: 0, marginTop: 2 }}>{iconMap[type]}</span>
            <div style={{ flex: 1 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontWeight: 500, fontSize: 'var(--text-sm)' }}>{f.title}</span>
                <span className={`severity-badge ${f.severity.toLowerCase()}`}>{f.severity}</span>
              </div>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', marginTop: 2 }}>
                {f.category} · {f.module_name}
                {f.endpoint_url && <> · <span className="mono">{f.endpoint_url}</span></>}
              </div>
            </div>
          </div>
        ))}
      </div>
    );
  };

  const summary = result?.summary || {};

  return (
    <div className="fade-in">
      <div className="page-header">
        <h1><SwapOutlined style={{ marginRight: 8 }} />Scan Comparison</h1>
        <p>Compare two scan results to track vulnerability changes and regression</p>
      </div>

      {/* Scan Selectors */}
      <div style={{ display: 'flex', gap: 'var(--space-4)', marginBottom: 'var(--space-5)', alignItems: 'center', flexWrap: 'wrap' }}>
        <div>
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', marginBottom: 4, textTransform: 'uppercase', fontWeight: 600 }}>Baseline (A)</div>
          <Select
            placeholder="Select baseline scan"
            value={scanA}
            onChange={setScanA}
            style={{ width: 300 }}
            options={assessments.map((a) => ({ label: `${a.assessment_name} (${a.id.substring(0, 8)})`, value: a.id }))}
          />
        </div>
        <SwapOutlined style={{ fontSize: 20, color: 'var(--text-tertiary)', marginTop: 18 }} />
        <div>
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', marginBottom: 4, textTransform: 'uppercase', fontWeight: 600 }}>Compare (B)</div>
          <Select
            placeholder="Select comparison scan"
            value={scanB}
            onChange={setScanB}
            style={{ width: 300 }}
            options={assessments.filter(a => a.id !== scanA).map((a) => ({ label: `${a.assessment_name} (${a.id.substring(0, 8)})`, value: a.id }))}
          />
        </div>
      </div>

      {!scanA || !scanB ? (
        <div className="card" style={{ textAlign: 'center', padding: 60 }}>
          <SwapOutlined style={{ fontSize: 48, color: 'var(--text-tertiary)', marginBottom: 16 }} />
          <p style={{ color: 'var(--text-tertiary)' }}>Select two scans to compare</p>
        </div>
      ) : loading ? (
        <div style={{ padding: 40, textAlign: 'center' }}><Spin size="large" /></div>
      ) : result ? (
        <>
          {/* Summary Stats */}
          <div className="stats-grid" style={{ marginBottom: 'var(--space-5)', gridTemplateColumns: 'repeat(4, 1fr)' }}>
            <div className="stat-card" style={{ borderTop: '3px solid #ff4757' }}>
              <span className="stat-label"><PlusCircleOutlined /> New Vulnerabilities</span>
              <span className="stat-value" style={{ color: '#ff4757' }}>{summary.total_new || 0}</span>
            </div>
            <div className="stat-card" style={{ borderTop: '3px solid #00e87b' }}>
              <span className="stat-label"><CheckCircleOutlined /> Fixed</span>
              <span className="stat-value" style={{ color: '#00e87b' }}>{summary.total_fixed || 0}</span>
            </div>
            <div className="stat-card" style={{ borderTop: '3px solid var(--text-tertiary)' }}>
              <span className="stat-label"><MinusCircleOutlined /> Persistent</span>
              <span className="stat-value">{summary.total_persistent || 0}</span>
            </div>
            <div className="stat-card" style={{ borderTop: '3px solid var(--accent-secondary)' }}>
              <span className="stat-label">Improvement Score</span>
              <span className="stat-value" style={{
                color: (summary.improvement_score || 0) > 50 ? '#00e87b' : (summary.improvement_score || 0) > 0 ? '#ffc312' : '#ff4757'
              }}>
                {summary.improvement_score || 0}%
                {(summary.improvement_score || 0) > 0 ? <ArrowUpOutlined style={{ fontSize: 14, marginLeft: 4 }} /> : <ArrowDownOutlined style={{ fontSize: 14, marginLeft: 4 }} />}
              </span>
            </div>
          </div>

          {/* Tabbed Diff View */}
          <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
            <Tabs
              style={{ padding: '0 var(--space-4)' }}
              items={[
                {
                  key: 'new',
                  label: <span style={{ color: '#ff4757' }}><PlusCircleOutlined /> New ({result.new_findings?.length || 0})</span>,
                  children: renderFindingList(result.new_findings, 'new'),
                },
                {
                  key: 'fixed',
                  label: <span style={{ color: '#00e87b' }}><CheckCircleOutlined /> Fixed ({result.fixed_findings?.length || 0})</span>,
                  children: renderFindingList(result.fixed_findings, 'fixed'),
                },
                {
                  key: 'persistent',
                  label: <span><MinusCircleOutlined /> Persistent ({result.persistent_findings?.length || 0})</span>,
                  children: renderFindingList(result.persistent_findings, 'persistent'),
                },
              ]}
            />
          </div>
        </>
      ) : null}
    </div>
  );
};

export default ScanComparison;
