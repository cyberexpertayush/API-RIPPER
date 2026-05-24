/* ============================================================
   Attack Surface — Interactive API endpoint map viewer
   ============================================================ */

import React, { useEffect, useState } from 'react';
import { Select, Empty, Spin, Tag, Input, Badge } from 'antd';
import {
  ApiOutlined, LockOutlined, UnlockOutlined, SearchOutlined,
  GlobalOutlined, LinkOutlined,
} from '@ant-design/icons';
import { useAssessmentStore } from '@/store';
import { endpointsApi } from '@/services/apiClient';

const METHOD_COLORS: Record<string, string> = {
  GET: '#00e87b', POST: '#3b82f6', PUT: '#ffc312',
  PATCH: '#a855f7', DELETE: '#ff4757', HEAD: '#64748b',
  OPTIONS: '#94a3b8',
};

interface EndpointItem {
  id: string;
  url: string;
  path: string;
  method: string;
  status_code?: number;
  requires_auth?: boolean;
}

const AttackSurface: React.FC = () => {
  const { assessments, fetchAssessments } = useAssessmentStore();
  const [selectedAssessment, setSelectedAssessment] = useState<string | undefined>();
  const [endpoints, setEndpoints] = useState<EndpointItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [methodFilter, setMethodFilter] = useState<string | undefined>();

  useEffect(() => { fetchAssessments(); }, []);

  useEffect(() => {
    if (selectedAssessment) {
      setLoading(true);
      endpointsApi.list(selectedAssessment)
        .then((res: any) => setEndpoints(Array.isArray(res) ? res : res?.data || []))
        .catch(() => setEndpoints([]))
        .finally(() => setLoading(false));
    }
  }, [selectedAssessment]);

  const filtered = endpoints.filter((e) => {
    if (search && !e.url?.toLowerCase().includes(search.toLowerCase()) && !e.path?.toLowerCase().includes(search.toLowerCase())) return false;
    if (methodFilter && e.method !== methodFilter) return false;
    return true;
  });

  const methodCounts = endpoints.reduce<Record<string, number>>((acc, e) => {
    acc[e.method] = (acc[e.method] || 0) + 1;
    return acc;
  }, {});

  const authCount = endpoints.filter(e => e.requires_auth).length;
  const openCount = endpoints.length - authCount;

  // Group by base path
  const grouped = filtered.reduce<Record<string, EndpointItem[]>>((acc, e) => {
    const parts = (e.path || e.url || '').split('/').filter(Boolean);
    const base = '/' + (parts[0] || 'root');
    if (!acc[base]) acc[base] = [];
    acc[base].push(e);
    return acc;
  }, {});

  return (
    <div className="fade-in">
      <div className="page-header">
        <h1><ApiOutlined style={{ marginRight: 8 }} />Attack Surface Map</h1>
        <p>Visualize discovered API endpoints with authentication and method analysis</p>
      </div>

      {/* Controls */}
      <div style={{ display: 'flex', gap: 'var(--space-3)', marginBottom: 'var(--space-4)', flexWrap: 'wrap', alignItems: 'center' }}>
        <Select
          placeholder="Select Scan"
          value={selectedAssessment}
          onChange={(v) => { setSelectedAssessment(v); setSearch(''); setMethodFilter(undefined); }}
          style={{ width: 300 }}
          options={assessments.map((a) => ({ label: `${a.assessment_name} (${a.id.substring(0, 8)})`, value: a.id }))}
        />
        <Input
          prefix={<SearchOutlined />}
          placeholder="Search endpoints..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{ width: 240 }}
          allowClear
        />
        <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
          <Tag
            style={{ cursor: 'pointer', borderRadius: 12, padding: '2px 12px' }}
            color={!methodFilter ? 'green' : undefined}
            onClick={() => setMethodFilter(undefined)}
          >All ({endpoints.length})</Tag>
          {Object.entries(methodCounts).map(([method, count]) => (
            <Tag
              key={method}
              style={{ cursor: 'pointer', borderRadius: 12, padding: '2px 12px' }}
              color={methodFilter === method ? 'green' : undefined}
              onClick={() => setMethodFilter(method === methodFilter ? undefined : method)}
            >{method} ({count})</Tag>
          ))}
        </div>
      </div>

      {!selectedAssessment ? (
        <div className="card" style={{ textAlign: 'center', padding: 60 }}>
          <GlobalOutlined style={{ fontSize: 48, color: 'var(--text-tertiary)', marginBottom: 16 }} />
          <p style={{ color: 'var(--text-tertiary)' }}>Select a scan to view the attack surface</p>
        </div>
      ) : loading ? (
        <div style={{ padding: 40, textAlign: 'center' }}><Spin size="large" /></div>
      ) : (
        <>
          {/* Stats Cards */}
          <div className="stats-grid" style={{ marginBottom: 'var(--space-5)' }}>
            <div className="stat-card">
              <span className="stat-label">Total Endpoints</span>
              <span className="stat-value">{endpoints.length}</span>
            </div>
            <div className="stat-card">
              <span className="stat-label"><LockOutlined /> Auth Required</span>
              <span className="stat-value" style={{ color: 'var(--severity-medium)' }}>{authCount}</span>
            </div>
            <div className="stat-card">
              <span className="stat-label"><UnlockOutlined /> Open Access</span>
              <span className="stat-value" style={{ color: authCount === 0 && openCount > 0 ? 'var(--severity-high)' : 'var(--accent-primary)' }}>{openCount}</span>
            </div>
            <div className="stat-card">
              <span className="stat-label">HTTP Methods</span>
              <span className="stat-value">{Object.keys(methodCounts).length}</span>
            </div>
          </div>

          {/* Endpoint Tree */}
          {filtered.length === 0 ? (
            <Empty description="No endpoints match filters" style={{ padding: 40 }} />
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
              {Object.entries(grouped).sort().map(([base, eps]) => (
                <div key={base} className="card" style={{ padding: 0, overflow: 'hidden' }}>
                  <div style={{
                    padding: 'var(--space-3) var(--space-4)',
                    borderBottom: '1px solid var(--border-subtle)',
                    background: 'var(--bg-surface)',
                    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                  }}>
                    <span style={{ fontWeight: 600, fontSize: 'var(--text-sm)', fontFamily: 'var(--font-mono)' }}>
                      <LinkOutlined style={{ marginRight: 6 }} />{base}
                    </span>
                    <Badge count={eps.length} style={{ backgroundColor: 'var(--bg-hover)' }} />
                  </div>
                  <div style={{ padding: 0 }}>
                    {eps.map((ep) => (
                      <div
                        key={ep.id}
                        style={{
                          display: 'flex', alignItems: 'center', gap: 'var(--space-3)',
                          padding: 'var(--space-2) var(--space-4)',
                          borderBottom: '1px solid var(--border-subtle)',
                          fontSize: 'var(--text-sm)',
                          transition: 'background 150ms',
                        }}
                        className="endpoint-row"
                      >
                        <span
                          className={`method-badge ${ep.method}`}
                          style={{ minWidth: 56, textAlign: 'center' }}
                        >{ep.method}</span>
                        <span style={{ flex: 1, fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-primary)' }}>
                          {ep.path || ep.url}
                        </span>
                        {ep.status_code ? (
                          <span style={{
                            fontSize: 'var(--text-xs)',
                            color: ep.status_code < 400 ? 'var(--accent-primary)' : 'var(--severity-critical)',
                            fontFamily: 'var(--font-mono)',
                          }}>{ep.status_code}</span>
                        ) : null}
                        {ep.requires_auth ? (
                          <LockOutlined style={{ color: 'var(--severity-medium)', fontSize: 13 }} />
                        ) : (
                          <UnlockOutlined style={{ color: 'var(--text-tertiary)', fontSize: 13 }} />
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
};

export default AttackSurface;
