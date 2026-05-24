/* ============================================================
   Discovery Explorer — Virtualized API Surface Discovery
   ============================================================ */

import React, { useEffect, useState, useCallback } from 'react';
import { Input, Tag, Empty, Spin, Select } from 'antd';
import { SearchOutlined, ApiOutlined, LockOutlined, UnlockOutlined } from '@ant-design/icons';
import { List } from 'react-window';
import type { RowComponentProps } from 'react-window';
import { endpointsApi } from '@/services/apiClient';
import type { Endpoint, EndpointCategory } from '@/types/api';

interface EndpointResult {
  endpoints: Endpoint[];
  total: number;
}

interface EndpointRowProps {
  filteredEndpoints: Endpoint[];
  selectedEndpointId: number | null;
  onSelect: (ep: Endpoint) => void;
}

const EndpointRow = ({ index, style, filteredEndpoints, selectedEndpointId, onSelect }: RowComponentProps<EndpointRowProps>) => {
  const ep = filteredEndpoints[index];
  if (!ep) return null;
  return (
    <div
      style={{
        ...style,
        display: 'flex',
        alignItems: 'center',
        gap: 'var(--space-3)',
        padding: '0 var(--space-4)',
        borderBottom: '1px solid var(--border-subtle)',
        cursor: 'pointer',
        background: selectedEndpointId === ep.id ? 'var(--bg-active)' : 'transparent',
        transition: 'background 150ms ease',
      }}
      onClick={() => onSelect(ep)}
    >
      <span className={`method-badge ${ep.method}`}>{ep.method}</span>
      <span className="mono" style={{ flex: 1, fontSize: 'var(--text-sm)', color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {ep.path}
      </span>
      {ep.auth_required ? (
        <LockOutlined style={{ color: 'var(--severity-high)', fontSize: 14 }} />
      ) : (
        <UnlockOutlined style={{ color: 'var(--text-tertiary)', fontSize: 14 }} />
      )}
    </div>
  );
};

const DiscoveryExplorer: React.FC = () => {
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [categories, setCategories] = useState<EndpointCategory | null>(null);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string | undefined>();
  const [selectedEndpoint, setSelectedEndpoint] = useState<Endpoint | null>(null);

  const fetchEndpoints = useCallback(async () => {
    setLoading(true);
    try {
      const data: any = await endpointsApi.getAll(500, 0, selectedCategory);
      const eps = Array.isArray(data) ? data : data.endpoints || [];
      setEndpoints(eps);
    } catch {
      setEndpoints([]);
    } finally {
      setLoading(false);
    }
  }, [selectedCategory]);

  useEffect(() => {
    fetchEndpoints();
    endpointsApi.getCategories().then(setCategories).catch(() => {});
  }, [fetchEndpoints]);

  const filtered = search
    ? endpoints.filter((e) =>
        e.path.toLowerCase().includes(search.toLowerCase()) ||
        e.method.toLowerCase().includes(search.toLowerCase())
      )
    : endpoints;

  return (
    <div className="fade-in">
      <div className="page-header">
        <h1>API Surface Discovery</h1>
        <p>Explore discovered API endpoints across assessments</p>
      </div>

      {/* Search & Filters */}
      <div style={{ display: 'flex', gap: 'var(--space-3)', marginBottom: 'var(--space-4)' }}>
        <Input
          prefix={<SearchOutlined style={{ color: 'var(--text-tertiary)' }} />}
          placeholder="Search endpoints by path or method..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{ flex: 1 }}
          allowClear
        />
        <Select
          placeholder="All Categories"
          value={selectedCategory}
          onChange={setSelectedCategory}
          allowClear
          style={{ width: 220 }}
          options={categories?.categories?.map((c) => ({ label: `${c} (${categories.category_counts?.[c] ?? 0})`, value: c })) || []}
        />
      </div>

      {/* Stats Bar */}
      {categories && (
        <div className="stats-grid" style={{ marginBottom: 'var(--space-4)', gridTemplateColumns: 'repeat(3, 1fr)' }}>
          <div className="stat-card">
            <span className="stat-label">Total Endpoints</span>
            <span className="stat-value">{categories.total_endpoints?.toLocaleString() ?? 0}</span>
          </div>
          <div className="stat-card">
            <span className="stat-label">Categories</span>
            <span className="stat-value">{categories.categories?.length ?? 0}</span>
          </div>
          <div className="stat-card">
            <span className="stat-label">Filtered</span>
            <span className="stat-value">{filtered.length.toLocaleString()}</span>
          </div>
        </div>
      )}

      {/* Main Layout */}
      <div style={{ display: 'grid', gridTemplateColumns: selectedEndpoint ? '1fr 400px' : '1fr', gap: 'var(--space-4)' }}>
        {/* Endpoint List */}
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <div style={{ padding: 'var(--space-3) var(--space-4)', borderBottom: '1px solid var(--border-subtle)', display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <ApiOutlined style={{ color: 'var(--accent-primary)' }} />
            <span style={{ fontWeight: 600, fontSize: 'var(--text-sm)' }}>Endpoints ({filtered.length})</span>
          </div>
          {loading ? (
            <div style={{ padding: 40, textAlign: 'center' }}><Spin /></div>
          ) : filtered.length > 0 ? (
            <List
              rowComponent={EndpointRow}
              rowProps={{
                filteredEndpoints: filtered,
                selectedEndpointId: selectedEndpoint?.id ?? null,
                onSelect: setSelectedEndpoint,
              }}
              rowCount={filtered.length}
              rowHeight={44}
              style={{ height: 560 }}
            />
          ) : (
            <Empty description="No endpoints found" style={{ padding: 40 }} />
          )}
        </div>

        {/* Detail Panel */}
        {selectedEndpoint && (
          <div className="card">
            <h3 className="section-title" style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
              <span className={`method-badge ${selectedEndpoint.method}`}>{selectedEndpoint.method}</span>
              Endpoint Detail
            </h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
              <div>
                <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 600 }}>Path</span>
                <div className="mono" style={{ marginTop: 4, fontSize: 'var(--text-sm)', wordBreak: 'break-all' }}>{selectedEndpoint.path}</div>
              </div>
              <div>
                <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 600 }}>Authentication</span>
                <div style={{ marginTop: 4 }}>
                  {selectedEndpoint.auth_required ? (
                    <Tag color="orange">{selectedEndpoint.auth_type || 'Required'}</Tag>
                  ) : (
                    <Tag>None</Tag>
                  )}
                </div>
              </div>
              {selectedEndpoint.parameters && Object.keys(selectedEndpoint.parameters).length > 0 && (
                <div>
                  <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 600 }}>Parameters</span>
                  <pre className="json-viewer" style={{ marginTop: 4, maxHeight: 200 }}>
                    {JSON.stringify(selectedEndpoint.parameters, null, 2)}
                  </pre>
                </div>
              )}
              {selectedEndpoint.request_body_schema && (
                <div>
                  <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 600 }}>Request Schema</span>
                  <pre className="json-viewer" style={{ marginTop: 4, maxHeight: 200 }}>
                    {JSON.stringify(selectedEndpoint.request_body_schema, null, 2)}
                  </pre>
                </div>
              )}
              {selectedEndpoint.response_schema && (
                <div>
                  <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 600 }}>Response Schema</span>
                  <pre className="json-viewer" style={{ marginTop: 4, maxHeight: 200 }}>
                    {JSON.stringify(selectedEndpoint.response_schema, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default DiscoveryExplorer;
