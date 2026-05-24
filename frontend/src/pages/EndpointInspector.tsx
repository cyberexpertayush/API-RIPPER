/* ============================================================
   Endpoint Inspector — Split-panel endpoint detail viewer
   ============================================================ */

import React, { useEffect, useState } from 'react';
import { Input, Tag, Empty, Spin, Collapse, Table } from 'antd';
import { SearchOutlined, LockOutlined, UnlockOutlined, CodeOutlined } from '@ant-design/icons';
import { endpointsApi } from '@/services/apiClient';
import type { Endpoint } from '@/types/api';

interface EndpointResult {
  endpoints: Endpoint[];
  total: number;
}

const JsonTree: React.FC<{ data: unknown; depth?: number }> = ({ data, depth = 0 }) => {
  if (data === null || data === undefined) return <span className="json-null">null</span>;
  if (typeof data === 'string') return <span className="json-string">"{data}"</span>;
  if (typeof data === 'number') return <span className="json-number">{data}</span>;
  if (typeof data === 'boolean') return <span className="json-boolean">{String(data)}</span>;

  if (Array.isArray(data)) {
    return (
      <div style={{ paddingLeft: depth > 0 ? 16 : 0 }}>
        {'['}
        {data.map((item, i) => (
          <div key={i} style={{ paddingLeft: 16 }}>
            <JsonTree data={item} depth={depth + 1} />{i < data.length - 1 ? ',' : ''}
          </div>
        ))}
        {']'}
      </div>
    );
  }

  if (typeof data === 'object') {
    const entries = Object.entries(data as Record<string, unknown>);
    return (
      <div style={{ paddingLeft: depth > 0 ? 16 : 0 }}>
        {'{'}
        {entries.map(([key, value], i) => (
          <div key={key} style={{ paddingLeft: 16 }}>
            <span className="json-key">"{key}"</span>: <JsonTree data={value} depth={depth + 1} />{i < entries.length - 1 ? ',' : ''}
          </div>
        ))}
        {'}'}
      </div>
    );
  }

  return <span>{String(data)}</span>;
};

const EndpointInspector: React.FC = () => {
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState<Endpoint | null>(null);

  useEffect(() => {
    setLoading(true);
    endpointsApi.getAll(200)
      .then((data: any) => {
        // Handle both array and object response formats
        const eps = Array.isArray(data) ? data : data.endpoints || [];
        setEndpoints(eps);
      })
      .catch(() => setEndpoints([]))
      .finally(() => setLoading(false));
  }, []);

  const filtered = search
    ? endpoints.filter((e) => e.path.toLowerCase().includes(search.toLowerCase()))
    : endpoints;

  const paramColumns = [
    { title: 'Name', dataIndex: 'name', key: 'name', render: (v: string) => <span className="mono">{v}</span> },
    { title: 'Type', dataIndex: 'type', key: 'type' },
    { title: 'Required', dataIndex: 'required', key: 'required', render: (v: boolean) => v ? <Tag color="orange">Yes</Tag> : <Tag>No</Tag> },
  ];

  const paramData = selected?.parameters
    ? Object.entries(selected.parameters).map(([name, info]) => ({
        key: name,
        name,
        type: typeof info === 'object' && info !== null && 'type' in info ? String((info as Record<string, unknown>).type) : typeof info,
        required: typeof info === 'object' && info !== null && 'required' in info ? Boolean((info as Record<string, unknown>).required) : false,
      }))
    : [];

  return (
    <div className="fade-in">
      <div className="page-header">
        <h1>Endpoint Inspector</h1>
        <p>Deep-dive into individual endpoint specifications</p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '380px 1fr', gap: 'var(--space-4)', height: 'calc(100vh - 200px)' }}>
        {/* Left: Endpoint List */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden', padding: 0 }}>
          <div style={{ padding: 'var(--space-3)' }}>
            <Input
              prefix={<SearchOutlined style={{ color: 'var(--text-tertiary)' }} />}
              placeholder="Filter endpoints..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              allowClear
              size="small"
            />
          </div>
          <div style={{ flex: 1, overflowY: 'auto' }}>
            {loading ? (
              <div style={{ padding: 40, textAlign: 'center' }}><Spin /></div>
            ) : filtered.length > 0 ? (
              filtered.map((ep) => (
                <div
                  key={ep.id}
                  onClick={() => setSelected(ep)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 'var(--space-2)',
                    padding: 'var(--space-2) var(--space-3)',
                    cursor: 'pointer',
                    background: selected?.id === ep.id ? 'var(--bg-active)' : 'transparent',
                    borderBottom: '1px solid var(--border-subtle)',
                    transition: 'background 150ms',
                  }}
                >
                  <span className={`method-badge ${ep.method}`} style={{ fontSize: '10px', minWidth: 42 }}>{ep.method}</span>
                  <span className="mono" style={{ flex: 1, fontSize: 'var(--text-xs)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {ep.path}
                  </span>
                  {ep.auth_required ? <LockOutlined style={{ fontSize: 12, color: 'var(--severity-high)' }} /> : <UnlockOutlined style={{ fontSize: 12, color: 'var(--text-tertiary)' }} />}
                </div>
              ))
            ) : (
              <Empty description="No endpoints" style={{ padding: 24 }} />
            )}
          </div>
        </div>

        {/* Right: Detail Panel */}
        <div className="card" style={{ overflow: 'auto' }}>
          {selected ? (
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', marginBottom: 'var(--space-6)' }}>
                <span className={`method-badge ${selected.method}`}>{selected.method}</span>
                <h2 className="mono" style={{ fontSize: 'var(--text-base)', fontWeight: 600, wordBreak: 'break-all' }}>{selected.path}</h2>
              </div>

              <div style={{ display: 'flex', gap: 'var(--space-3)', marginBottom: 'var(--space-6)' }}>
                <Tag color={selected.auth_required ? 'orange' : 'green'}>
                  {selected.auth_required ? `Auth: ${selected.auth_type || 'Required'}` : 'No Auth'}
                </Tag>
              </div>

              <Collapse
                defaultActiveKey={['params', 'request', 'response']}
                ghost
                items={[
                  ...(paramData.length > 0 ? [{
                    key: 'params',
                    label: <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}><CodeOutlined /> Parameters ({paramData.length})</span>,
                    children: <Table columns={paramColumns} dataSource={paramData} pagination={false} size="small" />
                  }] : []),
                  ...(selected.request_body_schema ? [{
                    key: 'request',
                    label: <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>Request Body Schema</span>,
                    children: <div className="json-viewer"><JsonTree data={selected.request_body_schema} /></div>
                  }] : []),
                  ...(selected.response_schema ? [{
                    key: 'response',
                    label: <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>Response Schema</span>,
                    children: <div className="json-viewer"><JsonTree data={selected.response_schema} /></div>
                  }] : []),
                ]}
              />
              {!paramData.length && !selected.request_body_schema && !selected.response_schema && (
                <Empty description="No schema data available" style={{ marginTop: 24 }} />
              )}
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--text-tertiary)' }}>
              <CodeOutlined style={{ fontSize: 48, marginBottom: 16 }} />
              <p>Select an endpoint to inspect</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default EndpointInspector;
