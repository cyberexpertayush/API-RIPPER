/* ============================================================
   Payload Mutation View — Payload variant viewer
   ============================================================ */

import React, { useEffect, useState } from 'react';
import { Select, Empty, Spin, Tag, Input, Collapse } from 'antd';
import { ExperimentOutlined, SearchOutlined, SwapOutlined } from '@ant-design/icons';
import { useAssessmentStore } from '@/store';
import { findingsApi } from '@/services/apiClient';
import type { Finding } from '@/types/api';

interface MutationInfo {
  original: string;
  mutated: string;
  strategy: string;
  rationale: string;
  response_diff: string;
}

const PayloadMutationView: React.FC = () => {
  const { assessments, fetchAssessments } = useAssessmentStore();
  const [selectedAssessment, setSelectedAssessment] = useState<string | undefined>();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');

  useEffect(() => { fetchAssessments(); }, []);

  useEffect(() => {
    if (selectedAssessment) {
      setLoading(true);
      findingsApi.list(selectedAssessment)
        .then((res) => setFindings(res.data || []))
        .catch(() => setFindings([]))
        .finally(() => setLoading(false));
    }
  }, [selectedAssessment]);

  const filtered = search
    ? findings.filter((f) =>
        f.title.toLowerCase().includes(search.toLowerCase()) ||
        f.vulnerability_type.toLowerCase().includes(search.toLowerCase())
      )
    : findings;

  // Extract mutation data from evidence
  const getMutations = (finding: Finding): MutationInfo[] => {
    if (!finding.evidence) return [];
    const evidence = finding.evidence as Record<string, unknown>;
    const mutations: MutationInfo[] = [];

    if (evidence.payload_used) {
      mutations.push({
        original: String(evidence.original_value || 'N/A'),
        mutated: String(evidence.payload_used),
        strategy: String(evidence.mutation_strategy || finding.vulnerability_type),
        rationale: String(evidence.mutation_rationale || `Targeted ${finding.vulnerability_type} vulnerability`),
        response_diff: String(evidence.response_diff || 'Response behavior changed'),
      });
    }

    // Check for attack chain payloads
    if (finding.attack_chain_json && Array.isArray(finding.attack_chain_json)) {
      (finding.attack_chain_json as Record<string, unknown>[]).forEach((step) => {
        if (step.payload) {
          mutations.push({
            original: String(step.original || 'N/A'),
            mutated: String(step.payload),
            strategy: String(step.technique || 'chain'),
            rationale: String(step.rationale || 'Part of attack chain'),
            response_diff: String(step.observed_effect || 'N/A'),
          });
        }
      });
    }

    // Fallback: generate from finding data
    if (mutations.length === 0) {
      mutations.push({
        original: 'Standard parameter value',
        mutated: finding.description?.substring(0, 100) || 'Mutation applied',
        strategy: finding.vulnerability_type,
        rationale: `Testing for ${finding.vulnerability_type}`,
        response_diff: `Severity: ${finding.severity}, Confidence: ${Math.round((finding.confidence || 0) * 100)}%`,
      });
    }

    return mutations;
  };

  return (
    <div className="fade-in">
      <div className="page-header">
        <h1>Payload Mutations</h1>
        <p>Explore payload variants and mutation strategies used during testing</p>
      </div>

      <div style={{ display: 'flex', gap: 'var(--space-3)', marginBottom: 'var(--space-4)' }}>
        <Select
          placeholder="Select Assessment"
          value={selectedAssessment}
          onChange={setSelectedAssessment}
          style={{ width: 350 }}
          options={assessments.map((a) => ({ label: `${a.assessment_name || 'Untitled'} (#${a.id})`, value: a.id }))}
        />
        <Input
          prefix={<SearchOutlined style={{ color: 'var(--text-tertiary)' }} />}
          placeholder="Search payloads..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          allowClear
          style={{ flex: 1 }}
        />
      </div>

      {!selectedAssessment ? (
        <div className="card" style={{ textAlign: 'center', padding: 60 }}>
          <ExperimentOutlined style={{ fontSize: 48, color: 'var(--text-tertiary)', marginBottom: 16 }} />
          <p style={{ color: 'var(--text-tertiary)' }}>Select an assessment to view payload mutations</p>
        </div>
      ) : loading ? (
        <div style={{ padding: 40, textAlign: 'center' }}><Spin size="large" /></div>
      ) : filtered.length > 0 ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
          {filtered.map((f) => {
            const mutations = getMutations(f);
            return (
              <div key={f.id} className="card">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--space-3)' }}>
                  <div>
                    <h3 style={{ fontWeight: 600, fontSize: 'var(--text-base)' }}>{f.title}</h3>
                    <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)' }}>{f.vulnerability_type}</span>
                  </div>
                  <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
                    <span className={`severity-badge ${f.severity.toLowerCase()}`}>{f.severity}</span>
                    <Tag>{mutations.length} variant{mutations.length !== 1 ? 's' : ''}</Tag>
                  </div>
                </div>

                <Collapse ghost items={mutations.map((m, i) => ({
                  key: i,
                  label: (
                    <span style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                      <Tag color="blue">{m.strategy}</Tag>
                      <span className="mono" style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: 400 }}>
                        {m.mutated.substring(0, 60)}...
                      </span>
                    </span>
                  ),
                  children: (
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 40px 1fr', gap: 'var(--space-3)', alignItems: 'start' }}>
                      <div>
                        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', fontWeight: 600, textTransform: 'uppercase' }}>Original</span>
                        <pre className="json-viewer" style={{ marginTop: 4, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{m.original}</pre>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', paddingTop: 24 }}>
                        <SwapOutlined style={{ fontSize: 20, color: 'var(--accent-primary)' }} />
                      </div>
                      <div>
                        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', fontWeight: 600, textTransform: 'uppercase' }}>Mutated</span>
                        <pre className="json-viewer" style={{ marginTop: 4, whiteSpace: 'pre-wrap', wordBreak: 'break-all', borderColor: 'var(--accent-primary)' }}>{m.mutated}</pre>
                      </div>
                      <div style={{ gridColumn: '1 / -1' }}>
                        <div style={{ display: 'flex', gap: 'var(--space-4)', marginTop: 'var(--space-2)' }}>
                          <div style={{ flex: 1 }}>
                            <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', fontWeight: 600 }}>RATIONALE</span>
                            <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', margin: '4px 0 0' }}>{m.rationale}</p>
                          </div>
                          <div style={{ flex: 1 }}>
                            <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', fontWeight: 600 }}>RESPONSE DIFF</span>
                            <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', margin: '4px 0 0' }}>{m.response_diff}</p>
                          </div>
                        </div>
                      </div>
                    </div>
                  ),
                }))} />
              </div>
            );
          })}
        </div>
      ) : (
        <Empty description="No payload mutation data available" />
      )}
    </div>
  );
};

export default PayloadMutationView;
