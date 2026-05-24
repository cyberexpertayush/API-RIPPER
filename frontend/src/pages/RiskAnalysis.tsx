/* ============================================================
   Risk Analysis — Comprehensive risk dashboard
   ============================================================ */

import React, { useEffect, useState } from 'react';
import { Select, Empty, Spin, Tag, Progress } from 'antd';
import {
  BarChartOutlined,
  SafetyCertificateOutlined,
  WarningOutlined,
  AlertOutlined,
} from '@ant-design/icons';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell,
} from 'recharts';
import { useAssessmentStore, useRiskStore } from '@/store';
import { riskApi } from '@/services/apiClient';

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ff4757',
  HIGH: '#ff8c42',
  MEDIUM: '#ffc312',
  LOW: '#00e87b',
  INFO: '#3b82f6',
};

const COMPLIANCE_COLORS: Record<string, string> = {
  compliant: '#00e87b',
  partial: '#ffc312',
  'non-compliant': '#ff4757',
  unknown: '#6b7280',
};

interface RiskMatrixData {
  matrix: { likelihood: string; impact: string; count: number; severity: string }[];
}

const RiskAnalysis: React.FC = () => {
  const { assessments, fetchAssessments } = useAssessmentStore();
  const { riskAnalysis, loading: riskLoading, fetchRiskAnalysis } = useRiskStore();
  const [selectedAssessment, setSelectedAssessment] = useState<string | undefined>();
  const [_riskMatrix, setRiskMatrix] = useState<RiskMatrixData | null>(null);
  const [_businessImpact, setBusinessImpact] = useState<Record<string, unknown> | null>(null);

  useEffect(() => { fetchAssessments(); }, []);

  useEffect(() => {
    if (selectedAssessment) {
      fetchRiskAnalysis(selectedAssessment);
      riskApi.getRiskMatrix(selectedAssessment).then((r: any) => setRiskMatrix(r)).catch(() => setRiskMatrix(null));
      riskApi.getBusinessImpact(selectedAssessment).then((r: any) => setBusinessImpact(r)).catch(() => setBusinessImpact(null));
    }
  }, [selectedAssessment]);

  const riskColor = (score: number) => score >= 8 ? '#ff4757' : score >= 6 ? '#ff8c42' : score >= 4 ? '#ffc312' : '#00e87b';

  return (
    <div className="fade-in">
      <div className="page-header">
        <h1>Risk Analysis</h1>
        <p>Comprehensive security risk assessment and compliance status</p>
      </div>

      <Select
        placeholder="Select Assessment"
        value={selectedAssessment}
        onChange={setSelectedAssessment}
        style={{ width: 350, marginBottom: 'var(--space-6)' }}
        options={assessments.map((a) => ({ label: `${a.assessment_name || 'Untitled'} (#${a.id})`, value: a.id }))}
      />

      {!selectedAssessment ? (
        <div className="card" style={{ textAlign: 'center', padding: 60 }}>
          <BarChartOutlined style={{ fontSize: 48, color: 'var(--text-tertiary)', marginBottom: 16 }} />
          <p style={{ color: 'var(--text-tertiary)' }}>Select an assessment to view risk analysis</p>
        </div>
      ) : riskLoading ? (
        <div style={{ padding: 40, textAlign: 'center' }}><Spin size="large" /></div>
      ) : riskAnalysis ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-6)' }}>
          {/* Overall Risk Score */}
          <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)' }}>
            <div className="stat-card" style={{ borderTopColor: riskColor(riskAnalysis.overall_risk.risk_score), borderTopWidth: 3, borderTopStyle: 'solid' }}>
              <span className="stat-label">Overall Risk Score</span>
              <span className="stat-value" style={{ color: riskColor(riskAnalysis.overall_risk.risk_score) }}>
                {riskAnalysis.overall_risk.risk_score.toFixed(1)}
              </span>
              <Tag color={riskColor(riskAnalysis.overall_risk.risk_score)}>{riskAnalysis.overall_risk.rating}</Tag>
            </div>
            <div className="stat-card">
              <span className="stat-label">Confidence Level</span>
              <span className="stat-value">{Math.round(riskAnalysis.overall_risk.confidence_level * 100)}%</span>
              <Progress percent={Math.round(riskAnalysis.overall_risk.confidence_level * 100)} size="small" strokeColor="#3b82f6" trailColor="#21262d" showInfo={false} />
            </div>
            <div className="stat-card">
              <span className="stat-label">Total Vulnerabilities</span>
              <span className="stat-value">{riskAnalysis.vulnerability_stats.total}</span>
            </div>
            <div className="stat-card critical">
              <span className="stat-label">Critical + High</span>
              <span className="stat-value">{riskAnalysis.vulnerability_stats.critical + riskAnalysis.vulnerability_stats.high}</span>
            </div>
          </div>

          {/* Charts Row */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-4)' }}>
            {/* CVSS Distribution */}
            <div className="card">
              <h3 className="section-title">CVSS Score Distribution</h3>
              <ResponsiveContainer width="100%" height={250}>
                <BarChart data={Object.entries(riskAnalysis.cvss_analysis.distribution).map(([range, count]) => ({ range, count }))}>
                  <XAxis dataKey="range" tick={{ fill: '#8b949e', fontSize: 11 }} />
                  <YAxis tick={{ fill: '#8b949e', fontSize: 11 }} />
                  <Tooltip contentStyle={{ background: '#161b22', border: '1px solid #30363d', borderRadius: 8 }} />
                  <Bar dataKey="count" fill="#3b82f6" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 'var(--space-2)', fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)' }}>
                <span>Avg CVSS: {riskAnalysis.cvss_analysis.average_cvss.toFixed(1)}</span>
                <span>Highest: {riskAnalysis.cvss_analysis.highest_cvss.toFixed(1)}</span>
              </div>
            </div>

            {/* Severity Distribution Pie */}
            <div className="card">
              <h3 className="section-title">Severity Breakdown</h3>
              <ResponsiveContainer width="100%" height={250}>
                <PieChart>
                  <Pie
                    data={['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
                      .map((s) => ({ name: s, value: riskAnalysis.vulnerability_stats[s.toLowerCase() as keyof typeof riskAnalysis.vulnerability_stats] as number }))
                      .filter((d) => d.value > 0)}
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={85}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((s) => (
                      <Cell key={s} fill={SEVERITY_COLORS[s]} stroke="transparent" />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ background: '#161b22', border: '1px solid #30363d', borderRadius: 8 }} />
                </PieChart>
              </ResponsiveContainer>
              <div style={{ display: 'flex', justifyContent: 'center', gap: 'var(--space-3)', flexWrap: 'wrap' }}>
                {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((s) => {
                  const count = riskAnalysis.vulnerability_stats[s.toLowerCase() as keyof typeof riskAnalysis.vulnerability_stats] as number;
                  if (!count) return null;
                  return (
                    <div key={s} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 'var(--text-xs)' }}>
                      <span style={{ width: 8, height: 8, borderRadius: '50%', background: SEVERITY_COLORS[s] }} />
                      <span style={{ color: 'var(--text-secondary)' }}>{s}: {count}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Business Impact */}
          {riskAnalysis.business_impact && (
            <div className="card">
              <h3 className="section-title"><AlertOutlined /> Business Impact Assessment</h3>
              <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(5, 1fr)' }}>
                {Object.entries(riskAnalysis.business_impact).map(([key, value]) => (
                  <div key={key} className="stat-card">
                    <span className="stat-label">{key.replace(/_/g, ' ')}</span>
                    <Tag color={
                      value === 'CRITICAL' ? '#ff4757' :
                      value === 'HIGH' ? '#ff8c42' :
                      value === 'MEDIUM' ? '#ffc312' :
                      value === 'LOW' ? '#00e87b' : '#3b82f6'
                    }>{String(value)}</Tag>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Top Risks + Remediation Priority */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-4)' }}>
            <div className="card">
              <h3 className="section-title"><WarningOutlined /> Top Risks</h3>
              {riskAnalysis.top_risks?.length > 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
                  {riskAnalysis.top_risks.map((risk) => (
                    <div key={risk.rank} style={{ display: 'flex', gap: 'var(--space-3)', alignItems: 'center', padding: 'var(--space-3)', background: 'var(--bg-surface)', borderRadius: 'var(--radius-sm)' }}>
                      <span style={{ fontWeight: 800, fontSize: 'var(--text-lg)', color: 'var(--text-tertiary)', minWidth: 28 }}>#{risk.rank}</span>
                      <div style={{ flex: 1 }}>
                        <div style={{ fontWeight: 500, fontSize: 'var(--text-sm)' }}>{risk.title}</div>
                        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', marginTop: 2 }}>{risk.impact}</div>
                      </div>
                      <span className={`severity-badge ${risk.severity.toLowerCase()}`}>{risk.severity}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <Empty description="No top risks identified" />
              )}
            </div>

            <div className="card">
              <h3 className="section-title"><SafetyCertificateOutlined /> Compliance Status</h3>
              {riskAnalysis.compliance ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
                  {Object.entries(riskAnalysis.compliance).map(([framework, status]: [string, any]) => (
                    <div key={framework} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: 'var(--space-3)', background: 'var(--bg-surface)', borderRadius: 'var(--radius-sm)' }}>
                      <span style={{ fontWeight: 600, fontSize: 'var(--text-sm)' }}>{framework}</span>
                      <Tag color={COMPLIANCE_COLORS[status.toLowerCase()] || '#6b7280'}>{status}</Tag>
                    </div>
                  ))}
                </div>
              ) : (
                <Empty description="No compliance data" />
              )}
            </div>
          </div>

          {/* Recommendations */}
          {riskAnalysis.recommendations?.length > 0 && (
            <div className="card">
              <h3 className="section-title">Recommendations</h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
                {riskAnalysis.recommendations.map((rec, i) => (
                  <div key={i} style={{ display: 'flex', gap: 'var(--space-3)', padding: 'var(--space-3)', background: 'var(--bg-surface)', borderRadius: 'var(--radius-sm)', fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
                    <span style={{ color: 'var(--accent-primary)', fontWeight: 700 }}>{i + 1}.</span>
                    {rec}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      ) : (
        <Empty description="No risk analysis data available for this assessment" />
      )}
    </div>
  );
};

export default RiskAnalysis;
