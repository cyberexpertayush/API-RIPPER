/* ============================================================
   Report Generator — Report generation and export
   ============================================================ */

import React, { useEffect, useState } from 'react';
import { Select, Empty, Spin, Button, Tag, Tabs, Card, message, Descriptions } from 'antd';
import {
  FileTextOutlined,
  DownloadOutlined,
  FileExcelOutlined,
  CodeOutlined,
  SafetyCertificateOutlined,
  ToolOutlined,
} from '@ant-design/icons';
import { useAssessmentStore } from '@/store';
import { reportsApi } from '@/services/apiClient';
import type { ExecutiveSummary, ComplianceReport } from '@/types/api';

const ReportGenerator: React.FC = () => {
  const { assessments, fetchAssessments } = useAssessmentStore();
  const [selectedAssessment, setSelectedAssessment] = useState<string | undefined>();
  const [executiveSummary, setExecutiveSummary] = useState<ExecutiveSummary | null>(null);
  const [complianceReport, setComplianceReport] = useState<ComplianceReport | null>(null);
  const [remediationRoadmap, setRemediationRoadmap] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(false);
  const [generating, setGenerating] = useState<string | null>(null);

  useEffect(() => { fetchAssessments(); }, []);

  useEffect(() => {
    if (selectedAssessment) {
      setLoading(true);
      Promise.allSettled([
        reportsApi.get(selectedAssessment).then((r: any) => setExecutiveSummary(r || null)),
        reportsApi.getCompliance(selectedAssessment).then((r: any) => setComplianceReport(r)),
        reportsApi.getRemediationRoadmap(selectedAssessment).then((r: any) => setRemediationRoadmap(r)),
      ]).finally(() => setLoading(false));
    }
  }, [selectedAssessment]);

  const handleGenerate = async (format: string) => {
    if (!selectedAssessment) return;
    setGenerating(format);
    try {
      await reportsApi.generate(selectedAssessment, format);
      message.success(`${format.toUpperCase()} report generation started`);
    } catch {
      message.error(`Failed to generate ${format} report`);
    } finally {
      setGenerating(null);
    }
  };

  const handleDownload = async (format: string) => {
    if (!selectedAssessment) return;
    try {
      let data;
      if (format === 'json') data = await reportsApi.getJson(selectedAssessment);
      else if (format === 'csv') data = await reportsApi.getCsv(selectedAssessment);
      else {
        // Detailed HTML report
        const res = await reportsApi.getDetailed(selectedAssessment);
        data = (res as any).html || res;
      }

      const blob = new Blob([typeof data === 'string' ? data : JSON.stringify(data, null, 2)], {
        type: format === 'json' ? 'application/json' : format === 'csv' ? 'text/csv' : 'text/html',
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `assessment_${selectedAssessment}_report.${format}`;
      a.click();
      URL.revokeObjectURL(url);
      message.success(`${format.toUpperCase()} downloaded`);
    } catch {
      message.error(`Failed to download ${format} report`);
    }
  };

  return (
    <div className="fade-in">
      <div className="page-header">
        <h1>Report Generator</h1>
        <p>Generate and export comprehensive security assessment reports</p>
      </div>

      <div style={{ display: 'flex', gap: 'var(--space-3)', marginBottom: 'var(--space-6)' }}>
        <Select
          placeholder="Select Assessment"
          value={selectedAssessment}
          onChange={setSelectedAssessment}
          style={{ width: 350 }}
          options={assessments.map((a) => ({ label: `${a.assessment_name || 'Untitled'} (#${a.id})`, value: a.id }))}
        />
      </div>

      {!selectedAssessment ? (
        <div className="card" style={{ textAlign: 'center', padding: 60 }}>
          <FileTextOutlined style={{ fontSize: 48, color: 'var(--text-tertiary)', marginBottom: 16 }} />
          <p style={{ color: 'var(--text-tertiary)' }}>Select an assessment to generate reports</p>
        </div>
      ) : loading ? (
        <div style={{ padding: 40, textAlign: 'center' }}><Spin size="large" /></div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: '300px 1fr', gap: 'var(--space-4)' }}>
          {/* Export Sidebar */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
            <div className="card">
              <h3 className="section-title">Generate Report</h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
                {[
                  { key: 'executive', label: 'Executive Summary', icon: <FileTextOutlined /> },
                  { key: 'detailed', label: 'Technical Report', icon: <CodeOutlined /> },
                  { key: 'compliance', label: 'Compliance Report', icon: <SafetyCertificateOutlined /> },
                  { key: 'remediation', label: 'Remediation Roadmap', icon: <ToolOutlined /> },
                ].map(({ key, label, icon }) => (
                  <Button
                    key={key}
                    icon={icon}
                    loading={generating === key}
                    onClick={() => handleGenerate(key)}
                    block
                    style={{ justifyContent: 'flex-start' }}
                  >
                    {label}
                  </Button>
                ))}
              </div>
            </div>

            <div className="card">
              <h3 className="section-title">Export</h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
                <Button icon={<CodeOutlined />} onClick={() => handleDownload('json')} block style={{ justifyContent: 'flex-start' }}>
                  Download JSON
                </Button>
                <Button icon={<FileExcelOutlined />} onClick={() => handleDownload('csv')} block style={{ justifyContent: 'flex-start' }}>
                  Download CSV
                </Button>
                <Button icon={<DownloadOutlined />} onClick={() => handleDownload('html')} block style={{ justifyContent: 'flex-start' }}>
                  Download HTML
                </Button>
              </div>
            </div>
          </div>

          {/* Report Preview */}
          <div className="card" style={{ overflow: 'auto', maxHeight: 'calc(100vh - 250px)' }}>
            <Tabs items={[
              {
                key: 'executive',
                label: 'Executive Summary',
                children: executiveSummary ? (
                  <div>
                    <Descriptions
                      column={2}
                      size="small"
                      labelStyle={{ color: 'var(--text-tertiary)', fontWeight: 600 }}
                      contentStyle={{ color: 'var(--text-primary)' }}
                    >
                      <Descriptions.Item label="Assessment">{executiveSummary.assessment_title || executiveSummary.title}</Descriptions.Item>
                      <Descriptions.Item label="Target">{executiveSummary.target}</Descriptions.Item>
                      <Descriptions.Item label="Date">{executiveSummary.report_date}</Descriptions.Item>
                      <Descriptions.Item label="Risk Rating">
                        <Tag color={executiveSummary.risk_rating === 'CRITICAL' ? '#ff4757' : executiveSummary.risk_rating === 'HIGH' ? '#ff8c42' : '#ffc312'}>
                          {executiveSummary.risk_rating}
                        </Tag>
                      </Descriptions.Item>
                    </Descriptions>

                    <div className="stats-grid" style={{ margin: 'var(--space-4) 0', gridTemplateColumns: 'repeat(5, 1fr)' }}>
                      {['critical', 'high', 'medium', 'low', 'info'].map((s) => (
                        <div key={s} className="stat-card" style={{ padding: 'var(--space-3)' }}>
                          <span className="stat-label">{s}</span>
                          <span className="stat-value" style={{ fontSize: 'var(--text-xl)' }}>
                            {executiveSummary.findings_summary[s as keyof typeof executiveSummary.findings_summary]}
                          </span>
                        </div>
                      ))}
                    </div>

                    {executiveSummary.key_findings?.length > 0 && (
                      <div style={{ marginTop: 'var(--space-4)' }}>
                        <h4 style={{ fontWeight: 600, marginBottom: 'var(--space-3)' }}>Key Findings</h4>
                        {executiveSummary.key_findings.map((kf) => (
                          <div key={kf.rank} style={{ display: 'flex', gap: 'var(--space-3)', padding: 'var(--space-3)', background: 'var(--bg-surface)', borderRadius: 'var(--radius-sm)', marginBottom: 'var(--space-2)' }}>
                            <span style={{ fontWeight: 800, color: 'var(--text-tertiary)' }}>#{kf.rank}</span>
                            <div style={{ flex: 1 }}>
                              <div style={{ fontWeight: 500 }}>{kf.title}</div>
                              <p style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-sm)', margin: '2px 0 0' }}>{kf.summary}</p>
                            </div>
                            <span className={`severity-badge ${kf.severity.toLowerCase()}`}>{kf.severity}</span>
                          </div>
                        ))}
                      </div>
                    )}

                    {executiveSummary.recommendations?.length > 0 && (
                      <div style={{ marginTop: 'var(--space-4)' }}>
                        <h4 style={{ fontWeight: 600, marginBottom: 'var(--space-3)' }}>Recommendations</h4>
                        {executiveSummary.recommendations.map((rec, i) => (
                          <div key={i} style={{ padding: 'var(--space-2) var(--space-3)', fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
                            <span style={{ color: 'var(--accent-primary)', fontWeight: 700 }}>{i + 1}.</span> {rec}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ) : (
                  <Empty description="No executive summary available. Click 'Generate' to create one." />
                ),
              },
              {
                key: 'compliance',
                label: 'Compliance',
                children: complianceReport ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
                    {Object.entries(complianceReport.compliance_frameworks).map(([framework, data]: [string, any]) => (
                      <Card key={framework} size="small" title={framework} style={{ background: 'var(--bg-surface)', borderColor: 'var(--border-subtle)' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                          <div>
                            <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>{data.findings}</div>
                            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', marginTop: 4 }}>{data.action_required}</div>
                          </div>
                          <Tag color={data.status === 'compliant' ? 'green' : data.status === 'partial' ? 'orange' : 'red'}>
                            {data.status}
                          </Tag>
                        </div>
                      </Card>
                    ))}
                  </div>
                ) : (
                  <Empty description="No compliance report available" />
                ),
              },
              {
                key: 'remediation',
                label: 'Remediation Roadmap',
                children: remediationRoadmap ? (
                  <pre className="json-viewer" style={{ maxHeight: 500 }}>
                    {JSON.stringify(remediationRoadmap, null, 2)}
                  </pre>
                ) : (
                  <Empty description="No remediation roadmap available" />
                ),
              },
            ]} />
          </div>
        </div>
      )}
    </div>
  );
};

export default ReportGenerator;
