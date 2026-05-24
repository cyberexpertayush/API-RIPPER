/* ============================================================
   Assessment List — CRUD with progress tracking
   ============================================================ */

import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Table, Button, Modal, Form, Input, Select, Switch, Space, Tag, Progress, Popconfirm, message } from 'antd';
import { PlusOutlined, DeleteOutlined, EyeOutlined, ThunderboltOutlined } from '@ant-design/icons';
import { useAssessmentStore } from '@/store';
import { assessmentApi } from '@/services/apiClient';

const AssessmentList: React.FC = () => {
  const { assessments, loading, fetchAssessments, deleteAssessment } = useAssessmentStore();
  const [modalOpen, setModalOpen] = useState(false);
  const [creating, setCreating] = useState(false);
  const [form] = Form.useForm();
  const navigate = useNavigate();

  useEffect(() => { fetchAssessments(); }, []);

  const handleCreate = async (values: Record<string, unknown>) => {
    setCreating(true);
    try {
      // Backend expects: { target_url, scan_name, description, scan_type }
      const exploitMode = values.deep_exploit_authorized ? 'full_auth' : 'standard';
      const authConfig: Record<string, unknown> = {};
      if (values.bearer_token) authConfig.bearer_token = values.bearer_token;

      const payload = {
        target_url: values.target_url as string,
        assessment_name: values.assessment_name as string,
        scan_type: values.testing_mode as string || 'full',
        exploit_mode: exploitMode,
        auth_config: authConfig,
        description: `Mode: ${exploitMode} | Type: ${values.testing_mode || 'full'} | Max Endpoints: ${values.max_endpoints || 1000}`,
      };
      const res = await assessmentApi.createAssessment(payload);
      const scanId = (res as any)?.id;

      // Auto-execute the scan so the scanning pipeline starts
      if (scanId) {
        try {
          await assessmentApi.execute(scanId);
          message.success('Scan created and scanning started!');
        } catch {
          message.success('Scan created (auto-start failed, run manually)');
        }
      } else {
        message.success('Scan created successfully');
      }

      setModalOpen(false);
      form.resetFields();
      fetchAssessments();
    } catch (e) {
      console.error('Create failed:', e);
      message.error('Failed to create scan');
    } finally {
      setCreating(false);
    }
  };

  const columns = [
    {
      title: 'ID',
      dataIndex: 'id',
      key: 'id',
      width: 90,
      render: (id: string) => <span className="mono" style={{ fontSize: 'var(--text-xs)' }}>{id.substring(0, 8)}</span>,
    },
    {
      title: 'Title',
      dataIndex: 'assessment_name',
      key: 'assessment_name',
      render: (name: string, record: any) => (
        <Link to={`/assessments/${record.id}`} style={{ fontWeight: 500 }}>{name || 'Untitled'}</Link>
      ),
    },
    {
      title: 'Target',
      dataIndex: 'target_url',
      key: 'target_url',
      render: (url: string) => <span className="mono" style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>{url}</span>,
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      width: 130,
      render: (status: string) => <span className={`status-badge ${status}`}>{status}</span>,
    },
    {
      title: 'Phase',
      dataIndex: 'phase_name',
      key: 'phase_name',
      width: 150,
      render: (phase: string) => <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>{phase || '—'}</span>,
    },
    {
      title: 'Progress',
      dataIndex: 'progress_percent',
      key: 'progress',
      width: 140,
      render: (p: number, record: any) => (
        <Progress percent={p || 0} size="small" strokeColor={record.status === 'failed' ? '#ff4757' : '#00e87b'} trailColor="#21262d" />
      ),
    },
    {
      title: 'Findings',
      key: 'findings',
      width: 160,
      render: (_: unknown, record: any) => (
        <Space size={4}>
          <Tag style={{ borderRadius: 12, margin: 0 }}>{record.total_findings ?? record.vulnerabilities_found ?? 0} total</Tag>
          {(record.critical_count ?? 0) > 0 && (
            <Tag color="#ff4757" style={{ borderRadius: 12, margin: 0 }}>{record.critical_count} critical</Tag>
          )}
        </Space>
      ),
    },
    {
      title: 'Actions',
      key: 'actions',
      width: 100,
      render: (_: unknown, record: any) => (
        <Space size={4}>
          <Button type="text" size="small" icon={<EyeOutlined />} onClick={() => navigate(`/assessments/${record.id}`)} />
          <Popconfirm title="Delete this scan?" onConfirm={() => { deleteAssessment(String(record.id)); message.success('Deleted'); }}>
            <Button type="text" size="small" icon={<DeleteOutlined />} danger />
          </Popconfirm>
        </Space>
      ),
    },
  ];

  return (
    <div className="fade-in">
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h1>Security Scans</h1>
          <p>Multi-Agent API Security Reasoning Framework</p>
        </div>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setModalOpen(true)} size="large">
          New Scan
        </Button>
      </div>

      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <Table
          columns={columns as any}
          dataSource={assessments}
          rowKey="id"
          loading={loading}
          pagination={{ pageSize: 20, showSizeChanger: false }}
          style={{ background: 'transparent' }}
        />
      </div>

      {/* Create Scan Modal */}
      <Modal
        title="New Security Scan"
        open={modalOpen}
        onCancel={() => setModalOpen(false)}
        footer={null}
        width={560}
      >
        <Form form={form} layout="vertical" onFinish={handleCreate} style={{ marginTop: 16 }}>
          <Form.Item name="assessment_name" label="Scan Title" rules={[{ required: true }]}>
            <Input placeholder="Q1 API Security Audit" />
          </Form.Item>
          <Form.Item name="target_url" label="Target URL" rules={[{ required: true }]}>
            <Input placeholder="https://api.example.com" />
          </Form.Item>
          <Form.Item name="testing_mode" label="Scan Type" initialValue="full">
            <Select>
              <Select.Option value="passive">Passive (Recon only)</Select.Option>
              <Select.Option value="full">Full Scan</Select.Option>
              <Select.Option value="api_only">API Security Only</Select.Option>
              <Select.Option value="quick">Quick Scan</Select.Option>
            </Select>
          </Form.Item>
          <Form.Item name="bearer_token" label="Bearer Token (optional)">
            <Input.Password placeholder="eyJhbGciOiJIUzI1NiIs..." />
          </Form.Item>
          <Form.Item name="max_endpoints" label="Max Endpoints" initialValue={1000}>
            <Input type="number" />
          </Form.Item>
          <div style={{ display: 'flex', gap: 24 }}>
            <Form.Item name="deep_exploit_authorized" label="Full Authorization Mode" valuePropName="checked" tooltip="Enable deep exploitation with no restrictions. Only use with explicit owner authorization.">
              <Switch />
            </Form.Item>
          </div>
          <div style={{ background: 'rgba(255,71,87,0.08)', border: '1px solid rgba(255,71,87,0.2)', borderRadius: 8, padding: '10px 14px', marginBottom: 16, fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>
            ⚠️ <strong>Full Authorization</strong> enables deep exploitation (injection, race conditions, mass assignment). Only enable when the target owner has given explicit written consent.
          </div>
          <Form.Item>
            <Button type="primary" htmlType="submit" loading={creating} icon={<ThunderboltOutlined />} block size="large">
              Launch Scan
            </Button>
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
};

export default AssessmentList;
