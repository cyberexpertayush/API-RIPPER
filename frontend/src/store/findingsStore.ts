import { create } from 'zustand';
import { apiClient } from '@/services/apiClient';

export interface Finding {
  id: string;
  scan_id?: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  description: string;
  status: string;
  endpoint?: string;
  endpoint_url?: string;
  method?: string;
  vulnerability_type?: string;
  category?: string;
  module_name?: string;
  details?: any;
  evidence?: any[];
  remediation?: string;
  cwe_id?: string;
  cvss_score?: number;
}

interface SeverityStats {
  CRITICAL: number;
  HIGH: number;
  MEDIUM: number;
  LOW: number;
  INFO: number;
}

interface FindingsStore {
  findings: Finding[];
  loading: boolean;
  error: string | null;
  severityStats: SeverityStats | null;
  fetchFindings: (scanId: number | string, severity?: string) => Promise<void>;
  fetchAllFindings: (severity?: string) => Promise<void>;
  fetchSeverityStats: (scanId: number | string) => Promise<void>;
  setFindings: (findings: Finding[]) => void;
  addFinding: (finding: Finding) => void;
  updateFinding: (id: string, finding: Partial<Finding>) => void;
}

function normalizeFinding(raw: any): Finding {
  return {
    id: raw.id,
    scan_id: raw.scan_id,
    title: raw.title || 'Untitled Finding',
    severity: (raw.severity || 'info').toLowerCase() as Finding['severity'],
    description: raw.description || '',
    status: raw.status || 'open',
    endpoint: raw.endpoint_url || raw.endpoint || '',
    endpoint_url: raw.endpoint_url || '',
    method: raw.method || 'GET',
    vulnerability_type: raw.category || raw.vulnerability_type || '',
    category: raw.category || '',
    module_name: raw.module_name || '',
    details: raw.details || {},
    evidence: raw.evidence || [],
    remediation: raw.remediation || '',
    cwe_id: raw.cwe_id,
    cvss_score: raw.cvss_score,
  };
}

export const useFindingsStore = create<FindingsStore>((set) => ({
  findings: [],
  loading: false,
  error: null,
  severityStats: null,

  fetchFindings: async (scanId: number | string, severity?: string) => {
    set({ loading: true, error: null });
    try {
      const params: any = {};
      if (severity) params.severity = severity.toLowerCase();
      const data = await apiClient.get(`/scans/${scanId}/findings`, { params });
      const list = Array.isArray(data) ? data : [];
      set({ findings: list.map(normalizeFinding), loading: false });
    } catch (error) {
      set({ error: 'Failed to fetch findings', loading: false });
    }
  },

  fetchAllFindings: async (severity?: string) => {
    set({ loading: true, error: null });
    try {
      const params: any = {};
      if (severity) params.severity = severity.toLowerCase();
      const data = await apiClient.get('/findings', { params });
      const list = Array.isArray(data) ? data : [];
      set({ findings: list.map(normalizeFinding), loading: false });
    } catch (error) {
      set({ error: 'Failed to fetch findings', loading: false });
    }
  },

  fetchSeverityStats: async (scanId: number | string) => {
    try {
      const data = await apiClient.get(`/scans/${scanId}/findings`);
      const findings = Array.isArray(data) ? data : [];
      const stats = {
        CRITICAL: findings.filter((f: any) => (f.severity || '').toLowerCase() === 'critical').length,
        HIGH: findings.filter((f: any) => (f.severity || '').toLowerCase() === 'high').length,
        MEDIUM: findings.filter((f: any) => (f.severity || '').toLowerCase() === 'medium').length,
        LOW: findings.filter((f: any) => (f.severity || '').toLowerCase() === 'low').length,
        INFO: findings.filter((f: any) => (f.severity || '').toLowerCase() === 'info').length,
      };
      set({ severityStats: stats });
    } catch {
      set({ severityStats: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 } });
    }
  },

  setFindings: (findings) => set({ findings }),
  addFinding: (finding) =>
    set((state) => ({ findings: [finding, ...state.findings] })),
  updateFinding: (id, finding) =>
    set((state) => ({
      findings: state.findings.map((f) => (f.id === id ? { ...f, ...finding } : f)),
    })),
}));
