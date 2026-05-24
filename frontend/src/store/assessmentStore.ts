import { create } from 'zustand';
import { apiClient } from '@/services/apiClient';

export interface Assessment {
  id: string;
  target_url: string;
  assessment_name: string;
  scan_name?: string;
  status: string;
  scan_type?: string;
  exploit_mode?: string;    // 'standard' | 'full_auth'
  endpoints_discovered: number;
  vulnerabilities_found: number;
  critical_count: number;
  high_count: number;
  medium_count?: number;
  low_count?: number;
  confidence: number;
  progress_percentage?: number;
  progress_percent?: number;
  phase_name?: string;
  total_findings?: number;
  created_at?: string;
  completed_at?: string;
}

interface AssessmentStore {
  assessments: Assessment[];
  currentAssessment: Assessment | null;
  loading: boolean;
  error: string | null;
  fetchAssessments: (offset?: number, limit?: number) => Promise<void>;
  fetchAssessment: (id: string) => Promise<void>;
  createAssessment: (data: any) => Promise<Assessment | null>;
  deleteAssessment: (id: string) => Promise<void>;
  executeAssessment: (id: string) => Promise<void>;
  cancelAssessment: (id: string) => Promise<void>;
  updateProgress: (id: string, progress: any) => void;
}

function normalizeScan(raw: any): Assessment {
  return {
    id: raw.id,
    target_url: raw.target_url,
    assessment_name: raw.scan_name || raw.assessment_name || 'Untitled',
    scan_name: raw.scan_name,
    status: raw.status,
    scan_type: raw.scan_type || 'full',
    exploit_mode: raw.exploit_mode || 'standard',
    endpoints_discovered: raw.endpoints_discovered || 0,
    vulnerabilities_found: raw.vulnerabilities_found || 0,
    critical_count: raw.critical_count || 0,
    high_count: raw.high_count || 0,
    medium_count: raw.medium_count || 0,
    low_count: raw.low_count || 0,
    confidence: raw.confidence || 0,
    progress_percentage: raw.progress_percentage || 0,
    progress_percent: raw.progress_percentage || 0,
    phase_name: raw.phase_name || 'Initialization',
    total_findings: raw.vulnerabilities_found || 0,
    created_at: raw.created_at,
    completed_at: raw.completed_at,
  };
}

export const useAssessmentStore = create<AssessmentStore>((set) => ({
  assessments: [],
  currentAssessment: null,
  loading: false,
  error: null,

  fetchAssessments: async (offset = 0, limit = 50) => {
    set({ loading: true, error: null });
    try {
      const data = await apiClient.get('/scans', { params: { limit, offset } });
      const list = Array.isArray(data) ? data : [];
      set({ assessments: list.map(normalizeScan), loading: false });
    } catch (error: any) {
      set({ error: error?.message || 'Failed to fetch scans', loading: false });
    }
  },

  fetchAssessment: async (id: string) => {
    set({ loading: true, error: null });
    try {
      const data = await apiClient.get(`/scans/${id}`);
      set({ currentAssessment: normalizeScan(data), loading: false });
    } catch (error: any) {
      set({ error: error?.message || 'Failed to fetch scan', loading: false });
    }
  },

  createAssessment: async (assessmentData: any) => {
    set({ loading: true, error: null });
    try {
      const data = await apiClient.post('/scans', {
        target_url: assessmentData.target_url,
        scan_name: assessmentData.assessment_name || assessmentData.scan_name || 'New Scan',
        description: assessmentData.description || '',
        scan_type: assessmentData.scan_type || 'full',
        exploit_mode: assessmentData.exploit_mode || 'standard',
        auth_config: assessmentData.auth_config || {},
      });
      const normalized = normalizeScan(data);
      set((state) => ({
        assessments: [normalized, ...state.assessments],
        loading: false,
      }));
      return normalized;
    } catch (error: any) {
      set({ error: error?.message || 'Failed to create scan', loading: false });
      return null;
    }
  },

  deleteAssessment: async (id: string) => {
    try {
      await apiClient.delete(`/scans/${id}`);
      set((state) => ({
        assessments: state.assessments.filter((a) => a.id !== id),
      }));
    } catch (error: any) {
      set({ error: error?.message || 'Failed to delete scan' });
    }
  },

  executeAssessment: async (id: string) => {
    try {
      await apiClient.post(`/scans/${id}/execute`);
      set((state) => ({
        assessments: state.assessments.map((a) =>
          a.id === id ? { ...a, status: 'running' } : a
        ),
      }));
    } catch (error: any) {
      set({ error: error?.message || 'Failed to execute scan' });
    }
  },

  cancelAssessment: async (id: string) => {
    try {
      await apiClient.post(`/scans/${id}/cancel`);
      set((state) => ({
        assessments: state.assessments.map((a) =>
          a.id === id ? { ...a, status: 'cancelled' } : a
        ),
      }));
    } catch (error: any) {
      set({ error: error?.message || 'Failed to cancel scan' });
    }
  },

  updateProgress: (id: string, progress: any) => {
    set((state) => ({
      assessments: state.assessments.map((a) =>
        a.id === id ? { ...a, ...progress } : a
      ),
    }));
  },
}));
