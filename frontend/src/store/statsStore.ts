import { create } from 'zustand';
import { apiClient } from '@/services/apiClient';

interface Stats {
  total_assessments: number;
  total_endpoints: number;
  total_vulnerabilities: number;
  critical_vulnerabilities: number;
  high_vulnerabilities: number;
  // Enhanced fields from new stats API
  risk_score: number;
  severity_breakdown: Record<string, number>;
  owasp_coverage: Record<string, number>;
  scan_trend: Array<{
    scan_id: string;
    name: string;
    date: string;
    findings: number;
    duration: number | null;
  }>;
}

interface StatsStore {
  stats: Stats | null;
  loading: boolean;
  error: string | null;
  fetchStats: () => Promise<void>;
}

export const useStatsStore = create<StatsStore>((set) => ({
  stats: null,
  loading: false,
  error: null,
  fetchStats: async () => {
    set({ loading: true, error: null });
    try {
      const data: any = await apiClient.get('/stats');
      // Map backend field names to what frontend expects
      const severity = data.severity_breakdown || {};
      set({
        stats: {
          total_assessments: data.total_scans || 0,
          total_endpoints: data.total_endpoints || 0,
          total_vulnerabilities: data.total_findings || 0,
          critical_vulnerabilities: severity.critical || severity.CRITICAL || 0,
          high_vulnerabilities: severity.high || severity.HIGH || 0,
          risk_score: data.risk_score || 0,
          severity_breakdown: severity,
          owasp_coverage: data.owasp_coverage || {},
          scan_trend: data.scan_trend || [],
        },
        loading: false,
      });
    } catch (error) {
      set({ error: 'Failed to fetch stats', loading: false });
    }
  },
}));
