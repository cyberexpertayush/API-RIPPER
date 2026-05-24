import { create } from 'zustand';
import { riskApi } from '@/services/apiClient';

interface RiskAnalysis {
  id: string;
  assessment_id: string;
  risk_score: number;
  risk_level: 'critical' | 'high' | 'medium' | 'low';
  findings: any[];
  recommendations: string[];
}

interface RiskStore {
  riskAnalysis: RiskAnalysis | null;
  loading: boolean;
  error: string | null;
  riskLevel: 'critical' | 'high' | 'medium' | 'low';
  riskScore: number;
  fetchRiskAnalysis: (assessmentId: number | string) => Promise<void>;
  setRiskLevel: (level: 'critical' | 'high' | 'medium' | 'low') => void;
  setRiskScore: (score: number) => void;
}

export const useRiskStore = create<RiskStore>((set) => ({
  riskAnalysis: null,
  loading: false,
  error: null,
  riskLevel: 'medium',
  riskScore: 0,
  fetchRiskAnalysis: async (assessmentId: number | string) => {
    set({ loading: true, error: null });
    try {
      const data = await riskApi.getRiskMatrix(assessmentId);
      set({ 
        riskAnalysis: data as RiskAnalysis, 
        loading: false,
        riskScore: (data as any)?.risk_score || 0,
        riskLevel: (data as any)?.risk_level || 'medium'
      });
    } catch (error) {
      set({ error: 'Failed to fetch risk analysis', loading: false });
    }
  },
  setRiskLevel: (level) => set({ riskLevel: level }),
  setRiskScore: (score) => set({ riskScore: score }),
}));
