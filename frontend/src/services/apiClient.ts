import axios from 'axios';

const API_BASE_URL = (import.meta && import.meta.env && import.meta.env.VITE_API_BASE)
  ? String(import.meta.env.VITE_API_BASE)
  : '/api/v1';

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor
apiClient.interceptors.request.use(
  (config) => {
    const token = typeof window !== 'undefined' ? localStorage.getItem('token') : null;
    if (token && config.headers) {
      config.headers.set('Authorization', `Bearer ${token}`);
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor — unwrap data
apiClient.interceptors.response.use(
  (resp) => resp.data,
  (error) => {
    if (error?.response?.status === 401) {
      console.warn('Auth failure');
      localStorage.removeItem('token');
    }
    return Promise.reject(error?.response?.data || error?.message || error);
  }
);

export { apiClient };

// ============================================================
// API Methods — mapped to new backend routes
// ============================================================

// Scans (formerly assessments)
export const assessmentApi = {
  list: (limit = 50, offset = 0) =>
    apiClient.get('/scans', { params: { limit, offset } }),
  get: (id: string) => apiClient.get(`/scans/${id}`),
  create: (data: any) => apiClient.post('/scans', {
    target_url: data.target_url,
    scan_name: data.assessment_name || data.scan_name,
    description: data.description,
    scan_type: data.scan_type || 'full',
  }),
  createAssessment: (data: any) => apiClient.post('/scans', {
    target_url: data.target_url,
    scan_name: data.assessment_name || data.scan_name,
    description: data.description,
    scan_type: data.scan_type || 'full',
  }),
  delete: (id: string) => apiClient.delete(`/scans/${id}`),
  execute: (id: string) => apiClient.post(`/scans/${id}/execute`),
  cancel: (id: string) => apiClient.post(`/scans/${id}/cancel`),
  progress: (id: string) => apiClient.get(`/scans/${id}/progress`),
  rescan: (id: string) => apiClient.post(`/scans/${id}/rescan`),
  updateTags: (id: string, tags: string[]) => apiClient.put(`/scans/${id}/tags`, tags),
};

export const endpointsApi = {
  list: (scanId: string) =>
    apiClient.get(`/scans/${scanId}/endpoints`),
  getAll: (limit = 500, offset = 0, category?: string) =>
    apiClient.get('/endpoints', { params: { limit, offset, category } }),
  getCategories: () =>
    apiClient.get('/endpoints/categories'),
};

export const securityApi = {
  scan: (scanId: string) =>
    apiClient.post(`/scans/${scanId}/execute`),
  getGraph: (scanId: string | number) =>
    apiClient.get(`/scans/${scanId}/graph`),
};

export const findingsApi = {
  list: (scanId: string) =>
    apiClient.get(`/scans/${scanId}/findings`),
  getDetailedAnalysis: (findingId: string) =>
    apiClient.get(`/findings/${findingId}/analysis`),
  toggleFalsePositive: (findingId: string) =>
    apiClient.patch(`/findings/${findingId}/false-positive`),
};

export const riskApi = {
  getRiskMatrix: (scanId: number | string) =>
    apiClient.get(`/scans/${scanId}/report?format=json`),
  getBusinessImpact: (scanId: number | string) =>
    apiClient.get(`/scans/${scanId}/compliance`),
};

export const reportsApi = {
  get: (scanId: string) =>
    apiClient.get(`/scans/${scanId}/report`),
  getCompliance: (scanId: string) =>
    apiClient.get(`/scans/${scanId}/compliance`),
  getRemediationRoadmap: (scanId: string) =>
    apiClient.get(`/scans/${scanId}/remediation`),
  generate: (scanId: string, format: string) =>
    apiClient.get(`/scans/${scanId}/report`, { params: { format } }),
  getJson: (scanId: string) =>
    apiClient.get(`/scans/${scanId}/report?format=json`),
  getCsv: (scanId: string) =>
    apiClient.get(`/scans/${scanId}/report?format=csv`),
  getDetailed: (scanId: string) =>
    apiClient.get(`/scans/${scanId}/report?format=html`),
};

// Scan Comparison
export const comparisonApi = {
  compareFindings: (scanA: string, scanB: string) =>
    apiClient.get('/scans/compare', { params: { scan_a: scanA, scan_b: scanB } }),
  compareEndpoints: (scanA: string, scanB: string) =>
    apiClient.get('/scans/compare/endpoints', { params: { scan_a: scanA, scan_b: scanB } }),
};

// Stats for dashboard
export const statsApi = {
  get: () => apiClient.get('/stats'),
};
