export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface Assessment {
  id: string;
  target_url: string;
  assessment_name: string;
  scan_name?: string;
  status: string;
  scan_type?: string;
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
  total_endpoints?: number;
  created_at?: string;
  completed_at?: string;
  started_at?: string;
  // Legacy fields — may be undefined
  current_phase?: string;
  testing_mode?: string;
  testing_tier?: string;
  scanned_endpoints?: number;
  endpoints?: Endpoint[];
  progress_logs?: any[];
}

export interface Endpoint {
  id: string;
  url: string;
  path: string;
  method: string;
  status_code?: number;
  auth_required?: boolean;
  auth_type?: string;
  requires_auth?: boolean;
  discovered_at?: string;
  parameters?: Record<string, any>;
  request_body_schema?: any;
  response_schema?: any;
}

export interface Finding {
  id: string;
  scan_id?: string;
  title: string;
  severity: string;
  description: string;
  status?: string;
  endpoint?: string;
  endpoint_url?: string;
  endpoint_id?: string;
  method?: string;
  vulnerability_type?: string;
  category?: string;
  module_name?: string;
  details?: any;
  evidence?: any[];
  remediation?: string;
  confidence?: number;
  confidence_score_10?: number;
  owasp_category?: string;
  cwe_id?: string;
  cvss_score?: number;
  // v4.0 fields
  vulnerability_class?: string;
  attack_vector?: string;
}

export interface DetailedFindingAnalysis {
  id: string;
  title: string;
  severity: string;
  description: string;
  technical_analysis?: {
    root_cause?: string;
    affected_component?: string;
    http_method?: string;
    parameter_name?: string;
  };
  exploitation?: {
    methodology?: string;
    attack_complexity?: string;
    step_by_step_guide?: string[];
  };
  advanced_techniques?: {
    poc_payloads?: string[];
  };
  impact?: {
    business_impact?: string;
    attack_scenarios?: string[];
  };
  remediation?: {
    priority?: string;
    estimated_effort?: string;
    fix_description?: string;
    code_example?: string;
  };
}

export interface Vulnerability {
  id: string;
  type: string;
  severity: string;
  description: string;
  remediation: string;
}

export interface AttackChain {
  id: string;
  steps: string[];
  success_rate: number;
}

export interface Report {
  id: string;
  scan_id: string;
  assessment_id?: string;
  title: string;
  generated_at?: string;
}

export interface WebSocketMessage {
  type: string;
  data?: any;
  timestamp?: number;
  status?: string;
  current_phase?: string;
  phase?: number;
  phase_name?: string;
  progress_percent?: number;
  progress?: number;
  total_endpoints?: number;
  total_findings?: number;
  findings_count?: number;
  endpoints_count?: number;
  critical_count?: number;
  high_count?: number;
}

export type WSMessage = WebSocketMessage;

export interface ExecutiveSummary {
  scan_id?: string;
  assessment_id?: string;
  assessment_title?: string;
  title?: string;
  target: string;
  report_date: string;
  risk_rating: string;
  findings_summary: {
    total?: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  key_findings?: Array<{
    rank: number;
    title: string;
    summary: string;
    severity: string;
  }>;
  recommendations?: string[];
}

export interface ComplianceReport {
  scan_id: string;
  assessment_id?: string;
  compliance_frameworks: Record<string, {
    status: string;
    findings?: string;
    categories?: Record<string, number>;
    total_issues?: number;
    action_required?: string;
  }>;
}
