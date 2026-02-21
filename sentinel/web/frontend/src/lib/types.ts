export type AuditMode = "github_url" | "code_paste";
export type AuditDepth = "fast" | "standard" | "deep";
export type JobStatusType = "pending" | "running" | "complete" | "error";

export interface AuditRequest {
  mode: AuditMode;
  github_url?: string;
  code?: string;
  filename?: string;
  depth: AuditDepth;
  model?: string;
}

export interface AuditResponse {
  job_id: string;
  ws_url: string;
  status: string;
}

export interface JobStatus {
  job_id: string;
  status: JobStatusType;
  phase: string | null;
  total_findings: number;
  cost: number;
  error: string | null;
}

export type WSMessageType =
  | "phase_start"
  | "phase_complete"
  | "log"
  | "finding"
  | "cost_update"
  | "error"
  | "complete"
  | "artifact";

export interface WSMessage {
  type: WSMessageType;
  timestamp: string;
  data: Record<string, unknown>;
}

export interface PhaseInfo {
  name: string;
  status: "pending" | "running" | "complete";
  detail?: Record<string, unknown>;
}

export interface FindingInfo {
  id: string;
  title: string;
  severity: string;
  vulnerability_type: string;
  contract: string;
  function?: string | null;
  description: string;
  impact?: string;
  recommendation?: string;
  confidence: number;
  validated: boolean;
  poc_code?: string | null;
  poc_output?: string | null;
}

export interface CostInfo {
  total_cost: number;
  total_input_tokens: number;
  total_output_tokens: number;
  total_thinking_tokens: number;
  prompt_cache_savings: number;
  cache_hits: number;
}

export interface AuditReport {
  job_id: string;
  report_markdown: string;
  findings: FindingInfo[];
  testing_diagram: string | null;
  test_setup: string | null;
  input_source: string | null;
  cost: number;
  duration_seconds: number;
}
