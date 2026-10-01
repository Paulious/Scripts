// Mirrors backend/app/models.py. Keep the two in step.

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Role = "cause" | "symptom";

export interface LogFileInfo {
  path: string;
  size_bytes: number;
  line_count: number;
  encoding: string;
  log_type: string;
  log_type_label: string;
  detection_confidence: number;
  error_count: number;
  warning_count: number;
  first_timestamp: string | null;
  last_timestamp: string | null;
  facts: Record<string, string>;
}

export interface SkippedFile {
  path: string;
  reason: string;
}

export interface EvidenceLine {
  n: number;
  text: string;
  match: boolean;
  anchor: boolean;
  noise: boolean;
}

export interface EvidenceWindow {
  file: string;
  start_line: number;
  end_line: number;
  anchor_line: number;
  lines: EvidenceLine[];
}

export interface Finding {
  id: string;
  pattern_id: string;
  title: string;
  category: string;
  severity: Severity;
  role: Role;
  file: string;
  log_type: string;
  match_count: number;
  attempts: number;
  first_line: number;
  last_line: number;
  first_timestamp: string | null;
  last_timestamp: string | null;
  details: string[];
  error_codes: string[];
  sample: string;
  score: number;
  explanation: string;
  related_files: string[];
  evidence: EvidenceWindow[];
  evidence_trimmed: boolean;
}

export interface SuppressedNoise {
  id: string;
  reason: string;
  count: number;
  example: string;
}

export interface ConfidenceFactor {
  name: string;
  score: number;
  weight: number;
  detail: string;
}

export interface Confidence {
  score: number;
  label: "High" | "Medium" | "Low";
  factors: ConfidenceFactor[];
  llm_reported: number | null;
}

export interface RemediationStep {
  order: number;
  action: string;
  detail: string;
  command: string | null;
}

export interface RootCause {
  title: string;
  category: string;
  explanation: string;
  reasoning: string;
  finding_ids: string[];
  confidence: Confidence;
}

export interface Analysis {
  summary: string;
  root_cause: RootCause | null;
  contributing_factors: string[];
  ruled_out: string[];
  remediation: RemediationStep[];
  verification: string[];
  further_data: string[];
  provider: string;
  model: string | null;
  degraded: boolean;
  notes: string[];
}

export interface Stats {
  files_analyzed: number;
  files_skipped: number;
  total_lines: number;
  total_bytes: number;
  findings: number;
  errors: number;
  duration_ms: number;
}

export interface AnalysisResult {
  generated_at: string;
  context: string | null;
  stats: Stats;
  files: LogFileInfo[];
  skipped: SkippedFile[];
  findings: Finding[];
  suppressed: SuppressedNoise[];
  analysis: Analysis;
  report_markdown: string;
}

export interface ProviderInfo {
  id: string;
  label: string;
  model: string | null;
  configured: boolean;
}

export interface StageInfo {
  id: string;
  label: string;
}

export interface AppConfig {
  providers: ProviderInfo[];
  default_provider: string;
  ai_available: boolean;
  ai_default_provider: string | null;
  stages: StageInfo[];
  limits: { max_upload_mb: number; evidence_context_lines: number };
  redact_default: boolean;
}

export type StageStatus = "pending" | "running" | "done" | "error";

export type StreamEvent =
  | { type: "progress"; stage: string; status: "running" | "done"; message: string; percent?: number }
  | { type: "result"; data: AnalysisResult }
  | { type: "error"; message: string }
  | { type: "ping" };
