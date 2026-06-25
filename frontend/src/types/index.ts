/**
 * TypeScript type definitions for the Detection-as-Code Platform API.
 */

// ── Log Types ────────────────────────────────────────────────────────────────
export interface UploadBatch {
  id: number;
  filename: string;
  upload_time: string;
  log_count: number;
  status: string;
  detections_run: boolean;
  detections_run_at: string | null;
}

export interface LogEntry {
  id: number;
  batch_id: number;
  event_id: number | null;
  hostname: string | null;
  username: string | null;
  timestamp: string | null;
  raw_json: string;
}

export interface LogEntryPage {
  total: number;
  page: number;
  page_size: number;
  items: LogEntry[];
}

export interface UploadResponse {
  batch: UploadBatch;
  message: string;
}

// ── Rule Types ────────────────────────────────────────────────────────────────
export interface SigmaRule {
  id: number;
  name: string;
  title: string;
  description: string | null;
  severity: Severity;
  yaml_content: string;
  mitre_tactics: string | null;
  mitre_techniques: string | null;
  mitre_tactic_ids: string | null;
  tags: string | null;
  created_at: string;
  updated_at: string | null;
  enabled: boolean;
}

export interface SigmaRuleList {
  total: number;
  items: SigmaRule[];
}

// ── Alert Types ───────────────────────────────────────────────────────────────
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational';

export interface Alert {
  id: number;
  rule_id: number;
  log_entry_id: number;
  batch_id: number;
  severity: Severity;
  hostname: string | null;
  username: string | null;
  rule_name: string;
  technique_id: string | null;
  technique_name: string | null;
  tactic: string | null;
  tactic_id: string | null;
  event_id: number | null;
  triggered_at: string;
  details_json: string | null;
}

export interface AlertPage {
  total: number;
  page: number;
  page_size: number;
  items: Alert[];
}

export interface AlertFilters {
  hostname?: string;
  username?: string;
  rule_name?: string;
  technique_id?: string;
  tactic?: string;
  severity?: string;
  batch_id?: number;
  from_date?: string;
  to_date?: string;
  page?: number;
  page_size?: number;
}

// ── Detection Types ───────────────────────────────────────────────────────────
export interface DetectionRunResult {
  batch_id: number;
  logs_scanned: number;
  rules_evaluated: number;
  alerts_generated: number;
  duration_seconds: number;
}

// ── Dashboard Types ───────────────────────────────────────────────────────────
export interface SeverityCount {
  severity: string;
  count: number;
}

export interface TopRule {
  rule_name: string;
  rule_id: number;
  count: number;
  severity: string;
}

export interface DashboardStats {
  total_alerts: number;
  total_logs: number;
  total_rules: number;
  total_batches: number;
  severity_distribution: SeverityCount[];
  top_rules: TopRule[];
  attack_coverage_pct: number;
  unique_hosts_affected: number;
  unique_techniques_triggered: number;
}

export interface TimelinePoint {
  date: string;
  count: number;
}

export interface TimelineResponse {
  points: TimelinePoint[];
  granularity: string;
}

export interface MitreTechniqueCount {
  technique_id: string;
  technique_name: string;
  tactic: string;
  tactic_id: string;
  count: number;
}

export interface MitreCoverage {
  total_techniques_in_rules: number;
  techniques_triggered: number;
  coverage_pct: number;
  techniques: MitreTechniqueCount[];
}
