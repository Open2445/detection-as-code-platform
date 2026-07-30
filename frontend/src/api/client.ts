/**
 * Axios-based API client for the Detection-as-Code backend.
 */
import axios from 'axios';
import type {
  UploadBatch, UploadResponse, LogEntryPage,
  SigmaRule, SigmaRuleList, RuleValidationPayload, RuleChange, RuleChangeCreate, RuleValidateRequest, RuleValidateResponse,
  Alert, AlertPage, AlertFilters, AlertTriagePayload, AlertTriageHistory, AlertCounters, DetectionRunResult,
  DashboardStats, TimelineResponse, MitreCoverage,
} from '../types';

const api = axios.create({
  baseURL: '/api',
  timeout: 60_000,
  headers: { 'Content-Type': 'application/json' },
});

// ── Logs ──────────────────────────────────────────────────────────────────────
export const logsApi = {
  upload: async (file: File): Promise<UploadResponse> => {
    const form = new FormData();
    form.append('file', file);
    const res = await api.post<UploadResponse>('/logs/upload', form, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    return res.data;
  },

  list: async (skip = 0, limit = 50): Promise<UploadBatch[]> => {
    const res = await api.get<UploadBatch[]>('/logs', { params: { skip, limit } });
    return res.data;
  },

  get: async (batchId: number): Promise<UploadBatch> => {
    const res = await api.get<UploadBatch>(`/logs/${batchId}`);
    return res.data;
  },

  entries: async (batchId: number, page = 1, pageSize = 50): Promise<LogEntryPage> => {
    const res = await api.get<LogEntryPage>(`/logs/${batchId}/entries`, {
      params: { page, page_size: pageSize },
    });
    return res.data;
  },

  delete: async (batchId: number): Promise<void> => {
    await api.delete(`/logs/${batchId}`);
  },
};

// ── Rules ─────────────────────────────────────────────────────────────────────
export const rulesApi = {
  list: async (skip = 0, limit = 100, enabled?: boolean): Promise<SigmaRuleList> => {
    const res = await api.get<SigmaRuleList>('/rules', {
      params: { skip, limit, ...(enabled !== undefined && { enabled }) },
    });
    return res.data;
  },

  get: async (ruleId: number): Promise<SigmaRule> => {
    const res = await api.get<SigmaRule>(`/rules/${ruleId}`);
    return res.data;
  },

  create: async (payload: Partial<SigmaRule>): Promise<SigmaRule> => {
    const res = await api.post<SigmaRule>('/rules', payload);
    return res.data;
  },

  update: async (ruleId: number, payload: Partial<SigmaRule>): Promise<SigmaRule> => {
    const res = await api.put<SigmaRule>(`/rules/${ruleId}`, payload);
    return res.data;
  },

  updateValidation: async (ruleId: number, payload: RuleValidationPayload): Promise<SigmaRule> => {
    const res = await api.put<SigmaRule>(`/rules/${ruleId}/validation`, payload);
    return res.data;
  },

  delete: async (ruleId: number): Promise<void> => {
    await api.delete(`/rules/${ruleId}`);
  },

  toggleEnabled: async (rule: SigmaRule): Promise<SigmaRule> => {
    return rulesApi.update(rule.id, { enabled: !rule.enabled });
  },

  createRaw: async (ruleText: string, format: string = 'auto'): Promise<SigmaRule> => {
    const res = await api.post<SigmaRule>('/rules/raw', { rule_text: ruleText, format });
    return res.data;
  },
};

// ── Rule Changes ──────────────────────────────────────────────────────────────
export const ruleChangesApi = {
  validate: async (ruleId: number, payload: RuleValidateRequest): Promise<RuleValidateResponse> => {
    const res = await api.post<RuleValidateResponse>(`/rules/${ruleId}/changes/validate`, payload);
    return res.data;
  },

  list: async (ruleId: number): Promise<RuleChange[]> => {
    const res = await api.get<RuleChange[]>(`/rules/${ruleId}/changes`);
    return res.data;
  },

  create: async (ruleId: number, payload: RuleChangeCreate, changeType: 'draft' | 'submitted' = 'draft'): Promise<RuleChange> => {
    const res = await api.post<RuleChange>(`/rules/${ruleId}/changes`, payload, {
      params: { change_type: changeType }
    });
    return res.data;
  },

  apply: async (ruleId: number, changeId: number): Promise<RuleChange> => {
    const res = await api.post<RuleChange>(`/rules/${ruleId}/changes/${changeId}/apply`, {});
    return res.data;
  },

  revert: async (ruleId: number, changeId: number): Promise<RuleChange> => {
    const res = await api.post<RuleChange>(`/rules/${ruleId}/changes/${changeId}/revert`, {});
    return res.data;
  },
};

// ── Detections ────────────────────────────────────────────────────────────────
export const detectionsApi = {
  run: async (batchId: number): Promise<DetectionRunResult> => {
    const res = await api.post<DetectionRunResult>('/detections/run', { batch_id: batchId });
    return res.data;
  },
};

// ── Alerts ────────────────────────────────────────────────────────────────────
export const alertsApi = {
  list: async (filters: AlertFilters = {}): Promise<AlertPage> => {
    const params: Record<string, unknown> = {};
    Object.entries(filters).forEach(([k, v]) => {
      if (v !== undefined && v !== '' && v !== null) params[k] = v;
    });
    const res = await api.get<AlertPage>('/alerts', { params });
    return res.data;
  },

  get: async (alertId: number): Promise<Alert> => {
    const res = await api.get<Alert>(`/alerts/${alertId}`);
    return res.data;
  },

  getCounters: async (): Promise<AlertCounters> => {
    const res = await api.get<AlertCounters>('/alerts/counters');
    return res.data;
  },

  getHistory: async (alertId: number): Promise<AlertTriageHistory[]> => {
    const res = await api.get<AlertTriageHistory[]>(`/alerts/${alertId}/history`);
    return res.data;
  },

  updateTriage: async (alertId: number, payload: AlertTriagePayload): Promise<Alert> => {
    const res = await api.put<Alert>(`/alerts/${alertId}/triage`, payload);
    return res.data;
  },

  exportCsv: (filters: AlertFilters = {}): void => {
    const params = new URLSearchParams();
    Object.entries(filters).forEach(([k, v]) => {
      if (v !== undefined && v !== '' && v !== null) params.set(k, String(v));
    });
    const url = `/api/alerts/export/csv?${params.toString()}`;
    const link = document.createElement('a');
    link.href = url;
    link.download = 'alerts_export.csv';
    link.click();
  },
};


// ── Dashboard ─────────────────────────────────────────────────────────────────
export const dashboardApi = {
  stats: async (): Promise<DashboardStats> => {
    const res = await api.get<DashboardStats>('/dashboard/stats');
    return res.data;
  },

  timeline: async (days = 30): Promise<TimelineResponse> => {
    const res = await api.get<TimelineResponse>('/dashboard/timeline', { params: { days } });
    return res.data;
  },

  mitreCoverage: async (): Promise<MitreCoverage> => {
    const res = await api.get<MitreCoverage>('/dashboard/mitre-coverage');
    return res.data;
  },
};

export default api;
