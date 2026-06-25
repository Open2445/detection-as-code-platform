/**
 * Axios-based API client for the Detection-as-Code backend.
 */
import axios from 'axios';
import type {
  UploadBatch, UploadResponse, LogEntryPage,
  SigmaRule, SigmaRuleList,
  Alert, AlertPage, AlertFilters, DetectionRunResult,
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

  delete: async (ruleId: number): Promise<void> => {
    await api.delete(`/rules/${ruleId}`);
  },

  toggleEnabled: async (rule: SigmaRule): Promise<SigmaRule> => {
    return rulesApi.update(rule.id, { enabled: !rule.enabled });
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
