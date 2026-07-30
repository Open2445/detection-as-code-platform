import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Download, Filter, Bell, CheckCircle2, AlertTriangle, Copy, HelpCircle, Clock } from 'lucide-react';
import { alertsApi } from '../api/client';
import AlertTable from '../components/AlertTable';
import type { AlertFilters } from '../types';

const SEVERITY_OPTIONS = ['critical', 'high', 'medium', 'low', 'informational'];
const CLASSIFICATION_OPTIONS = [
  { value: 'unclassified', label: 'Unclassified' },
  { value: 'true_positive', label: 'True Positive' },
  { value: 'false_positive', label: 'False Positive' },
  { value: 'duplicate', label: 'Duplicate' },
  { value: 'needs_investigation', label: 'Needs Investigation' },
];
const TRIAGE_STATUS_OPTIONS = [
  { value: 'open', label: 'Open' },
  { value: 'in_progress', label: 'In Progress' },
  { value: 'closed', label: 'Closed' },
];

export default function Alerts() {
  const [filters, setFilters] = useState<AlertFilters>({
    page: 1,
    page_size: 50,
  });

  const { data, isLoading } = useQuery({
    queryKey: ['alerts', filters],
    queryFn: () => alertsApi.list(filters),
  });

  const { data: counters } = useQuery({
    queryKey: ['alerts-counters'],
    queryFn: () => alertsApi.getCounters(),
  });

  const updateFilter = (key: keyof AlertFilters, value: string | number | undefined) => {
    setFilters(prev => ({ ...prev, [key]: value || undefined, page: 1 }));
  };

  const handleExportCsv = () => {
    alertsApi.exportCsv({
      hostname: filters.hostname,
      username: filters.username,
      rule_name: filters.rule_name,
      technique_id: filters.technique_id,
      tactic: filters.tactic,
      severity: filters.severity,
      batch_id: filters.batch_id,
      classification: filters.classification,
      triage_status: filters.triage_status,
    });
  };

  return (
    <div className="page">
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h1 className="page-title">Alerts</h1>
          <p className="page-subtitle">
            {data?.total ? `${data.total.toLocaleString()} total alerts` : 'Detection results'}
          </p>
        </div>
        <button className="btn btn-outline" onClick={handleExportCsv}>
          <Download size={14} />
          Export CSV
        </button>
      </div>

      {/* Counters Metrics Grid */}
      <div style={{
        display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '14px', marginBottom: '20px',
      }}>
        <div
          onClick={() => updateFilter('triage_status', filters.triage_status === 'open' ? undefined : 'open')}
          style={{
            background: filters.triage_status === 'open' ? 'rgba(56,189,248,0.15)' : 'var(--bg-card, #1e293b)',
            border: `1px solid ${filters.triage_status === 'open' ? '#38bdf8' : 'var(--border-default, #334155)'}`,
            borderRadius: '10px', padding: '12px 16px', cursor: 'pointer', transition: 'all 0.2s ease',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
            <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>Open Alerts</span>
            <Clock size={16} style={{ color: '#38bdf8' }} />
          </div>
          <div style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--text-primary)' }}>
            {counters?.open_alerts ?? '—'}
          </div>
        </div>

        <div
          onClick={() => updateFilter('classification', filters.classification === 'true_positive' ? undefined : 'true_positive')}
          style={{
            background: filters.classification === 'true_positive' ? 'rgba(34,197,94,0.15)' : 'var(--bg-card, #1e293b)',
            border: `1px solid ${filters.classification === 'true_positive' ? '#22c55e' : 'var(--border-default, #334155)'}`,
            borderRadius: '10px', padding: '12px 16px', cursor: 'pointer', transition: 'all 0.2s ease',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
            <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>True Positives</span>
            <CheckCircle2 size={16} style={{ color: '#4ade80' }} />
          </div>
          <div style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--text-primary)' }}>
            {counters?.true_positives ?? '—'}
          </div>
        </div>

        <div
          onClick={() => updateFilter('classification', filters.classification === 'false_positive' ? undefined : 'false_positive')}
          style={{
            background: filters.classification === 'false_positive' ? 'rgba(239,68,68,0.15)' : 'var(--bg-card, #1e293b)',
            border: `1px solid ${filters.classification === 'false_positive' ? '#ef4444' : 'var(--border-default, #334155)'}`,
            borderRadius: '10px', padding: '12px 16px', cursor: 'pointer', transition: 'all 0.2s ease',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
            <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>False Positives</span>
            <AlertTriangle size={16} style={{ color: '#fca5a5' }} />
          </div>
          <div style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--text-primary)' }}>
            {counters?.false_positives ?? '—'}
          </div>
        </div>

        <div
          onClick={() => updateFilter('classification', filters.classification === 'duplicate' ? undefined : 'duplicate')}
          style={{
            background: filters.classification === 'duplicate' ? 'rgba(168,85,247,0.15)' : 'var(--bg-card, #1e293b)',
            border: `1px solid ${filters.classification === 'duplicate' ? '#a855f7' : 'var(--border-default, #334155)'}`,
            borderRadius: '10px', padding: '12px 16px', cursor: 'pointer', transition: 'all 0.2s ease',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
            <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>Duplicates</span>
            <Copy size={16} style={{ color: '#c084fc' }} />
          </div>
          <div style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--text-primary)' }}>
            {counters?.duplicates ?? '—'}
          </div>
        </div>

        <div
          onClick={() => updateFilter('classification', filters.classification === 'needs_investigation' ? undefined : 'needs_investigation')}
          style={{
            background: filters.classification === 'needs_investigation' ? 'rgba(234,179,8,0.15)' : 'var(--bg-card, #1e293b)',
            border: `1px solid ${filters.classification === 'needs_investigation' ? '#eab308' : 'var(--border-default, #334155)'}`,
            borderRadius: '10px', padding: '12px 16px', cursor: 'pointer', transition: 'all 0.2s ease',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
            <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>Needs Investigation</span>
            <HelpCircle size={16} style={{ color: '#fde047' }} />
          </div>
          <div style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--text-primary)' }}>
            {counters?.needs_investigation ?? '—'}
          </div>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="filter-bar" style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr) repeat(3, 1.2fr) auto', gap: 10 }}>
        <div className="form-group">
          <label className="form-label">Hostname</label>
          <input
            className="form-input"
            placeholder="e.g. WORKSTATION-01"
            value={filters.hostname || ''}
            onChange={e => updateFilter('hostname', e.target.value)}
          />
        </div>
        <div className="form-group">
          <label className="form-label">Username</label>
          <input
            className="form-input"
            placeholder="e.g. jdoe"
            value={filters.username || ''}
            onChange={e => updateFilter('username', e.target.value)}
          />
        </div>
        <div className="form-group">
          <label className="form-label">Rule Name</label>
          <input
            className="form-input"
            placeholder="e.g. mimikatz"
            value={filters.rule_name || ''}
            onChange={e => updateFilter('rule_name', e.target.value)}
          />
        </div>
        <div className="form-group">
          <label className="form-label">Technique</label>
          <input
            className="form-input"
            placeholder="e.g. T1059"
            value={filters.technique_id || ''}
            onChange={e => updateFilter('technique_id', e.target.value)}
          />
        </div>
        <div className="form-group">
          <label className="form-label">Severity</label>
          <select
            className="form-select"
            value={filters.severity || ''}
            onChange={e => updateFilter('severity', e.target.value)}
          >
            <option value="">All severities</option>
            {SEVERITY_OPTIONS.map(s => (
              <option key={s} value={s}>
                {s.charAt(0).toUpperCase() + s.slice(1)}
              </option>
            ))}
          </select>
        </div>

        <div className="form-group">
          <label className="form-label">Classification</label>
          <select
            className="form-select"
            value={filters.classification || ''}
            onChange={e => updateFilter('classification', e.target.value)}
          >
            <option value="">All classifications</option>
            {CLASSIFICATION_OPTIONS.map(c => (
              <option key={c.value} value={c.value}>
                {c.label}
              </option>
            ))}
          </select>
        </div>

        <div className="form-group">
          <label className="form-label">Triage Status</label>
          <select
            className="form-select"
            value={filters.triage_status || ''}
            onChange={e => updateFilter('triage_status', e.target.value)}
          >
            <option value="">All status</option>
            {TRIAGE_STATUS_OPTIONS.map(s => (
              <option key={s.value} value={s.value}>
                {s.label}
              </option>
            ))}
          </select>
        </div>

        <div className="form-group" style={{ minWidth: 'auto' }}>
          <label className="form-label">&nbsp;</label>
          <button
            className="btn btn-outline"
            onClick={() => setFilters({ page: 1, page_size: 50 })}
            style={{ whiteSpace: 'nowrap' }}
          >
            Clear Filters
          </button>
        </div>
      </div>

      {/* Alert Table */}
      <AlertTable
        alerts={data?.items ?? []}
        total={data?.total ?? 0}
        page={filters.page ?? 1}
        pageSize={filters.page_size ?? 50}
        onPageChange={(p) => setFilters(prev => ({ ...prev, page: p }))}
        loading={isLoading}
      />
    </div>
  );
}

