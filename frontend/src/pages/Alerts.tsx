import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Download, Filter, Bell } from 'lucide-react';
import { alertsApi } from '../api/client';
import AlertTable from '../components/AlertTable';
import type { AlertFilters } from '../types';

const SEVERITY_OPTIONS = ['critical', 'high', 'medium', 'low', 'informational'];

export default function Alerts() {
  const [filters, setFilters] = useState<AlertFilters>({
    page: 1,
    page_size: 50,
  });

  const { data, isLoading } = useQuery({
    queryKey: ['alerts', filters],
    queryFn: () => alertsApi.list(filters),
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

      {/* Filter Bar */}
      <div className="filter-bar">
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
            <option value="">All</option>
            {SEVERITY_OPTIONS.map(s => (
              <option key={s} value={s}>
                {s.charAt(0).toUpperCase() + s.slice(1)}
              </option>
            ))}
          </select>
        </div>
        <div className="form-group">
          <label className="form-label">Tactic</label>
          <input
            className="form-input"
            placeholder="e.g. execution"
            value={filters.tactic || ''}
            onChange={e => updateFilter('tactic', e.target.value)}
          />
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
