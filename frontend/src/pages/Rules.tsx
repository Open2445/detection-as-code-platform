import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Shield, ToggleLeft, ToggleRight, Eye, EyeOff, Search, Plus } from 'lucide-react';
import { rulesApi } from '../api/client';
import type { SigmaRule } from '../types';
import AddRuleModal from '../components/AddRuleModal';

function RuleRow({ rule, onToggle }: { rule: SigmaRule; onToggle: (r: SigmaRule) => void }) {
  const [expanded, setExpanded] = useState(false);
  const techniques = rule.mitre_techniques?.split(',').map(t => t.trim()).filter(Boolean) || [];

  return (
    <>
      <tr style={{ opacity: rule.enabled ? 1 : 0.5 }}>
        <td>
          <span className={`badge badge-${rule.severity}`}>{rule.severity}</span>
        </td>
        <td style={{ color: 'var(--text-primary)', fontWeight: 500 }}>
          {rule.title}
        </td>
        <td>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
            {techniques.slice(0, 3).map(t => (
              <span key={t} style={{
                fontFamily: 'var(--font-mono)', fontSize: '0.68rem',
                padding: '2px 7px', borderRadius: 4,
                background: 'var(--accent-dim)', color: 'var(--accent)',
                border: '1px solid var(--border-default)',
              }}>
                {t}
              </span>
            ))}
            {techniques.length > 3 && (
              <span style={{ color: 'var(--text-muted)', fontSize: '0.72rem' }}>
                +{techniques.length - 3}
              </span>
            )}
          </div>
        </td>
        <td style={{ color: 'var(--text-secondary)', textTransform: 'capitalize' }}>
          {rule.mitre_tactics?.replace(/,/g, ' · ').replace(/-/g, ' ') || '—'}
        </td>
        <td>
          <span className={`badge ${rule.enabled ? 'badge-low' : 'badge-medium'}`}>
            {rule.enabled ? 'Enabled' : 'Disabled'}
          </span>
        </td>
        <td>
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              className="btn btn-outline btn-sm btn-icon"
              onClick={() => setExpanded(e => !e)}
              title={expanded ? 'Hide YAML' : 'View YAML'}
            >
              {expanded ? <EyeOff size={14} /> : <Eye size={14} />}
            </button>
            <button
              className="btn btn-outline btn-sm btn-icon"
              onClick={() => onToggle(rule)}
              title={rule.enabled ? 'Disable rule' : 'Enable rule'}
            >
              {rule.enabled
                ? <ToggleRight size={14} style={{ color: 'var(--sev-low)' }} />
                : <ToggleLeft size={14} />
              }
            </button>
          </div>
        </td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={6} style={{ padding: 0, background: 'var(--bg-elevated)' }}>
            <pre style={{
              padding: '12px 20px',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.73rem',
              color: 'var(--text-secondary)',
              overflowX: 'auto',
              margin: 0,
              whiteSpace: 'pre',
              lineHeight: 1.6,
              borderTop: '1px solid var(--border-subtle)',
            }}>
              {rule.yaml_content}
            </pre>
          </td>
        </tr>
      )}
    </>
  );
}

export default function Rules() {
  const qc = useQueryClient();
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);

  const { data, isLoading } = useQuery({
    queryKey: ['rules'],
    queryFn: () => rulesApi.list(0, 100),
  });

  const toggleMutation = useMutation({
    mutationFn: rulesApi.toggleEnabled,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rules'] }),
  });

  const filtered = (data?.items ?? []).filter(r => {
    const matchSearch = !search ||
      r.title.toLowerCase().includes(search.toLowerCase()) ||
      r.name.toLowerCase().includes(search.toLowerCase()) ||
      (r.mitre_techniques || '').includes(search.toUpperCase());
    const matchSev = !severityFilter || r.severity === severityFilter;
    return matchSearch && matchSev;
  });

  return (
    <div className="page">
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h1 className="page-title">Sigma Rules</h1>
          <p className="page-subtitle">
            {data?.total ?? 0} rules loaded · PySigma in-memory evaluator
          </p>
        </div>
        <button
          className="btn btn-primary"
          onClick={() => setIsAddModalOpen(true)}
          style={{ display: 'flex', alignItems: 'center', gap: 6 }}
        >
          <Plus size={16} />
          Add Rule
        </button>
      </div>

      <AddRuleModal
        isOpen={isAddModalOpen}
        onClose={() => setIsAddModalOpen(false)}
        onSuccess={() => qc.invalidateQueries({ queryKey: ['rules'] })}
      />

      {/* Search + Filter */}
      <div className="filter-bar mb-4">
        <div className="form-group" style={{ flex: 2 }}>
          <label className="form-label">Search</label>
          <div style={{ position: 'relative' }}>
            <Search size={14} style={{
              position: 'absolute', left: 12, top: '50%',
              transform: 'translateY(-50%)', color: 'var(--text-muted)',
            }} />
            <input
              className="form-input"
              style={{ paddingLeft: 34 }}
              placeholder="Rule name, title, or technique ID…"
              value={search}
              onChange={e => setSearch(e.target.value)}
            />
          </div>
        </div>
        <div className="form-group">
          <label className="form-label">Severity</label>
          <select className="form-select" value={severityFilter} onChange={e => setSeverityFilter(e.target.value)}>
            <option value="">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="informational">Informational</option>
          </select>
        </div>
      </div>

      {/* Rules Table */}
      {isLoading ? (
        <div className="loading-spinner"><div className="spinner" /></div>
      ) : (
        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Title</th>
                <th>Techniques</th>
                <th>Tactics</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={6}>
                    <div className="empty-state" style={{ padding: '32px 0' }}>
                      <Shield size={28} className="empty-state-icon" />
                      <div className="empty-state-sub">No rules match your filter</div>
                    </div>
                  </td>
                </tr>
              ) : (
                filtered.map(rule => (
                  <RuleRow
                    key={rule.id}
                    rule={rule}
                    onToggle={toggleMutation.mutate}
                  />
                ))
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
