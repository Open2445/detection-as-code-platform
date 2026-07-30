import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Shield, ToggleLeft, ToggleRight, Eye, EyeOff, Search, Plus, ShieldCheck, CheckCircle2, AlertTriangle, HelpCircle, Star, Edit2 } from 'lucide-react';
import { rulesApi } from '../api/client';
import type { SigmaRule } from '../types';
import AddRuleModal from '../components/AddRuleModal';
import RuleValidationModal from '../components/RuleValidationModal';
import EditRuleModal from '../components/EditRuleModal';
import RuleChangeHistory from '../components/RuleChangeHistory';

function ValidationBadge({ rule }: { rule: SigmaRule }) {
  const status = rule.validation_status || 'unvalidated';
  let badgeClass = 'badge-medium';
  let label = 'Unvalidated';
  let icon = <HelpCircle size={12} />;

  if (status === 'validated_in_lab') {
    badgeClass = 'badge-low';
    label = 'Validated in Lab';
    icon = <CheckCircle2 size={12} />;
  } else if (status === 'needs_tuning') {
    badgeClass = 'badge-high';
    label = 'Needs Tuning';
    icon = <AlertTriangle size={12} />;
  }

  return (
    <div style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
      <span className={`badge ${badgeClass}`} style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
        {icon}
        {label}
      </span>
      {rule.primary_validated_rule && (
        <span
          className="badge"
          style={{ background: 'rgba(234,179,8,0.15)', color: '#eab308', border: '1px solid rgba(234,179,8,0.3)', display: 'inline-flex', alignItems: 'center', gap: 3 }}
          title="Primary Validated Rule"
        >
          <Star size={11} fill="currentColor" />
          Primary
        </span>
      )}
    </div>
  );
}

function RuleRow({
  rule,
  onToggle,
  onOpenValidation,
  onEdit,
}: {
  rule: SigmaRule;
  onToggle: (r: SigmaRule) => void;
  onOpenValidation: (r: SigmaRule) => void;
  onEdit: (r: SigmaRule) => void;
}) {
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
          <ValidationBadge rule={rule} />
        </td>
        <td>
          <span className={`badge ${rule.enabled ? 'badge-low' : 'badge-medium'}`}>
            {rule.enabled ? 'Enabled' : 'Disabled'}
          </span>
        </td>
        <td>
          <div style={{ display: 'flex', gap: 6 }}>
            <button
              className="btn btn-outline btn-sm"
              onClick={() => onOpenValidation(rule)}
              title="Update Rule Validation"
              style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: '0.75rem', padding: '3px 8px' }}
            >
              <ShieldCheck size={13} />
              Validate
            </button>
            <button
              className="btn btn-outline btn-sm"
              onClick={() => onEdit(rule)}
              title="Edit Rule"
              style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: '0.75rem', padding: '3px 8px' }}
            >
              <Edit2 size={13} />
              Edit
            </button>
            <button
              className="btn btn-outline btn-sm btn-icon"
              onClick={() => setExpanded(e => !e)}
              title={expanded ? 'Hide Details' : 'View Details & History'}
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
          <td colSpan={7} style={{ padding: 0, background: 'var(--bg-elevated)' }}>
            <div style={{ padding: '12px 20px', borderTop: '1px solid var(--border-subtle)' }}>
              {rule.validation_notes && (
                <div style={{
                  marginBottom: '12px', padding: '10px 14px', borderRadius: '6px',
                  background: 'rgba(56,189,248,0.1)', border: '1px solid rgba(56,189,248,0.2)',
                  fontSize: '0.8rem', color: 'var(--text-primary)',
                }}>
                  <strong style={{ color: 'var(--accent)' }}>Validation Notes:</strong> {rule.validation_notes}
                  {rule.validation_evidence_filename && (
                    <div style={{ marginTop: '4px', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                      <strong>Evidence File:</strong> <code>{rule.validation_evidence_filename}</code>
                      {rule.validation_evidence_batch_id && ` (Batch #${rule.validation_evidence_batch_id})`}
                    </div>
                  )}
                </div>
              )}
              <pre style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '0.73rem',
                color: 'var(--text-secondary)',
                overflowX: 'auto',
                margin: 0,
                whiteSpace: 'pre',
                lineHeight: 1.6,
              }}>
                {rule.yaml_content}
              </pre>
              
              <div style={{ marginTop: 16, borderTop: '1px dashed var(--border-subtle)', paddingTop: 16 }}>
                <RuleChangeHistory rule={rule} />
              </div>
            </div>
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
  const [validationFilter, setValidationFilter] = useState('');
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [selectedValidationRule, setSelectedValidationRule] = useState<SigmaRule | null>(null);
  const [editingRule, setEditingRule] = useState<SigmaRule | null>(null);

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
    const matchVal = !validationFilter || (r.validation_status || 'unvalidated') === validationFilter;
    return matchSearch && matchSev && matchVal;
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

      <RuleValidationModal
        isOpen={!!selectedValidationRule}
        rule={selectedValidationRule}
        onClose={() => setSelectedValidationRule(null)}
        onSuccess={() => qc.invalidateQueries({ queryKey: ['rules'] })}
      />
      
      <EditRuleModal
        isOpen={!!editingRule}
        rule={editingRule}
        onClose={() => setEditingRule(null)}
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
        <div className="form-group">
          <label className="form-label">Validation</label>
          <select className="form-select" value={validationFilter} onChange={e => setValidationFilter(e.target.value)}>
            <option value="">All validation states</option>
            <option value="unvalidated">Unvalidated</option>
            <option value="validated_in_lab">Validated in Lab</option>
            <option value="needs_tuning">Needs Tuning</option>
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
                <th>Validation</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={7}>
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
                    onOpenValidation={setSelectedValidationRule}
                    onEdit={setEditingRule}
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

