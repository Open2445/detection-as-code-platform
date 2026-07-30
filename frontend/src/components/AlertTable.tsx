import { useState, useEffect } from 'react';
import { format, parseISO } from 'date-fns';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { ChevronDown, ChevronRight, Save, History, Info, AlertCircle, CheckCircle, Clock, Copy } from 'lucide-react';
import { alertsApi } from '../api/client';
import type { Alert, Severity, AlertClassification, TriageStatus } from '../types';

interface AlertTableProps {
  alerts: Alert[];
  total: number;
  page: number;
  pageSize: number;
  onPageChange: (page: number) => void;
  loading?: boolean;
}

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={`badge badge-${severity}`}>
      <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'currentColor', display: 'inline-block' }} />
      {severity}
    </span>
  );
}

function ClassificationBadge({ classification }: { classification: AlertClassification }) {
  const map: Record<AlertClassification, { label: string; style: React.CSSProperties }> = {
    unclassified: { label: 'Unclassified', style: { background: 'rgba(148,163,184,0.15)', color: '#94a3b8', border: '1px solid #475569' } },
    true_positive: { label: 'True Positive', style: { background: 'rgba(34,197,94,0.15)', color: '#4ade80', border: '1px solid rgba(34,197,94,0.3)' } },
    false_positive: { label: 'False Positive', style: { background: 'rgba(239,68,68,0.15)', color: '#fca5a5', border: '1px solid rgba(239,68,68,0.3)' } },
    duplicate: { label: 'Duplicate', style: { background: 'rgba(168,85,247,0.15)', color: '#c084fc', border: '1px solid rgba(168,85,247,0.3)' } },
    needs_investigation: { label: 'Needs Investigation', style: { background: 'rgba(234,179,8,0.15)', color: '#fde047', border: '1px solid rgba(234,179,8,0.3)' } },
  };

  const conf = map[classification] || map.unclassified;
  return (
    <span className="badge" style={{ ...conf.style, fontSize: '0.72rem', padding: '2px 8px' }}>
      {conf.label}
    </span>
  );
}

function TriageStatusBadge({ status }: { status: TriageStatus }) {
  const map: Record<TriageStatus, { label: string; style: React.CSSProperties }> = {
    open: { label: 'Open', style: { background: 'rgba(56,189,248,0.15)', color: '#38bdf8', border: '1px solid rgba(56,189,248,0.3)' } },
    in_progress: { label: 'In Progress', style: { background: 'rgba(249,115,22,0.15)', color: '#fb923c', border: '1px solid rgba(249,115,22,0.3)' } },
    closed: { label: 'Closed', style: { background: 'rgba(100,116,139,0.2)', color: '#cbd5e1', border: '1px solid #475569' } },
  };

  const conf = map[status] || map.open;
  return (
    <span className="badge" style={{ ...conf.style, fontSize: '0.72rem', padding: '2px 8px' }}>
      {conf.label}
    </span>
  );
}

function getLabGuidance(ruleName: string): { title: string; text: string; color: string } | null {
  if (ruleName === 'lab-encoded-powershell-001') {
    return {
      title: 'Lab Guidance: True Positive',
      text: 'lab-encoded-powershell-001 is the primary validated lab rule for this action.',
      color: '#4ade80',
    };
  }
  if (['encoded_powershell_command', 'suspicious_powershell_execution'].includes(ruleName)) {
    return {
      title: 'Lab Guidance: Likely Duplicate',
      text: `${ruleName} is likely a duplicate alert of the same encoded-PowerShell lab action.`,
      color: '#c084fc',
    };
  }
  if (ruleName === 'regsvr32_remote_scriptlet_execution') {
    return {
      title: 'Lab Guidance: Needs Investigation',
      text: 'regsvr32_remote_scriptlet_execution (Squiblydoo/T1218.010) requires analyst investigation and is not automatically a false positive.',
      color: '#fde047',
    };
  }
  return null;
}

function AlertRow({ alert, allAlerts }: { alert: Alert; allAlerts: Alert[] }) {
  const [expanded, setExpanded] = useState(false);
  const qc = useQueryClient();

  const [classification, setClassification] = useState<AlertClassification>(alert.classification || 'unclassified');
  const [triageStatus, setTriageStatus] = useState<TriageStatus>(alert.triage_status || 'open');
  const [analystNotes, setAnalystNotes] = useState(alert.analyst_notes || '');
  const [primaryAlertId, setPrimaryAlertId] = useState<number | ''>(alert.primary_alert_id || '');
  const [reviewedBy, setReviewedBy] = useState(alert.reviewed_by || 'local analyst');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  useEffect(() => {
    setClassification(alert.classification || 'unclassified');
    setTriageStatus(alert.triage_status || 'open');
    setAnalystNotes(alert.analyst_notes || '');
    setPrimaryAlertId(alert.primary_alert_id || '');
    setReviewedBy(alert.reviewed_by || 'local analyst');
  }, [alert]);

  // Query history when expanded
  const { data: history = [] } = useQuery({
    queryKey: ['alert-history', alert.id],
    queryFn: () => alertsApi.getHistory(alert.id),
    enabled: expanded,
  });

  const triageMutation = useMutation({
    mutationFn: (payload: any) => alertsApi.updateTriage(alert.id, payload),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['alerts'] });
      qc.invalidateQueries({ queryKey: ['alert-history', alert.id] });
      qc.invalidateQueries({ queryKey: ['alerts-counters'] });
      setErrorMessage(null);
      setSuccessMessage('Triage updated successfully');
      setTimeout(() => setSuccessMessage(null), 3000);
    },
    onError: (err: any) => {
      setErrorMessage(err.response?.data?.detail || 'Failed to update triage');
    },
  });

  const handleSaveTriage = () => {
    setErrorMessage(null);
    triageMutation.mutate({
      classification,
      triage_status: triageStatus,
      analyst_notes: analystNotes || null,
      primary_alert_id: classification === 'duplicate' && primaryAlertId !== '' ? Number(primaryAlertId) : null,
      reviewed_by: reviewedBy,
    });
  };

  let details: Record<string, unknown> = {};
  try {
    details = alert.details_json ? JSON.parse(alert.details_json) : {};
  } catch { /* ignore */ }

  const guidance = getLabGuidance(alert.rule_name);

  return (
    <>
      <tr>
        <td>
          <button
            onClick={() => setExpanded(e => !e)}
            style={{
              background: 'none', border: 'none', cursor: 'pointer',
              color: 'var(--text-secondary)', padding: '2px 4px',
              display: 'flex', alignItems: 'center',
            }}
          >
            {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
          </button>
        </td>
        <td><SeverityBadge severity={alert.severity} /></td>
        <td style={{ color: 'var(--text-primary)', fontWeight: 500, maxWidth: 180 }}>
          <span className="truncate" style={{ display: 'block' }}>{alert.rule_name}</span>
        </td>
        <td><ClassificationBadge classification={alert.classification} /></td>
        <td><TriageStatusBadge status={alert.triage_status} /></td>
        <td className="mono">{alert.technique_id || '—'}</td>
        <td style={{ color: 'var(--text-secondary)', textTransform: 'capitalize' }}>
          {alert.tactic?.replace(/-/g, ' ') || '—'}
        </td>
        <td className="mono">{alert.hostname || '—'}</td>
        <td>{alert.username || '—'}</td>
        <td className="mono" style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>
          {alert.triggered_at ? format(parseISO(alert.triggered_at), 'MMM d, HH:mm:ss') : '—'}
        </td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={10} style={{ padding: 0, background: 'var(--bg-elevated, #0f172a)' }}>
            <div style={{ padding: '20px 24px', borderTop: '1px solid var(--border-subtle, #1e293b)' }}>
              
              {/* Lab Guidance Card */}
              {guidance && (
                <div style={{
                  padding: '10px 14px', borderRadius: '8px', marginBottom: '16px',
                  background: 'rgba(56,189,248,0.08)', border: `1px solid ${guidance.color}`,
                  display: 'flex', alignItems: 'center', gap: '10px',
                }}>
                  <Info size={18} style={{ color: guidance.color, flexShrink: 0 }} />
                  <div style={{ fontSize: '0.82rem' }}>
                    <strong style={{ color: guidance.color, display: 'block' }}>{guidance.title}</strong>
                    <span style={{ color: 'var(--text-secondary, #cbd5e1)' }}>{guidance.text}</span>
                  </div>
                </div>
              )}

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
                
                {/* Left Column: Triage Control Form */}
                <div style={{
                  background: 'var(--bg-card, #1e293b)', padding: '20px', borderRadius: '10px',
                  border: '1px solid var(--border-default, #334155)', display: 'flex', flexDirection: 'column', gap: '14px',
                }}>
                  <h4 style={{ margin: 0, fontSize: '0.9rem', color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 6 }}>
                    <Save size={15} style={{ color: 'var(--accent)' }} />
                    Analyst Triage & Classification
                  </h4>

                  {errorMessage && (
                    <div style={{
                      padding: '8px 12px', borderRadius: '6px', background: 'rgba(239,68,68,0.15)',
                      border: '1px solid #ef4444', color: '#fca5a5', fontSize: '0.8rem',
                    }}>
                      {errorMessage}
                    </div>
                  )}

                  {successMessage && (
                    <div style={{
                      padding: '8px 12px', borderRadius: '6px', background: 'rgba(34,197,94,0.15)',
                      border: '1px solid #22c55e', color: '#86efac', fontSize: '0.8rem',
                    }}>
                      {successMessage}
                    </div>
                  )}

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                    <div className="form-group">
                      <label className="form-label">Classification</label>
                      <select
                        className="form-select"
                        value={classification}
                        onChange={e => setClassification(e.target.value as AlertClassification)}
                      >
                        <option value="unclassified">Unclassified</option>
                        <option value="true_positive">True Positive</option>
                        <option value="false_positive">False Positive</option>
                        <option value="duplicate">Duplicate</option>
                        <option value="needs_investigation">Needs Investigation</option>
                      </select>
                    </div>

                    <div className="form-group">
                      <label className="form-label">Triage Status</label>
                      <select
                        className="form-select"
                        value={triageStatus}
                        onChange={e => setTriageStatus(e.target.value as TriageStatus)}
                      >
                        <option value="open">Open</option>
                        <option value="in_progress">In Progress</option>
                        <option value="closed">Closed</option>
                      </select>
                    </div>
                  </div>

                  {classification === 'duplicate' && (
                    <div className="form-group">
                      <label className="form-label">Mark as duplicate of (Primary Alert)</label>
                      <select
                        className="form-select"
                        value={primaryAlertId}
                        onChange={e => setPrimaryAlertId(e.target.value ? Number(e.target.value) : '')}
                      >
                        <option value="">-- Select Primary Alert --</option>
                        {allAlerts
                          .filter(a => a.id !== alert.id)
                          .map(a => (
                            <option key={a.id} value={a.id}>
                              Alert #{a.id} - {a.rule_name} ({a.hostname || 'no-host'})
                            </option>
                          ))
                        }
                      </select>
                    </div>
                  )}

                  <div className="form-group">
                    <label className="form-label">Analyst Notes</label>
                    <textarea
                      className="form-input"
                      rows={3}
                      style={{ resize: 'vertical', fontFamily: 'inherit', fontSize: '0.8rem' }}
                      placeholder="Add investigation details, evidence rationale, or root cause analysis..."
                      value={analystNotes}
                      onChange={e => setAnalystNotes(e.target.value)}
                    />
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: '16px', alignItems: 'flex-end' }}>
                    <div className="form-group">
                      <label className="form-label">Reviewed By</label>
                      <input
                        className="form-input"
                        style={{ fontSize: '0.8rem' }}
                        value={reviewedBy}
                        onChange={e => setReviewedBy(e.target.value)}
                      />
                    </div>
                    <button
                      className="btn btn-primary"
                      onClick={handleSaveTriage}
                      disabled={triageMutation.isPending}
                      style={{ padding: '8px 18px', fontSize: '0.8rem' }}
                    >
                      {triageMutation.isPending ? 'Saving...' : 'Save Triage'}
                    </button>
                  </div>
                </div>

                {/* Right Column: Evidence Details & Triage History */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                  
                  {/* Evidence Json */}
                  <div style={{
                    background: 'var(--bg-card, #1e293b)', padding: '16px', borderRadius: '10px',
                    border: '1px solid var(--border-default, #334155)',
                  }}>
                    <div style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '8px' }}>
                      Raw Event Evidence (Immutable)
                    </div>
                    <div style={{
                      fontFamily: 'var(--font-mono)', fontSize: '0.73rem', color: 'var(--text-secondary)',
                      whiteSpace: 'pre-wrap', wordBreak: 'break-all', maxHeight: '160px', overflowY: 'auto',
                      background: '#090d16', padding: '10px 14px', borderRadius: '6px', border: '1px solid #1e293b',
                    }}>
                      {Object.keys(details).length > 0
                        ? JSON.stringify(details, null, 2)
                        : <span style={{ color: 'var(--text-muted)' }}>No additional raw evidence details</span>
                      }
                    </div>
                  </div>

                  {/* Triage History List */}
                  <div style={{
                    background: 'var(--bg-card, #1e293b)', padding: '16px', borderRadius: '10px',
                    border: '1px solid var(--border-default, #334155)', flex: 1,
                  }}>
                    <h5 style={{ margin: '0 0 12px 0', fontSize: '0.82rem', color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 6 }}>
                      <History size={14} style={{ color: 'var(--accent)' }} />
                      Triage Audit History ({history.length})
                    </h5>

                    {history.length === 0 ? (
                      <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', fontStyle: 'italic' }}>
                        No previous triage history recorded.
                      </div>
                    ) : (
                      <div style={{ maxHeight: '160px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                        {history.map(h => (
                          <div key={h.id} style={{
                            padding: '10px 12px', borderRadius: '6px', background: 'var(--bg-elevated, #0f172a)',
                            border: '1px solid var(--border-subtle, #1e293b)', fontSize: '0.75rem',
                          }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                              <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{h.reviewed_by || 'local analyst'}</span>
                              <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', fontSize: '0.7rem' }}>
                                {h.created_at ? format(parseISO(h.created_at), 'MMM d, HH:mm:ss') : ''}
                              </span>
                            </div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
                              <ClassificationBadge classification={h.new_classification as AlertClassification} />
                              <span style={{ color: 'var(--text-muted)' }}>·</span>
                              <TriageStatusBadge status={h.new_triage_status as TriageStatus} />
                              {h.primary_alert_id && <span style={{ color: 'var(--text-muted)', fontSize: '0.7rem' }}>(Duplicate of #{h.primary_alert_id})</span>}
                            </div>
                            {h.analyst_notes && (
                              <div style={{ color: 'var(--text-secondary)', fontStyle: 'italic', marginTop: '6px', wordBreak: 'break-word' }}>
                                "{h.analyst_notes}"
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                </div>

              </div>

            </div>
          </td>
        </tr>
      )}
    </>
  );
}

export default function AlertTable({
  alerts, total, page, pageSize, onPageChange, loading,
}: AlertTableProps) {
  const totalPages = Math.ceil(total / pageSize);

  if (loading) {
    return <div className="loading-spinner"><div className="spinner" /></div>;
  }

  if (alerts.length === 0) {
    return (
      <div className="empty-state">
        <div className="empty-state-title">No alerts found</div>
        <div className="empty-state-sub">Try adjusting your filters or run detections on a log batch</div>
      </div>
    );
  }

  return (
    <>
      <div className="table-wrapper">
        <table>
          <thead>
            <tr>
              <th style={{ width: 36 }} />
              <th>Severity</th>
              <th>Rule</th>
              <th>Classification</th>
              <th>Status</th>
              <th>Technique</th>
              <th>Tactic</th>
              <th>Hostname</th>
              <th>Username</th>
              <th>Triggered At</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map(a => <AlertRow key={a.id} alert={a} allAlerts={alerts} />)}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          marginTop: 16, color: 'var(--text-secondary)', fontSize: '0.82rem',
        }}>
          <span>{total.toLocaleString()} total alerts</span>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <button
              className="btn btn-outline btn-sm"
              onClick={() => onPageChange(page - 1)}
              disabled={page <= 1}
            >
              Previous
            </button>
            <span style={{ color: 'var(--accent)', fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>
              {page} / {totalPages}
            </span>
            <button
              className="btn btn-outline btn-sm"
              onClick={() => onPageChange(page + 1)}
              disabled={page >= totalPages}
            >
              Next
            </button>
          </div>
        </div>
      )}
    </>
  );
}

