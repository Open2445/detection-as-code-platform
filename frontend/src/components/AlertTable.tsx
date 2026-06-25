import { useState } from 'react';
import { format, parseISO } from 'date-fns';
import { ChevronDown, ChevronRight, ExternalLink } from 'lucide-react';
import type { Alert, Severity } from '../types';

interface AlertTableProps {
  alerts: Alert[];
  total: number;
  page: number;
  pageSize: number;
  onPageChange: (page: number) => void;
  loading?: boolean;
}

const SEV_ORDER: Record<Severity, number> = {
  critical: 0, high: 1, medium: 2, low: 3, informational: 4,
};

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={`badge badge-${severity}`}>
      <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'currentColor', display: 'inline-block' }} />
      {severity}
    </span>
  );
}

function AlertRow({ alert }: { alert: Alert }) {
  const [expanded, setExpanded] = useState(false);

  let details: Record<string, unknown> = {};
  try {
    details = alert.details_json ? JSON.parse(alert.details_json) : {};
  } catch { /* ignore */ }

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
        <td style={{ color: 'var(--text-primary)', fontWeight: 500, maxWidth: 200 }}>
          <span className="truncate" style={{ display: 'block' }}>{alert.rule_name}</span>
        </td>
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
          <td colSpan={8} style={{ padding: '0 0 0 40px', background: 'var(--bg-elevated)' }}>
            <div style={{
              padding: '12px 16px',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.75rem',
              color: 'var(--text-secondary)',
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-all',
            }}>
              {Object.keys(details).length > 0
                ? JSON.stringify(details, null, 2)
                : <span style={{ color: 'var(--text-muted)' }}>No additional details available</span>
              }
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
              <th>Technique</th>
              <th>Tactic</th>
              <th>Hostname</th>
              <th>Username</th>
              <th>Triggered At</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map(a => <AlertRow key={a.id} alert={a} />)}
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
