import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { ruleChangesApi } from '../api/client';
import { Clock, CheckCircle2, RotateCcw, FileEdit, AlertCircle } from 'lucide-react';
import type { SigmaRule, RuleChange } from '../types';

interface RuleChangeHistoryProps {
  rule: SigmaRule;
}

export default function RuleChangeHistory({ rule }: RuleChangeHistoryProps) {
  const qc = useQueryClient();
  const { data: changes = [], isLoading } = useQuery({
    queryKey: ['ruleChanges', rule.id],
    queryFn: () => ruleChangesApi.list(rule.id),
  });

  const applyMutation = useMutation({
    mutationFn: (changeId: number) => ruleChangesApi.apply(rule.id, changeId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['rules'] });
      qc.invalidateQueries({ queryKey: ['ruleChanges', rule.id] });
    },
    onError: (err: any) => {
      alert(`Apply failed: ${err.response?.data?.detail || err.message}`);
    }
  });

  const revertMutation = useMutation({
    mutationFn: (changeId: number) => ruleChangesApi.revert(rule.id, changeId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['rules'] });
      qc.invalidateQueries({ queryKey: ['ruleChanges', rule.id] });
    },
    onError: (err: any) => {
      alert(`Revert failed: ${err.response?.data?.detail || err.message}`);
    }
  });

  if (isLoading) return <div style={{ padding: 12, fontSize: '0.8rem' }}>Loading history...</div>;
  
  if (changes.length === 0) return (
    <div style={{ padding: 20, textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
      No change history for this rule.
    </div>
  );

  return (
    <div style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <h4 style={{ margin: 0, fontSize: '0.9rem', color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 6 }}>
        <Clock size={14} /> Rule Change History
      </h4>
      
      {changes.map(change => (
        <div key={change.id} style={{
          background: 'var(--bg-card)', border: '1px solid var(--border-subtle)',
          borderRadius: 'var(--radius-sm)', padding: 16, display: 'flex', flexDirection: 'column', gap: 10
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                <span className={`badge ${change.change_type === 'applied' ? 'badge-low' : change.change_type === 'reverted' ? 'badge-high' : 'badge-medium'}`}>
                  {change.change_type.toUpperCase()}
                </span>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                  by <strong>{change.changed_by}</strong> on {new Date(change.changed_at).toLocaleString()}
                </span>
                <span className="badge" style={{ fontSize: '0.65rem' }}>{change.rule_format.toUpperCase()}</span>
              </div>
              <div style={{ fontSize: '0.85rem', color: 'var(--text-primary)' }}>
                <strong>Reason:</strong> {change.change_reason}
              </div>
              {change.expected_outcome && (
                <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: 2 }}>
                  <strong>Expected:</strong> {change.expected_outcome}
                </div>
              )}
            </div>
            
            <div style={{ display: 'flex', gap: 8 }}>
              {change.change_type === 'submitted' && (
                <button
                  className="btn btn-outline btn-sm"
                  onClick={() => applyMutation.mutate(change.id)}
                  disabled={applyMutation.isPending}
                  title="Apply this proposed change"
                >
                  <CheckCircle2 size={13} style={{ marginRight: 4 }} /> Apply Change
                </button>
              )}
              {change.change_type === 'applied' && (
                <button
                  className="btn btn-outline btn-sm"
                  onClick={() => revertMutation.mutate(change.id)}
                  disabled={revertMutation.isPending}
                  title="Revert to this previous version"
                >
                  <RotateCcw size={13} style={{ marginRight: 4 }} /> Revert to this version
                </button>
              )}
            </div>
          </div>
          
          <details>
            <summary style={{ fontSize: '0.8rem', cursor: 'pointer', color: 'var(--accent)', fontWeight: 500 }}>View Content / Diff</summary>
            <div style={{ marginTop: 8, display: 'flex', gap: 12 }}>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: 4 }}>New Content</div>
                <pre style={{
                  fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--text-secondary)',
                  overflowX: 'auto', margin: 0, padding: 10, background: 'var(--bg-input)', borderRadius: 4, border: '1px solid var(--border-default)',
                  maxHeight: 200, overflowY: 'auto'
                }}>
                  {change.new_content}
                </pre>
              </div>
              {change.previous_content && (
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: 4 }}>Previous Content</div>
                  <pre style={{
                    fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--text-secondary)',
                    overflowX: 'auto', margin: 0, padding: 10, background: 'var(--bg-input)', borderRadius: 4, border: '1px solid var(--border-default)',
                    maxHeight: 200, overflowY: 'auto'
                  }}>
                    {change.previous_content}
                  </pre>
                </div>
              )}
            </div>
          </details>
        </div>
      ))}
    </div>
  );
}
