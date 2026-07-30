import { useState, useEffect } from 'react';
import { X, CheckCircle, ShieldCheck } from 'lucide-react';
import { rulesApi, logsApi } from '../api/client';
import type { SigmaRule, ValidationStatus, UploadBatch } from '../types';

interface RuleValidationModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
  rule: SigmaRule | null;
}

export default function RuleValidationModal({
  isOpen,
  onClose,
  onSuccess,
  rule,
}: RuleValidationModalProps) {
  const [validationStatus, setValidationStatus] = useState<ValidationStatus>('unvalidated');
  const [validationNotes, setValidationNotes] = useState('');
  const [evidenceBatchId, setEvidenceBatchId] = useState<number | ''>('');
  const [evidenceFilename, setEvidenceFilename] = useState('');
  const [primaryValidated, setPrimaryValidated] = useState(false);
  const [batches, setBatches] = useState<UploadBatch[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen) {
      logsApi.list(0, 100).then(setBatches).catch(() => {});
      if (rule) {
        setValidationStatus(rule.validation_status || 'unvalidated');
        setValidationNotes(rule.validation_notes || '');
        setEvidenceBatchId(rule.validation_evidence_batch_id || '');
        setEvidenceFilename(rule.validation_evidence_filename || '');
        setPrimaryValidated(rule.primary_validated_rule || false);
      }
      setError(null);
    }
  }, [isOpen, rule]);

  if (!isOpen || !rule) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      await rulesApi.updateValidation(rule.id, {
        validation_status: validationStatus,
        validation_notes: validationNotes || null,
        validation_evidence_batch_id: evidenceBatchId !== '' ? Number(evidenceBatchId) : null,
        validation_evidence_filename: evidenceFilename || null,
        primary_validated_rule: primaryValidated,
      });
      onSuccess();
      onClose();
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to update rule validation');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-backdrop" style={{
      position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
      background: 'rgba(0,0,0,0.65)', display: 'flex',
      alignItems: 'center', justifyContent: 'center', zIndex: 1000,
    }}>
      <div className="modal" style={{
        background: 'var(--bg-card, #1e293b)',
        border: '1px solid var(--border-default, #334155)',
        borderRadius: '12px',
        padding: '24px',
        width: '100%',
        maxWidth: '560px',
        color: 'var(--text-primary, #f8fafc)',
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <ShieldCheck size={22} style={{ color: 'var(--accent, #38bdf8)' }} />
            <h2 style={{ fontSize: '1.2rem', fontWeight: 600, margin: 0 }}>Update Rule Validation</h2>
          </div>
          <button
            onClick={onClose}
            style={{ background: 'none', border: 'none', color: 'var(--text-muted, #94a3b8)', cursor: 'pointer' }}
          >
            <X size={18} />
          </button>
        </div>

        <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary, #cbd5e1)', marginBottom: '16px' }}>
          Rule: <strong style={{ color: 'var(--text-primary, #fff)' }}>{rule.title}</strong>
        </p>

        {error && (
          <div style={{
            padding: '10px 14px', borderRadius: '6px', background: 'rgba(239,68,68,0.15)',
            border: '1px solid #ef4444', color: '#fca5a5', fontSize: '0.85rem', marginBottom: '16px',
          }}>
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div className="form-group mb-3" style={{ marginBottom: 16 }}>
            <label className="form-label" style={{ display: 'block', marginBottom: 6, fontSize: '0.82rem' }}>
              Validation Status
            </label>
            <select
              className="form-select"
              style={{ width: '100%' }}
              value={validationStatus}
              onChange={e => setValidationStatus(e.target.value as ValidationStatus)}
            >
              <option value="unvalidated">Unvalidated</option>
              <option value="validated_in_lab">Validated in Lab</option>
              <option value="needs_tuning">Needs Tuning</option>
            </select>
          </div>

          <div className="form-group mb-3" style={{ marginBottom: 16 }}>
            <label className="form-label" style={{ display: 'block', marginBottom: 6, fontSize: '0.82rem' }}>
              Evidence Log Batch (Uploaded EVTX / JSON)
            </label>
            <select
              className="form-select"
              style={{ width: '100%' }}
              value={evidenceBatchId}
              onChange={e => {
                const val = e.target.value ? Number(e.target.value) : '';
                setEvidenceBatchId(val);
                if (val !== '') {
                  const found = batches.find(b => b.id === val);
                  if (found) setEvidenceFilename(found.filename);
                }
              }}
            >
              <option value="">-- Select Evidence Batch --</option>
              {batches.map(b => (
                <option key={b.id} value={b.id}>
                  Batch #{b.id} - {b.filename} ({b.log_count} logs)
                </option>
              ))}
            </select>
          </div>

          <div className="form-group mb-3" style={{ marginBottom: 16 }}>
            <label className="form-label" style={{ display: 'block', marginBottom: 6, fontSize: '0.82rem' }}>
              Evidence Filename / External Reference (EVTX)
            </label>
            <input
              className="form-input"
              style={{ width: '100%' }}
              placeholder="e.g. powershell_attack_simulation.evtx"
              value={evidenceFilename}
              onChange={e => setEvidenceFilename(e.target.value)}
            />
          </div>

          <div className="form-group mb-3" style={{ marginBottom: 16 }}>
            <label className="form-label" style={{ display: 'block', marginBottom: 6, fontSize: '0.82rem' }}>
              Validation Notes
            </label>
            <textarea
              className="form-input"
              rows={3}
              style={{ width: '100%', resize: 'vertical', fontFamily: 'inherit' }}
              placeholder="Details about lab environment, test commands executed, or tuning notes..."
              value={validationNotes}
              onChange={e => setValidationNotes(e.target.value)}
            />
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 20 }}>
            <input
              type="checkbox"
              id="primary_validated_rule"
              checked={primaryValidated}
              onChange={e => setPrimaryValidated(e.target.checked)}
              style={{ cursor: 'pointer' }}
            />
            <label htmlFor="primary_validated_rule" style={{ fontSize: '0.85rem', cursor: 'pointer' }}>
              Primary Validated Rule for this Technique / Category
            </label>
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
            <button type="button" className="btn btn-outline" onClick={onClose}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary" disabled={loading}>
              <CheckCircle size={14} style={{ marginRight: 4 }} />
              {loading ? 'Saving...' : 'Save Validation'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
