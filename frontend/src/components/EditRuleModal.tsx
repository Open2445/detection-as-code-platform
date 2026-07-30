import { useState, useEffect } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { X, Code, CheckCircle, AlertTriangle, FileCode, Check, RotateCcw } from 'lucide-react';
import { ruleChangesApi } from '../api/client';
import type { SigmaRule, RuleValidateResponse } from '../types';

interface EditRuleModalProps {
  isOpen: boolean;
  rule: SigmaRule | null;
  onClose: () => void;
  onSuccess: () => void;
}

export default function EditRuleModal({ isOpen, rule, onClose, onSuccess }: EditRuleModalProps) {
  const qc = useQueryClient();
  const [format, setFormat] = useState<'yaml' | 'json'>('yaml');
  
  // Independent content states to preserve edits when switching tabs
  const [yamlContent, setYamlContent] = useState('');
  const [jsonContent, setJsonContent] = useState('');
  
  const [changeReason, setChangeReason] = useState('');
  const [expectedOutcome, setExpectedOutcome] = useState('');
  
  const [valResult, setValResult] = useState<RuleValidateResponse | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    if (rule && isOpen) {
      setYamlContent(rule.yaml_content || '');
      setJsonContent(rule.json_content || '');
      setFormat(rule.rule_format === 'json' ? 'json' : 'yaml');
      setChangeReason('');
      setExpectedOutcome('');
      setValResult(null);
      setErrorMsg(null);
    }
  }, [rule, isOpen]);

  const validateMutation = useMutation({
    mutationFn: () => ruleChangesApi.validate(rule!.id, {
      rule_format: format,
      content: format === 'yaml' ? yamlContent : jsonContent
    }),
    onSuccess: (data) => setValResult(data),
    onError: (err: any) => {
      setValResult(null);
      setErrorMsg(err.response?.data?.detail || 'Validation failed');
    }
  });

  const saveMutation = useMutation({
    mutationFn: (type: 'draft' | 'submitted') => ruleChangesApi.create(rule!.id, {
      rule_format: format,
      new_content: format === 'yaml' ? yamlContent : jsonContent,
      change_reason: changeReason,
      expected_outcome: expectedOutcome,
    }, type),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['rules'] });
      qc.invalidateQueries({ queryKey: ['ruleChanges', rule?.id] });
      onSuccess();
      onClose();
    },
    onError: (err: any) => {
      setErrorMsg(err.response?.data?.detail || 'Failed to save rule change');
    }
  });

  if (!isOpen || !rule) return null;

  const handleFormatChange = (newFormat: 'yaml' | 'json') => {
    setFormat(newFormat);
    setValResult(null);
    setErrorMsg(null);
  };

  const currentContent = format === 'yaml' ? yamlContent : jsonContent;

  const handleValidate = () => {
    if (!currentContent.trim()) {
      setErrorMsg('Content cannot be empty');
      return;
    }
    setErrorMsg(null);
    validateMutation.mutate();
  };

  const handleSave = (type: 'draft' | 'submitted') => {
    if (!currentContent.trim()) {
      setErrorMsg('Content cannot be empty');
      return;
    }
    if (!changeReason.trim()) {
      setErrorMsg('Change reason is required');
      return;
    }
    setErrorMsg(null);
    saveMutation.mutate(type);
  };

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 1000,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      background: 'rgba(3, 7, 18, 0.75)', backdropFilter: 'blur(6px)',
      padding: 16,
    }}>
      <div style={{
        background: 'var(--bg-card)',
        border: '1px solid var(--border-default)',
        borderRadius: 'var(--radius-lg)',
        width: '100%', maxWidth: 860,
        height: '90vh', display: 'flex', flexDirection: 'column',
        boxShadow: '0 20px 40px rgba(0,0,0,0.5)',
        animation: 'fadeInUp 0.2s ease-out',
      }}>
        {/* Header */}
        <div style={{
          padding: '20px 24px', borderBottom: '1px solid var(--border-subtle)',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{
              width: 36, height: 36, borderRadius: 'var(--radius-sm)',
              background: 'var(--accent-dim)', border: '1px solid var(--border-default)',
              display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--accent)',
            }}>
              <Code size={18} />
            </div>
            <div>
              <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
                Edit Rule: {rule.title}
              </h3>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 4 }}>
                <span className="badge badge-medium" style={{ fontSize: '0.65rem' }}>{rule.name}</span>
              </div>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            style={{
              background: 'transparent', border: 'none', color: 'var(--text-muted)',
              cursor: 'pointer', padding: 4, borderRadius: 4, display: 'flex',
            }}
          >
            <X size={18} />
          </button>
        </div>

        {/* Body */}
        <div style={{ padding: '20px 24px', overflowY: 'auto', flex: 1, display: 'flex', flexDirection: 'column', gap: 16 }}>
          
          {/* Format Tabs */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div style={{
              display: 'inline-flex', background: 'var(--bg-surface)',
              padding: 4, borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)',
            }}>
              <button
                type="button"
                onClick={() => handleFormatChange('yaml')}
                disabled={!rule.yaml_content}
                title={!rule.yaml_content ? "No native YAML format exists. Format conversion not supported." : ""}
                style={{
                  padding: '6px 16px', borderRadius: 4, border: 'none', fontSize: '0.8rem',
                  fontWeight: 500, cursor: !rule.yaml_content ? 'not-allowed' : 'pointer', transition: 'var(--transition)',
                  background: format === 'yaml' ? 'var(--accent)' : 'transparent',
                  color: format === 'yaml' ? '#000' : (!rule.yaml_content ? 'var(--text-muted)' : 'var(--text-secondary)'),
                  opacity: !rule.yaml_content ? 0.5 : 1,
                }}
              >
                <FileCode size={13} style={{ marginRight: 6, verticalAlign: -2 }} />
                Sigma YAML
              </button>
              <button
                type="button"
                onClick={() => handleFormatChange('json')}
                disabled={!rule.json_content}
                title={!rule.json_content ? "No native JSON format exists. Format conversion not supported." : ""}
                style={{
                  padding: '6px 16px', borderRadius: 4, border: 'none', fontSize: '0.8rem',
                  fontWeight: 500, cursor: !rule.json_content ? 'not-allowed' : 'pointer', transition: 'var(--transition)',
                  background: format === 'json' ? 'var(--accent)' : 'transparent',
                  color: format === 'json' ? '#000' : (!rule.json_content ? 'var(--text-muted)' : 'var(--text-secondary)'),
                  opacity: !rule.json_content ? 0.5 : 1,
                }}
              >
                <Code size={13} style={{ marginRight: 6, verticalAlign: -2 }} />
                JSON Logic
              </button>
            </div>
            {((format === 'yaml' && !rule.yaml_content) || (format === 'json' && !rule.json_content)) && (
              <div style={{ fontSize: '0.75rem', color: 'var(--sev-high)' }}>
                <AlertTriangle size={12} style={{ display: 'inline', marginRight: 4, verticalAlign: -2 }} />
                Native format missing.
              </div>
            )}
          </div>

          {errorMsg && (
            <div style={{
              padding: '12px 16px', borderRadius: 'var(--radius-sm)',
              background: 'rgba(255, 61, 110, 0.12)', border: '1px solid rgba(255, 61, 110, 0.3)',
              color: 'var(--sev-critical)', fontSize: '0.82rem', display: 'flex', alignItems: 'flex-start', gap: 10,
            }}>
              <AlertTriangle size={16} style={{ marginTop: 2, flexShrink: 0 }} />
              <div>{errorMsg}</div>
            </div>
          )}

          {valResult && (
            <div style={{
              padding: '12px 16px', borderRadius: 'var(--radius-sm)',
              background: valResult.valid ? 'rgba(0, 230, 118, 0.1)' : 'rgba(255, 61, 110, 0.12)', 
              border: valResult.valid ? '1px solid rgba(0, 230, 118, 0.3)' : '1px solid rgba(255, 61, 110, 0.3)',
              color: valResult.valid ? 'var(--sev-low)' : 'var(--sev-critical)', fontSize: '0.82rem',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontWeight: 600, marginBottom: valResult.errors.length || valResult.warnings.length ? 8 : 0 }}>
                {valResult.valid ? <CheckCircle size={16} /> : <AlertTriangle size={16} />}
                {valResult.valid ? 'Validation Passed' : 'Validation Failed'}
              </div>
              {valResult.errors.length > 0 && (
                <ul style={{ margin: '4px 0 0 24px', padding: 0 }}>
                  {valResult.errors.map((e, i) => <li key={i}>{e}</li>)}
                </ul>
              )}
              {valResult.warnings.length > 0 && (
                <div style={{ marginTop: 8, color: 'var(--sev-medium)' }}>
                  <strong>Warnings:</strong>
                  <ul style={{ margin: '4px 0 0 24px', padding: 0 }}>
                    {valResult.warnings.map((w, i) => <li key={i}>{w}</li>)}
                  </ul>
                </div>
              )}
            </div>
          )}

          <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
            <textarea
              value={format === 'yaml' ? yamlContent : jsonContent}
              onChange={e => format === 'yaml' ? setYamlContent(e.target.value) : setJsonContent(e.target.value)}
              placeholder={`Enter ${format.toUpperCase()} logic...`}
              style={{
                width: '100%', height: '100%', fontFamily: 'var(--font-mono)', fontSize: '0.8rem',
                padding: 14, borderRadius: 'var(--radius-sm)', background: 'var(--bg-input)',
                border: '1px solid var(--border-default)', color: 'var(--text-primary)',
                resize: 'none', lineHeight: 1.5,
              }}
            />
          </div>

          <div style={{ display: 'flex', gap: 16 }}>
            <div style={{ flex: 1 }}>
              <label className="form-label">Change Reason (Required)</label>
              <textarea
                className="form-input"
                value={changeReason}
                onChange={e => setChangeReason(e.target.value)}
                placeholder="Why is this change necessary?"
                rows={3}
                style={{ resize: 'vertical' }}
              />
            </div>
            <div style={{ flex: 1 }}>
              <label className="form-label">Expected Outcome (Optional)</label>
              <textarea
                className="form-input"
                value={expectedOutcome}
                onChange={e => setExpectedOutcome(e.target.value)}
                placeholder="What should this fix/improve?"
                rows={3}
                style={{ resize: 'vertical' }}
              />
            </div>
          </div>
        </div>

        {/* Footer */}
        <div style={{
          padding: '16px 24px', borderTop: '1px solid var(--border-subtle)',
          display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--bg-surface)',
          borderBottomLeftRadius: 'var(--radius-lg)', borderBottomRightRadius: 'var(--radius-lg)',
        }}>
          <div>
            <button
              type="button"
              className="btn btn-outline"
              onClick={handleValidate}
              disabled={validateMutation.isPending}
            >
              <Check size={14} style={{ marginRight: 6 }} />
              Validate
            </button>
          </div>
          <div style={{ display: 'flex', gap: 12 }}>
            <button
              type="button"
              className="btn btn-outline"
              onClick={onClose}
            >
              Cancel
            </button>
            <button
              type="button"
              className="btn btn-outline"
              onClick={() => handleSave('draft')}
              disabled={saveMutation.isPending}
              style={{ color: 'var(--text-primary)' }}
            >
              Save Draft
            </button>
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => handleSave('submitted')}
              disabled={saveMutation.isPending}
            >
              Submit Rule Change
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
