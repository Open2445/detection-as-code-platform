import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { X, Code, CheckCircle, AlertTriangle, FileCode } from 'lucide-react';
import { rulesApi } from '../api/client';

interface AddRuleModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

const SAMPLE_YAML = `title: Custom Suspicious Process Execution
name: custom_suspicious_process_exec
description: Detects execution of cmd.exe creating powershell subprocesses
level: high
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    EventID: 1
    ParentImage|endswith: '\\cmd.exe'
    Image|endswith: '\\powershell.exe'
  condition: selection`;

const SAMPLE_JSON = `{
  "title": "Custom Suspicious Process Execution",
  "name": "custom_suspicious_process_exec",
  "description": "Detects execution of cmd.exe creating powershell subprocesses",
  "level": "high",
  "tags": [
    "attack.execution",
    "attack.t1059.001"
  ],
  "logsource": {
    "category": "process_creation",
    "product": "windows"
  },
  "detection": {
    "selection": {
      "EventID": 1,
      "ParentImage|endswith": "\\\\cmd.exe",
      "Image|endswith": "\\\\powershell.exe"
    },
    "condition": "selection"
  }
}`;

export default function AddRuleModal({ isOpen, onClose, onSuccess }: AddRuleModalProps) {
  const [format, setFormat] = useState<'yaml' | 'json'>('yaml');
  const [ruleText, setRuleText] = useState(SAMPLE_YAML);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const createMutation = useMutation({
    mutationFn: () => rulesApi.createRaw(ruleText, format),
    onSuccess: () => {
      setErrorMsg(null);
      onSuccess();
      onClose();
    },
    onError: (err: any) => {
      const msg = err.response?.data?.detail || err.message || 'Failed to create rule';
      setErrorMsg(msg);
    },
  });

  if (!isOpen) return null;

  const handleTabChange = (newFormat: 'yaml' | 'json') => {
    setFormat(newFormat);
    setErrorMsg(null);
    if (newFormat === 'yaml' && (ruleText === SAMPLE_JSON || ruleText.trim() === '')) {
      setRuleText(SAMPLE_YAML);
    } else if (newFormat === 'json' && (ruleText === SAMPLE_YAML || ruleText.trim() === '')) {
      setRuleText(SAMPLE_JSON);
    }
  };

  const handleLoadSample = () => {
    setErrorMsg(null);
    setRuleText(format === 'yaml' ? SAMPLE_YAML : SAMPLE_JSON);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!ruleText.trim()) {
      setErrorMsg('Rule content cannot be empty');
      return;
    }
    setErrorMsg(null);
    createMutation.mutate();
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
        width: '100%', maxWidth: 720,
        maxHeight: '90vh', display: 'flex', flexDirection: 'column',
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
                Add Custom Sigma Rule
              </h3>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', margin: 0 }}>
                Create detection rules using standard Sigma YAML or JSON format
              </p>
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

        {/* Form Body */}
        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', flex: 1, overflow: 'hidden' }}>
          <div style={{ padding: '20px 24px', overflowY: 'auto', flex: 1, display: 'flex', flexDirection: 'column', gap: 16 }}>
            {/* Format Selector Tabs */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{
                display: 'inline-flex', background: 'var(--bg-surface)',
                padding: 4, borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)',
              }}>
                <button
                  type="button"
                  onClick={() => handleTabChange('yaml')}
                  style={{
                    padding: '6px 16px', borderRadius: 4, border: 'none', fontSize: '0.8rem',
                    fontWeight: 500, cursor: 'pointer', transition: 'var(--transition)',
                    background: format === 'yaml' ? 'var(--accent)' : 'transparent',
                    color: format === 'yaml' ? '#000' : 'var(--text-secondary)',
                  }}
                >
                  <FileCode size={13} style={{ marginRight: 6, verticalAlign: -2 }} />
                  YAML Format
                </button>
                <button
                  type="button"
                  onClick={() => handleTabChange('json')}
                  style={{
                    padding: '6px 16px', borderRadius: 4, border: 'none', fontSize: '0.8rem',
                    fontWeight: 500, cursor: 'pointer', transition: 'var(--transition)',
                    background: format === 'json' ? 'var(--accent)' : 'transparent',
                    color: format === 'json' ? '#000' : 'var(--text-secondary)',
                  }}
                >
                  <Code size={13} style={{ marginRight: 6, verticalAlign: -2 }} />
                  JSON Format
                </button>
              </div>

              <button
                type="button"
                className="btn btn-outline btn-sm"
                onClick={handleLoadSample}
                style={{ fontSize: '0.75rem' }}
              >
                Load Sample Template
              </button>
            </div>

            {/* Error Notification */}
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

            {/* Code Textarea */}
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
              <label className="form-label" style={{ marginBottom: 6, display: 'flex', justifyContent: 'space-between' }}>
                <span>Rule Definition ({format.toUpperCase()})</span>
                <span style={{ color: 'var(--text-muted)', fontSize: '0.72rem' }}>Must include title and detection blocks</span>
              </label>
              <textarea
                value={ruleText}
                onChange={e => setRuleText(e.target.value)}
                placeholder={format === 'yaml' ? 'Paste Sigma YAML content...' : 'Paste Sigma JSON content...'}
                rows={12}
                style={{
                  width: '100%', fontFamily: 'var(--font-mono)', fontSize: '0.8rem',
                  padding: 14, borderRadius: 'var(--radius-sm)', background: 'var(--bg-input)',
                  border: '1px solid var(--border-default)', color: 'var(--text-primary)',
                  resize: 'vertical', lineHeight: 1.5,
                }}
              />
            </div>
          </div>

          {/* Footer Actions */}
          <div style={{
            padding: '16px 24px', borderTop: '1px solid var(--border-subtle)',
            display: 'flex', justifyContent: 'flex-end', gap: 12, background: 'var(--bg-surface)',
          }}>
            <button
              type="button"
              className="btn btn-outline"
              onClick={onClose}
              disabled={createMutation.isPending}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="btn btn-primary"
              disabled={createMutation.isPending}
            >
              {createMutation.isPending ? (
                <>
                  <div className="spinner" style={{ width: 14, height: 14, marginRight: 8 }} />
                  Saving Rule...
                </>
              ) : (
                <>
                  <CheckCircle size={14} style={{ marginRight: 6 }} />
                  Add Detection Rule
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
