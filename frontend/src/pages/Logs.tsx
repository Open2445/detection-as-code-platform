import { useState, useRef, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { format, parseISO } from 'date-fns';
import { Upload, Play, Trash2, FileText, ChevronRight } from 'lucide-react';
import { logsApi, detectionsApi } from '../api/client';
import type { UploadBatch, DetectionRunResult } from '../types';

export default function Logs() {
  const qc = useQueryClient();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [dragOver, setDragOver] = useState(false);
  const [uploadMsg, setUploadMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [detectionResult, setDetectionResult] = useState<DetectionRunResult | null>(null);
  const [runningBatchId, setRunningBatchId] = useState<number | null>(null);

  const { data: batches, isLoading } = useQuery({
    queryKey: ['log-batches'],
    queryFn: () => logsApi.list(0, 100),
  });

  const uploadMutation = useMutation({
    mutationFn: (file: File) => logsApi.upload(file),
    onSuccess: (data) => {
      setUploadMsg({ type: 'success', text: data.message });
      qc.invalidateQueries({ queryKey: ['log-batches'] });
      qc.invalidateQueries({ queryKey: ['dashboard-stats'] });
    },
    onError: (err: any) => {
      setUploadMsg({ type: 'error', text: err.response?.data?.detail || 'Upload failed' });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (batchId: number) => logsApi.delete(batchId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['log-batches'] });
      qc.invalidateQueries({ queryKey: ['dashboard-stats'] });
    },
  });

  const handleFile = (file: File) => {
    setUploadMsg(null);
    setDetectionResult(null);
    uploadMutation.mutate(file);
  };

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files[0];
    if (file) handleFile(file);
  }, []);

  const handleRunDetections = async (batchId: number) => {
    setRunningBatchId(batchId);
    setDetectionResult(null);
    try {
      const result = await detectionsApi.run(batchId);
      setDetectionResult(result);
      qc.invalidateQueries({ queryKey: ['log-batches'] });
      qc.invalidateQueries({ queryKey: ['dashboard-stats'] });
      qc.invalidateQueries({ queryKey: ['alerts'] });
    } catch (e: any) {
      setUploadMsg({ type: 'error', text: e.response?.data?.detail || 'Detection run failed' });
    } finally {
      setRunningBatchId(null);
    }
  };

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Log Management</h1>
        <p className="page-subtitle">Upload Sysmon/Windows Event JSON or binary EVTX logs and run Sigma detections</p>
      </div>

      {/* Upload Zone */}
      <div
        className={`upload-zone mb-6 ${dragOver ? 'drag-over' : ''}`}
        onDragOver={e => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
      >
        <div className="upload-zone-icon">
          <Upload size={40} />
        </div>
        <div className="upload-zone-title">
          {uploadMutation.isPending ? 'Uploading...' : 'Drop EVTX or JSON log file here'}
        </div>
        <div className="upload-zone-sub">
          Accepts native binary .evtx, JSON array, or NDJSON format · Sysmon & Windows Event Logs
        </div>
        <input
          ref={fileInputRef}
          type="file"
          accept=".json,.evtx"
          style={{ display: 'none' }}
          onChange={e => {
            const file = e.target.files?.[0];
            if (file) handleFile(file);
            e.target.value = '';
          }}
        />
      </div>

      {/* Messages */}
      {uploadMsg && (
        <div className={`alert-banner ${uploadMsg.type}`}>
          {uploadMsg.type === 'success' ? '✓' : '✗'} {uploadMsg.text}
        </div>
      )}
      {detectionResult && (
        <div className="alert-banner success">
          ✓ Detection complete — {detectionResult.alerts_generated} alerts generated
          from {detectionResult.logs_scanned} logs × {detectionResult.rules_evaluated} rules
          in {detectionResult.duration_seconds}s
        </div>
      )}

      {/* Batch List */}
      <div className="card">
        <div className="card-title">
          <FileText size={14} />
          Uploaded Batches
        </div>

        {isLoading ? (
          <div className="loading-spinner"><div className="spinner" /></div>
        ) : !batches || batches.length === 0 ? (
          <div className="empty-state" style={{ padding: '40px 0' }}>
            <Upload size={32} className="empty-state-icon" />
            <div className="empty-state-title">No logs uploaded yet</div>
            <div className="empty-state-sub">Upload an EVTX or JSON log file to get started</div>
          </div>

        ) : (
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Filename</th>
                  <th>Uploaded</th>
                  <th>Log Count</th>
                  <th>Status</th>
                  <th>Detections</th>
                  <th style={{ width: 180 }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {batches.map(batch => (
                  <tr key={batch.id}>
                    <td style={{ color: 'var(--text-primary)', fontWeight: 500 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <FileText size={14} style={{ color: 'var(--accent)', flexShrink: 0 }} />
                        {batch.filename}
                      </div>
                    </td>
                    <td className="mono" style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                      {format(parseISO(batch.upload_time), 'MMM d, HH:mm')}
                    </td>
                    <td className="mono" style={{ color: 'var(--accent)' }}>
                      {batch.log_count.toLocaleString()}
                    </td>
                    <td>
                      <span className={`badge ${batch.status === 'processed' ? 'badge-low' : 'badge-medium'}`}>
                        {batch.status}
                      </span>
                    </td>
                    <td>
                      {batch.detections_run ? (
                        <span className="badge badge-low">
                          ✓ Ran {batch.detections_run_at ? format(parseISO(batch.detections_run_at), 'HH:mm') : ''}
                        </span>
                      ) : (
                        <span style={{ color: 'var(--text-muted)', fontSize: '0.78rem' }}>Not run</span>
                      )}
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: 8 }}>
                        <button
                          className="btn btn-primary btn-sm"
                          onClick={() => handleRunDetections(batch.id)}
                          disabled={runningBatchId === batch.id}
                        >
                          <Play size={12} />
                          {runningBatchId === batch.id ? 'Running...' : 'Run Detections'}
                        </button>
                        <button
                          className="btn btn-danger btn-sm btn-icon"
                          onClick={() => deleteMutation.mutate(batch.id)}
                          title="Delete batch"
                        >
                          <Trash2 size={14} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
