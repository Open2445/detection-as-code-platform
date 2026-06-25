import { useQuery } from '@tanstack/react-query';
import { Map, Target, TrendingUp, Layers } from 'lucide-react';
import { dashboardApi } from '../api/client';
import MitreHeatmap from '../components/MitreHeatmap';

export default function Coverage() {
  const { data, isLoading } = useQuery({
    queryKey: ['mitre-coverage'],
    queryFn: dashboardApi.mitreCoverage,
  });

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">ATT&CK Coverage</h1>
        <p className="page-subtitle">MITRE ATT&CK heatmap based on triggered detections</p>
      </div>

      {/* Coverage Summary Cards */}
      <div className="stat-grid" style={{ marginBottom: 24 }}>
        <div className="stat-card warn">
          <div className="stat-card-label"><Target size={13} /> Coverage</div>
          <div className="stat-card-value">
            {data?.coverage_pct ?? 0}
            <span style={{ fontSize: '1rem', fontWeight: 500, marginLeft: 4, opacity: 0.7 }}>%</span>
          </div>
          <div className="stat-card-sub">of seeded rule techniques</div>
        </div>
        <div className="stat-card accent">
          <div className="stat-card-label"><TrendingUp size={13} /> Triggered</div>
          <div className="stat-card-value">{data?.techniques_triggered ?? 0}</div>
          <div className="stat-card-sub">unique techniques with alerts</div>
        </div>
        <div className="stat-card info">
          <div className="stat-card-label"><Layers size={13} /> In Rules</div>
          <div className="stat-card-value">{data?.total_techniques_in_rules ?? 0}</div>
          <div className="stat-card-sub">unique techniques seeded</div>
        </div>
      </div>

      {/* Legend */}
      <div style={{
        display: 'flex', gap: 16, flexWrap: 'wrap',
        marginBottom: 24, padding: '12px 16px',
        background: 'var(--bg-card)',
        border: '1px solid var(--border-subtle)',
        borderRadius: 'var(--radius-sm)',
      }}>
        <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginRight: 4 }}>Heat level:</span>
        {[
          { cls: 'inactive', label: 'No alerts' },
          { cls: 'low',      label: '1–4 alerts' },
          { cls: 'medium',   label: '5–19 alerts' },
          { cls: 'high',     label: '20–49 alerts' },
          { cls: 'critical', label: '50+ alerts' },
        ].map(({ cls, label }) => (
          <div key={cls} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <div className={`mitre-cell ${cls}`} style={{
              padding: '2px 10px', fontSize: '0.65rem',
              minWidth: 'auto', display: 'inline-block',
            }}>
              <span className="mitre-cell-id">T0000</span>
            </div>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>{label}</span>
          </div>
        ))}
      </div>

      {/* MITRE Heatmap */}
      <div className="card">
        <div className="card-title">
          <Map size={14} />
          MITRE ATT&CK Enterprise Matrix
        </div>

        {isLoading ? (
          <div className="loading-spinner"><div className="spinner" /></div>
        ) : (
          <MitreHeatmap data={data} />
        )}
      </div>
    </div>
  );
}
