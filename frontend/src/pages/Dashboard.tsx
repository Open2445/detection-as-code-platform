import { useQuery } from '@tanstack/react-query';
import { dashboardApi } from '../api/client';
import StatCard from '../components/StatCard';
import SeverityChart from '../components/SeverityChart';
import TimelineChart from '../components/TimelineChart';
import {
  Shield, Bell, Database, Layers,
  Server, Target, Cpu, Activity
} from 'lucide-react';

export default function Dashboard() {
  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: dashboardApi.stats,
    refetchInterval: 30_000,
  });

  const { data: timeline } = useQuery({
    queryKey: ['dashboard-timeline'],
    queryFn: () => dashboardApi.timeline(30),
  });

  if (statsLoading) {
    return <div className="loading-spinner"><div className="spinner" /></div>;
  }

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Security Dashboard</h1>
        <p className="page-subtitle">Real-time overview of detections and ATT&CK coverage</p>
      </div>

      {/* KPI Stat Cards */}
      <div className="stat-grid">
        <StatCard
          label="Total Alerts"
          value={stats?.total_alerts ?? 0}
          variant="danger"
          icon={<Bell size={13} />}
          sub="All time"
        />
        <StatCard
          label="Logs Ingested"
          value={stats?.total_logs ?? 0}
          variant="accent"
          icon={<Database size={13} />}
          sub="Across all batches"
        />
        <StatCard
          label="Active Rules"
          value={stats?.total_rules ?? 0}
          variant="info"
          icon={<Shield size={13} />}
          sub="Sigma detections"
        />
        <StatCard
          label="ATT&CK Coverage"
          value={stats?.attack_coverage_pct ?? 0}
          suffix="%"
          variant="warn"
          icon={<Target size={13} />}
          sub={`${stats?.unique_techniques_triggered ?? 0} techniques triggered`}
        />
        <StatCard
          label="Hosts Affected"
          value={stats?.unique_hosts_affected ?? 0}
          variant="danger"
          icon={<Server size={13} />}
          sub="Unique endpoints"
        />
        <StatCard
          label="Log Batches"
          value={stats?.total_batches ?? 0}
          variant="success"
          icon={<Layers size={13} />}
          sub="Uploaded datasets"
        />
      </div>

      {/* Charts Row */}
      <div className="charts-grid">
        {/* Severity Distribution */}
        <div className="card">
          <div className="card-title">
            <Activity size={14} />
            Alert Severity Distribution
          </div>
          <SeverityChart data={stats?.severity_distribution ?? []} />
        </div>

        {/* Alert Timeline */}
        <div className="card chart-full">
          <div className="card-title" style={{ justifyContent: 'space-between' }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Cpu size={14} />
              Alert Timeline (Last 30 Days)
            </span>
            {timeline && (
              <span style={{ color: 'var(--text-muted)', fontSize: '0.72rem', fontWeight: 400 }}>
                {timeline.points.length} days with activity
              </span>
            )}
          </div>
          <TimelineChart data={timeline?.points ?? []} />
        </div>
      </div>

      {/* Top Triggered Rules */}
      <div className="card">
        <div className="card-title">
          <Shield size={14} />
          Top Triggered Rules
        </div>
        {(!stats?.top_rules || stats.top_rules.length === 0) ? (
          <div className="empty-state" style={{ padding: '32px 0' }}>
            <div className="empty-state-sub">No detections yet — upload logs and run detections</div>
          </div>
        ) : (
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Rule Name</th>
                  <th>Severity</th>
                  <th>Alert Count</th>
                  <th>Share</th>
                </tr>
              </thead>
              <tbody>
                {stats.top_rules.map((rule, i) => {
                  const pct = stats.total_alerts > 0
                    ? Math.round((rule.count / stats.total_alerts) * 100)
                    : 0;
                  return (
                    <tr key={rule.rule_id}>
                      <td style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', width: 36 }}>
                        {i + 1}
                      </td>
                      <td style={{ color: 'var(--text-primary)', fontWeight: 500 }}>
                        {rule.rule_name.replace(/_/g, ' ')}
                      </td>
                      <td>
                        <span className={`badge badge-${rule.severity}`}>{rule.severity}</span>
                      </td>
                      <td className="mono" style={{ color: 'var(--accent)' }}>
                        {rule.count.toLocaleString()}
                      </td>
                      <td style={{ width: 180 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                          <div style={{
                            flex: 1, height: 4, background: 'var(--bg-elevated)',
                            borderRadius: 2, overflow: 'hidden',
                          }}>
                            <div style={{
                              width: `${pct}%`, height: '100%',
                              background: 'var(--accent)',
                              borderRadius: 2,
                            }} />
                          </div>
                          <span style={{ color: 'var(--text-muted)', fontSize: '0.72rem', width: 28 }}>
                            {pct}%
                          </span>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
