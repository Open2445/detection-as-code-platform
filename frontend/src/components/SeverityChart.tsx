import {
  PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer
} from 'recharts';
import type { SeverityCount } from '../types';

interface SeverityChartProps {
  data: SeverityCount[];
}

const COLOURS: Record<string, string> = {
  critical:      '#ff3d6e',
  high:          '#ff7043',
  medium:        '#ffab00',
  low:           '#00e676',
  informational: '#64b5f6',
};

const RADIAN = Math.PI / 180;

function CustomLabel({ cx, cy, midAngle, innerRadius, outerRadius, percent }: any) {
  if (percent < 0.05) return null;
  const r = innerRadius + (outerRadius - innerRadius) * 0.5;
  const x = cx + r * Math.cos(-midAngle * RADIAN);
  const y = cy + r * Math.sin(-midAngle * RADIAN);
  return (
    <text x={x} y={y} fill="#fff" textAnchor="middle" dominantBaseline="central"
      style={{ fontSize: 11, fontWeight: 700 }}>
      {`${(percent * 100).toFixed(0)}%`}
    </text>
  );
}

export default function SeverityChart({ data }: SeverityChartProps) {
  if (!data || data.length === 0) {
    return (
      <div className="empty-state" style={{ padding: 32 }}>
        <div className="empty-state-sub">No alert data</div>
      </div>
    );
  }

  const chartData = data.map(d => ({
    name: d.severity.charAt(0).toUpperCase() + d.severity.slice(1),
    value: d.count,
    color: COLOURS[d.severity] || '#7a8ba8',
  }));

  return (
    <ResponsiveContainer width="100%" height={260}>
      <PieChart>
        <Pie
          data={chartData}
          cx="50%"
          cy="50%"
          innerRadius={65}
          outerRadius={100}
          paddingAngle={3}
          dataKey="value"
          labelLine={false}
          label={CustomLabel}
        >
          {chartData.map((entry, i) => (
            <Cell
              key={i}
              fill={entry.color}
              stroke="rgba(0,0,0,0.3)"
              strokeWidth={1}
            />
          ))}
        </Pie>
        <Tooltip
          contentStyle={{
            background: '#0e1829',
            border: '1px solid rgba(0,212,255,0.2)',
            borderRadius: 8,
            color: '#e4eeff',
            fontSize: 12,
          }}
          formatter={(val: number) => [val.toLocaleString(), 'Alerts']}
        />
        <Legend
          wrapperStyle={{ fontSize: 12, color: '#7a8ba8' }}
          formatter={(value) => (
            <span style={{ color: '#a0b0c8' }}>{value}</span>
          )}
        />
      </PieChart>
    </ResponsiveContainer>
  );
}
