import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer
} from 'recharts';
import type { TimelinePoint } from '../types';
import { format, parseISO } from 'date-fns';

interface TimelineChartProps {
  data: TimelinePoint[];
}

export default function TimelineChart({ data }: TimelineChartProps) {
  if (!data || data.length === 0) {
    return (
      <div className="empty-state" style={{ padding: 32 }}>
        <div className="empty-state-sub">No timeline data yet</div>
      </div>
    );
  }

  const chartData = data.map(p => ({
    ...p,
    label: format(parseISO(p.date), 'MMM d'),
  }));

  return (
    <ResponsiveContainer width="100%" height={220}>
      <AreaChart data={chartData} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
        <defs>
          <linearGradient id="alertGradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%"   stopColor="#00d4ff" stopOpacity={0.3} />
            <stop offset="100%" stopColor="#00d4ff" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid
          strokeDasharray="3 3"
          stroke="rgba(0,212,255,0.08)"
          vertical={false}
        />
        <XAxis
          dataKey="label"
          tick={{ fill: '#4a5a70', fontSize: 11 }}
          axisLine={false}
          tickLine={false}
        />
        <YAxis
          tick={{ fill: '#4a5a70', fontSize: 11 }}
          axisLine={false}
          tickLine={false}
          allowDecimals={false}
        />
        <Tooltip
          contentStyle={{
            background: '#0e1829',
            border: '1px solid rgba(0,212,255,0.2)',
            borderRadius: 8,
            color: '#e4eeff',
            fontSize: 12,
          }}
          labelStyle={{ color: '#00d4ff', fontWeight: 600 }}
          formatter={(val: number) => [val.toLocaleString(), 'Alerts']}
        />
        <Area
          type="monotone"
          dataKey="count"
          stroke="#00d4ff"
          strokeWidth={2}
          fill="url(#alertGradient)"
          dot={false}
          activeDot={{ r: 4, fill: '#00d4ff', stroke: '#060b14', strokeWidth: 2 }}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}
