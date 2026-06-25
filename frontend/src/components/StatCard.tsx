import { type ReactNode } from 'react';

interface StatCardProps {
  label: string;
  value: number | string;
  sub?: string;
  variant?: 'accent' | 'danger' | 'warn' | 'success' | 'info';
  icon?: ReactNode;
  suffix?: string;
}

export default function StatCard({
  label,
  value,
  sub,
  variant = 'accent',
  icon,
  suffix,
}: StatCardProps) {
  const display = typeof value === 'number' && !isNaN(value)
    ? value.toLocaleString()
    : value;

  return (
    <div className={`stat-card ${variant}`}>
      <div className="stat-card-label">
        {icon}
        {label}
      </div>
      <div className="stat-card-value">
        {display}
        {suffix && (
          <span style={{ fontSize: '1rem', fontWeight: 500, marginLeft: 4, opacity: 0.7 }}>
            {suffix}
          </span>
        )}
      </div>
      {sub && <div className="stat-card-sub">{sub}</div>}
    </div>
  );
}
