import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard, Upload, Shield, Bell, Map,
  Zap
} from 'lucide-react';

const navItems = [
  { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/logs',      icon: Upload,          label: 'Logs' },
  { to: '/rules',     icon: Shield,          label: 'Rules' },
  { to: '/alerts',    icon: Bell,            label: 'Alerts' },
  { to: '/coverage',  icon: Map,             label: 'ATT&CK Coverage' },
];

export default function Sidebar() {
  return (
    <aside className="sidebar">
      {/* Logo */}
      <NavLink to="/dashboard" className="sidebar-logo" style={{ textDecoration: 'none' }}>
        <div className="sidebar-logo-icon">
          <Zap size={18} color="#000" strokeWidth={2.5} />
        </div>
        <div>
          <div className="sidebar-logo-text">Detection</div>
          <div className="sidebar-logo-sub">as Code Platform</div>
        </div>
      </NavLink>

      {/* Navigation */}
      <nav className="sidebar-nav">
        <div className="nav-section-label">Navigation</div>
        {navItems.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
          >
            <Icon className="nav-item-icon" size={18} />
            {label}
          </NavLink>
        ))}
      </nav>

      {/* Footer */}
      <div className="sidebar-footer">
        v1.0.0 &nbsp;·&nbsp; PySigma Engine
      </div>
    </aside>
  );
}
