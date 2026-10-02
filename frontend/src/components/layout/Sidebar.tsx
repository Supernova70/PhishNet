import { NavLink, useLocation } from 'react-router-dom';

import {
  Shield,
  LayoutDashboard,
  Inbox,
  ScanLine,
  ShieldCheck,
  Link2,
  Paperclip,
  Settings,
  Activity,
  Share2,
  Megaphone,
  Bell,
  Users,
} from 'lucide-react';
import { StatusDot } from '../ui/Badge';
import type { HealthResponse } from '../../hooks/useSystemHealth';
import { useAuth } from '../../auth/AuthContext';
import { can } from '../../auth/permissions';

interface NavItem {
  to: string;
  icon: React.ReactNode;
  label: string;
  badge?: number | string | null;
  badgeType?: 'count' | 'dot';
  dotStatus?: 'online' | 'offline' | 'warning';
}

interface NavSectionProps {
  title: string;
  items: NavItem[];
  currentPath: string;
}

function NavSection({ title, items, currentPath }: NavSectionProps) {
  return (
    <div style={{ marginBottom: 24 }}>
      <p style={{
        fontSize: '0.6rem',
        fontWeight: 700,
        letterSpacing: '0.12em',
        color: 'var(--text-muted)',
        textTransform: 'uppercase',
        padding: '0 12px',
        marginBottom: 4,
      }}>
        {title}
      </p>
      {items.map((item) => {
        const isActive = currentPath === item.to || (item.to !== '/' && currentPath.startsWith(item.to));
        return (
          <NavLink
            key={item.to}
            to={item.to}
            style={{ textDecoration: 'none' }}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                padding: '8px 12px',
                margin: '1px 8px',
                borderRadius: 6,
                cursor: 'pointer',
                position: 'relative',
                background: isActive ? 'var(--primary-glow)' : 'transparent',
                borderLeft: isActive ? '2px solid var(--primary)' : '2px solid transparent',
                transition: 'all 200ms ease',
                color: isActive ? 'var(--text-primary)' : 'var(--text-muted)',
              }}
              onMouseEnter={(e) => {
                if (!isActive) {
                  (e.currentTarget as HTMLDivElement).style.background = 'var(--bg-input)';
                  (e.currentTarget as HTMLDivElement).style.color = 'var(--text-secondary)';
                }
              }}
              onMouseLeave={(e) => {
                if (!isActive) {
                  (e.currentTarget as HTMLDivElement).style.background = 'transparent';
                  (e.currentTarget as HTMLDivElement).style.color = 'var(--text-muted)';
                }
              }}
            >
              <span style={{ flexShrink: 0, display: 'flex', alignItems: 'center', color: isActive ? 'var(--primary)' : 'inherit' }}>
                {item.icon}
              </span>
              <span style={{ fontSize: '0.875rem', fontWeight: isActive ? 600 : 400, flex: 1 }}>
                {item.label}
              </span>
              {item.badge != null && item.badgeType === 'count' && (
                <span style={{
                  background: 'var(--danger)',
                  color: 'white',
                  fontSize: '0.65rem',
                  fontWeight: 700,
                  padding: '1px 6px',
                  borderRadius: 10,
                  minWidth: 18,
                  textAlign: 'center',
                }}>
                  {item.badge}
                </span>
              )}
              {item.badgeType === 'dot' && item.dotStatus && (
                <StatusDot status={item.dotStatus} pulse />
              )}
            </div>
          </NavLink>
        );
      })}
    </div>
  );
}

interface SidebarProps {
  unreadCount?: number;
  runningScans?: number;
  apiStatus?: 'online' | 'offline' | 'warning';
  health?: HealthResponse | null;
}

export function Sidebar({ unreadCount = 0, runningScans = 0, apiStatus = 'online', health = null }: SidebarProps) {
  const location = useLocation();
  const { user } = useAuth();

  const monitorItems: NavItem[] = [
    { to: '/', icon: <LayoutDashboard size={16} />, label: 'Dashboard' },
    { to: '/emails', icon: <Inbox size={16} />, label: 'Email Inbox', badge: unreadCount || null, badgeType: 'count' },
    { to: '/active-scans', icon: <ScanLine size={16} />, label: 'Active Scans', badge: runningScans || null, badgeType: 'count' },
    { to: '/alerts', icon: <Bell size={16} />, label: 'Alerts' },
  ];

  const analyzeItems: NavItem[] = [
    { to: '/scans', icon: <ShieldCheck size={16} />, label: 'Scan Results' },
    { to: '/graph', icon: <Share2 size={16} />, label: 'Attribution Graph' },
    { to: '/campaigns', icon: <Megaphone size={16} />, label: 'Campaigns' },
    { to: '/url-analysis', icon: <Link2 size={16} />, label: 'URL Analysis' },
    { to: '/attachments', icon: <Paperclip size={16} />, label: 'Attachments' },
  ];

  // System section is RBAC-gated: each item appears only with its grant,
  // the section disappears entirely for users with no system capability.
  const systemItems: NavItem[] = [
    ...(can(user, 'system.settings')
      ? [{ to: '/settings', icon: <Settings size={16} />, label: 'Settings' }]
      : []),
    ...(can(user, 'system.health')
      ? [{ to: '/system-health', icon: <Activity size={16} />, label: 'API Health', badgeType: 'dot' as const, dotStatus: apiStatus }]
      : []),
    ...(can(user, 'users.manage')
      ? [{ to: '/users', icon: <Users size={16} />, label: 'User Management' }]
      : []),
  ];

  const showStatusPanel = can(user, 'system.health');

  // Derive component statuses from health hook
  const dbStatus = health?.components?.database?.status === 'connected' ? 'online' : health ? 'offline' : 'warning' as const;
  const mlStatus = health?.components?.ml_model?.status === 'loaded' ? 'online' : 'warning' as const;

  const statusItems = [
    {
      label: 'DB',
      dot: dbStatus,
      text: health?.components?.database?.status === 'connected' ? 'Connected' : health ? 'Error' : 'Unknown',
      textColor: health?.components?.database?.status === 'connected' ? 'var(--text-safe)' : 'var(--text-muted)',
    },
    {
      label: 'ML Model',
      dot: mlStatus,
      text: health?.components?.ml_model?.status === 'loaded' ? 'Loaded' : health ? 'Not Loaded' : 'Unknown',
      textColor: health?.components?.ml_model?.status === 'loaded' ? 'var(--text-safe)' : 'var(--text-muted)',
    },
  ];

  return (
    <aside className="app-sidebar no-print" style={{
      width: 240,
      minWidth: 240,
      height: '100vh',
      background: 'var(--bg-panel)',
      borderRight: '1px solid var(--border-default)',
      display: 'flex',
      flexDirection: 'column',
      overflow: 'hidden',
    }}>
      {/* Logo */}
      <div style={{
        padding: '20px 16px 16px',
        borderBottom: '1px solid var(--border-subtle)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{
            width: 32,
            height: 32,
            background: 'var(--primary-glow)',
            border: '1px solid var(--primary)',
            borderRadius: 8,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}>
            <Shield size={18} style={{ color: 'var(--primary)' }} />
          </div>
          <div>
            <p style={{ fontSize: '0.8rem', fontWeight: 700, letterSpacing: '0.1em', color: 'var(--primary)' }}>
              PHISHING-GUARD
            </p>
            <span style={{
              fontSize: '0.6rem',
              fontFamily: 'JetBrains Mono, monospace',
              color: 'var(--text-muted)',
              background: 'var(--bg-input)',
              padding: '1px 5px',
              borderRadius: 3,
            }}>
              2.0
            </span>
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav style={{ flex: 1, padding: '16px 0', overflowY: 'auto' }}>
        <NavSection title="Monitor" items={monitorItems} currentPath={location.pathname} />
        <NavSection title="Analyze" items={analyzeItems} currentPath={location.pathname} />
        {systemItems.length > 0 && (
          <NavSection title="System" items={systemItems} currentPath={location.pathname} />
        )}
      </nav>

      {/* System Status Panel — DB and ML Model only (Redis removed).
          RBAC: component detail is system.health data — hidden without it. */}
      {showStatusPanel && (
      <div style={{
        padding: '12px 16px',
        borderTop: '1px solid var(--border-subtle)',
        background: 'var(--bg-page)',
      }}>
        <p style={{ fontSize: '0.65rem', fontWeight: 700, letterSpacing: '0.1em', color: 'var(--text-muted)', marginBottom: 8, textTransform: 'uppercase' }}>
          System Status
        </p>
        {statusItems.map((item) => (
          <div key={item.label} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{item.label}</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              <StatusDot status={item.dot as 'online' | 'offline' | 'warning'} pulse={false} />
              <span style={{ fontSize: '0.7rem', color: item.textColor }}>{item.text}</span>
            </div>
          </div>
        ))}
        <p style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginTop: 8, fontFamily: 'JetBrains Mono, monospace' }}>
          build 2026.04
        </p>
      </div>
      )}
    </aside>
  );
}
