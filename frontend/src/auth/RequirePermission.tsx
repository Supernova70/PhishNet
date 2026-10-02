import type { ReactNode } from 'react';
import { Navigate } from 'react-router-dom';
import { ShieldAlert } from 'lucide-react';
import { useAuth } from './AuthContext';
import { can, PERMISSION_LABELS, type Permission } from './permissions';

/**
 * Client-side route gate for RBAC-protected pages.
 *
 * The server is authoritative (403 on every API call) — this only avoids
 * rendering pages the signed-in user cannot use and keeps the sidebar and
 * direct-URL navigation consistent. Missing permission → redirect home.
 */
export function RequirePermission({
  permission,
  children,
}: {
  permission: Permission;
  children: ReactNode;
}) {
  const { user, loading } = useAuth();

  if (loading) return null;
  if (!user) return <Navigate to="/login" replace />;
  if (!can(user, permission)) {
    return (
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          gap: 12,
          height: '100%',
          color: 'var(--text-muted)',
        }}
      >
        <ShieldAlert size={34} style={{ color: 'var(--warning)' }} />
        <p style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)' }}>
          Access denied
        </p>
        <p style={{ fontSize: '0.8rem' }}>
          {PERMISSION_LABELS[permission]} requires the{' '}
          <span className="font-mono">{permission}</span> permission — ask an
          administrator to grant it from User Management.
        </p>
      </div>
    );
  }
  return <>{children}</>;
}
