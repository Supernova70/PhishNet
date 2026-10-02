import type { AuthUser } from '../api/auth';

export type Permission = 'system.settings' | 'system.health' | 'users.manage';

export const PERMISSION_LABELS: Record<Permission, string> = {
  'system.settings': 'System Settings',
  'system.health': 'API Health',
  'users.manage': 'User Management',
};

export const ALL_PERMISSIONS: Permission[] = [
  'system.settings',
  'system.health',
  'users.manage',
];

/**
 * Does this user hold `permission`?
 *
 * Server resolves permissions live from the DB (/auth/me), never from the
 * JWT, so this reflects the latest grant as of the last /auth/me poll.
 * `role === 'admin'` is a safety net for pre-1.4 sessions that lack the
 * permissions field — the server still enforces every check authoritatively.
 */
export function can(user: AuthUser | null, permission: Permission): boolean {
  if (!user) return false;
  if (user.role === 'admin') return true;
  return user.permissions?.includes(permission) ?? false;
}
