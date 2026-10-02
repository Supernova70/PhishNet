import { useCallback, useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import {
  Users,
  ShieldCheck,
  RefreshCw,
  AlertCircle,
  CheckCircle2,
  KeyRound,
} from 'lucide-react';
import { apiClient } from '../api/client';
import { useAuth } from '../auth/AuthContext';
import {
  ALL_PERMISSIONS,
  PERMISSION_LABELS,
  can,
  type Permission,
} from '../auth/permissions';

// ── Types ─────────────────────────────────────────────────

interface Member {
  id: number;
  email: string;
  name?: string | null;
  picture?: string | null;
  role: string;
  permissions: string[];
  grants: string[];
  gmail_connected: boolean;
  created_at?: string | null;
  last_login_at?: string | null;
}

interface UsersResponse {
  count: number;
  users: Member[];
  permission_catalog: Record<string, string>;
}

function apiDetail(err: unknown): string {
  const detail = (err as { response?: { data?: { detail?: string } } })
    ?.response?.data?.detail;
  return detail ?? (err instanceof Error ? err.message : 'Request failed');
}

function formatDate(iso?: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString();
}

// ── Toggle switch (same visual language as SettingsPage) ──

function Toggle({
  checked,
  disabled,
  onChange,
  title,
}: {
  checked: boolean;
  disabled?: boolean;
  onChange: () => void;
  title?: string;
}) {
  return (
    <label
      title={title}
      style={{
        position: 'relative',
        display: 'inline-block',
        width: 44,
        height: 24,
        cursor: disabled ? 'not-allowed' : 'pointer',
        opacity: disabled ? 0.55 : 1,
      }}
    >
      <input
        type="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={onChange}
        style={{ display: 'none' }}
      />
      <span
        style={{
          position: 'absolute',
          inset: 0,
          borderRadius: 12,
          background: checked ? 'var(--primary)' : 'var(--bg-input)',
          border: `1px solid ${checked ? 'var(--primary)' : 'var(--border-default)'}`,
          transition: 'all 200ms',
        }}
      />
      <span
        style={{
          position: 'absolute',
          top: 2,
          left: checked ? 22 : 2,
          width: 20,
          height: 20,
          borderRadius: '50%',
          background: 'white',
          transition: 'all 200ms',
          boxShadow: '0 1px 3px rgba(0,0,0,0.2)',
        }}
      />
    </label>
  );
}

// ── Users page ────────────────────────────────────────────

export function UsersPage() {
  const { user: viewer, refresh: refreshAuth } = useAuth();
  const [members, setMembers] = useState<Member[]>([]);
  const [loading, setLoading] = useState(true);
  const [savingId, setSavingId] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    apiClient
      .get<UsersResponse>('/users')
      .then(({ data }) => setMembers(data.users))
      .catch((err) => setError(apiDetail(err)))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const flash = (msg: string) => {
    setSuccess(msg);
    setTimeout(() => setSuccess(null), 3000);
  };

  const replaceMember = (updated: Member) =>
    setMembers((prev) => prev.map((m) => (m.id === updated.id ? updated : m)));

  const togglePermission = async (member: Member, perm: Permission) => {
    if (!viewer || !can(viewer, perm)) return;
    const next = member.grants.includes(perm)
      ? member.grants.filter((p) => p !== perm)
      : [...member.grants, perm];
    setSavingId(member.id);
    setError(null);
    try {
      const { data } = await apiClient.put<Member>(
        `/users/${member.id}/permissions`,
        { permissions: next }
      );
      replaceMember(data);
      flash(
        `${perm} ${next.includes(perm) ? 'granted to' : 'revoked from'} ${member.email}`
      );
    } catch (err) {
      setError(apiDetail(err));
    } finally {
      setSavingId(null);
    }
  };

  const changeRole = async (member: Member, role: string) => {
    if (!viewer || viewer.role !== 'admin') return;
    if (
      !window.confirm(
        `Change role of ${member.email} from "${member.role}" to "${role}"?`
      )
    )
      return;
    setSavingId(member.id);
    setError(null);
    try {
      const { data } = await apiClient.patch<Member>(
        `/users/${member.id}/role`,
        { role }
      );
      replaceMember(data);
      flash(`${member.email} is now ${role}`);
      if (data.id === viewer.id) await refreshAuth();
    } catch (err) {
      setError(apiDetail(err));
      load(); // role may have been blocked (self/ADMIN_EMAILS/last-admin)
    } finally {
      setSavingId(null);
    }
  };

  if (loading) {
    return (
      <div style={{ padding: 24 }}>
        <div className="skeleton" style={{ height: 32, width: 220, borderRadius: 4, marginBottom: 24 }} />
        <div className="skeleton" style={{ height: 260, borderRadius: 8 }} />
      </div>
    );
  }

  const thStyle = {
    textAlign: 'left' as const,
    padding: '10px 12px',
    fontSize: '0.68rem',
    fontWeight: 700,
    letterSpacing: '0.08em',
    textTransform: 'uppercase' as const,
    color: 'var(--text-muted)',
    borderBottom: '1px solid var(--border-default)',
  };
  const tdStyle = {
    padding: '12px',
    fontSize: '0.85rem',
    color: 'var(--text-primary)',
    borderBottom: '1px solid var(--border-subtle)',
    verticalAlign: 'middle' as const,
  };

  return (
    <div style={{ padding: 24, maxWidth: 1050, margin: '0 auto' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8 }}>
        <Users size={24} style={{ color: 'var(--primary)' }} />
        <h1 style={{ fontSize: '1.25rem', fontWeight: 800, color: 'var(--text-primary)' }}>
          User Management
        </h1>
        <button
          className="btn-ghost"
          onClick={load}
          title="Reload"
          style={{ padding: '6px 10px', marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 4 }}
        >
          <RefreshCw size={13} />
        </button>
      </div>
      <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: 20 }}>
        Grant system capabilities to accounts. You can only grant permissions you
        hold yourself; roles may be changed by administrators only.
      </p>

      {/* Status messages */}
      {success && (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          style={{
            padding: '10px 16px', borderRadius: 6, background: 'var(--safe-subtle)',
            border: '1px solid var(--safe)', color: 'var(--text-safe)',
            marginBottom: 16, display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.875rem',
          }}
        >
          <CheckCircle2 size={16} /> {success}
        </motion.div>
      )}
      {error && (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          style={{
            padding: '10px 16px', borderRadius: 6, background: 'var(--danger-subtle)',
            border: '1px solid var(--danger)', color: 'var(--text-danger)',
            marginBottom: 16, display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.875rem',
          }}
        >
          <AlertCircle size={16} /> {error}
        </motion.div>
      )}

      {/* Accounts table */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        style={{
          background: 'var(--bg-card)',
          border: '1px solid var(--border-default)',
          borderRadius: 8,
          overflow: 'hidden',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '16px 20px 12px' }}>
          <ShieldCheck size={18} style={{ color: 'var(--primary)' }} />
          <h2 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)' }}>
            Accounts ({members.length})
          </h2>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th style={thStyle}>Account</th>
                <th style={thStyle}>Role</th>
                <th style={thStyle}>Gmail</th>
                <th style={thStyle}>Last login</th>
                <th style={thStyle}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
                    <KeyRound size={11} /> Permissions
                  </span>
                </th>
              </tr>
            </thead>
            <tbody>
              {members.map((member) => {
                const isAdminRow = member.role === 'admin';
                const isSelf = viewer?.id === member.id;
                return (
                  <tr key={member.id}>
                    <td style={tdStyle}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                        {member.picture ? (
                          <img
                            src={member.picture}
                            alt=""
                            width={30}
                            height={30}
                            style={{ borderRadius: '50%', border: '1px solid var(--border-default)' }}
                          />
                        ) : (
                          <div
                            style={{
                              width: 30, height: 30, borderRadius: '50%',
                              background: 'var(--primary-glow)', color: 'var(--primary)',
                              display: 'flex', alignItems: 'center', justifyContent: 'center',
                              fontSize: '0.72rem', fontWeight: 700,
                              border: '1px solid var(--primary)',
                            }}
                          >
                            {(member.name || member.email)[0]?.toUpperCase()}
                          </div>
                        )}
                        <div>
                          <p style={{ fontSize: '0.85rem', fontWeight: 600, margin: 0 }}>
                            {member.name || '—'}
                            {isSelf && (
                              <span style={{ color: 'var(--text-muted)', fontWeight: 400 }}> (you)</span>
                            )}
                          </p>
                          <p style={{ fontSize: '0.72rem', color: 'var(--text-muted)', margin: 0 }}>
                            {member.email}
                          </p>
                        </div>
                      </div>
                    </td>

                    <td style={tdStyle}>
                      {viewer?.role === 'admin' ? (
                        <select
                          className="dark-input"
                          value={member.role}
                          disabled={savingId === member.id || isSelf}
                          title={isSelf ? 'Cannot change your own role' : undefined}
                          onChange={(e) => changeRole(member, e.target.value)}
                          style={{ fontSize: '0.78rem', padding: '5px 8px' }}
                        >
                          <option value="admin">admin</option>
                          <option value="user">user</option>
                        </select>
                      ) : (
                        <span
                          className="font-mono"
                          style={{
                            fontSize: '0.7rem', fontWeight: 700, padding: '3px 8px',
                            borderRadius: 4,
                            background: isAdminRow ? 'var(--primary-glow)' : 'var(--bg-input)',
                            color: isAdminRow ? 'var(--primary)' : 'var(--text-muted)',
                            border: `1px solid ${isAdminRow ? 'var(--primary)' : 'var(--border-default)'}`,
                          }}
                        >
                          {member.role}
                        </span>
                      )}
                    </td>

                    <td style={tdStyle}>
                      <span
                        style={{
                          fontSize: '0.72rem',
                          color: member.gmail_connected ? 'var(--text-safe)' : 'var(--text-muted)',
                          display: 'inline-flex', alignItems: 'center', gap: 5,
                        }}
                      >
                        <span
                          style={{
                            width: 7, height: 7, borderRadius: '50%',
                            background: member.gmail_connected ? 'var(--safe)' : 'var(--text-muted)',
                          }}
                        />
                        {member.gmail_connected ? 'Connected' : 'Not connected'}
                      </span>
                    </td>

                    <td style={{ ...tdStyle, fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      {formatDate(member.last_login_at)}
                    </td>

                    <td style={tdStyle}>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                        {ALL_PERMISSIONS.map((perm) => {
                          const heldViaRole = isAdminRow;
                          const held = heldViaRole || member.grants.includes(perm);
                          const viewerHolds = can(viewer, perm);
                          const selfLockout =
                            isSelf && perm === 'users.manage' && viewer?.role !== 'admin';
                          const disabled =
                            heldViaRole || !viewerHolds || selfLockout ||
                            savingId === member.id;
                          const title = heldViaRole
                            ? 'Held implicitly via the admin role'
                            : !viewerHolds
                              ? `You do not hold ${perm} — cannot grant it`
                              : selfLockout
                                ? 'Removing your own user-management access is blocked'
                                : undefined;
                          return (
                            <div
                              key={perm}
                              style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}
                            >
                              <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                                {PERMISSION_LABELS[perm]}
                                <span
                                  className="font-mono"
                                  style={{ color: 'var(--text-muted)', fontSize: '0.62rem', marginLeft: 6 }}
                                >
                                  {perm}
                                </span>
                              </span>
                              <Toggle
                                checked={held}
                                disabled={disabled}
                                title={title}
                                onChange={() => togglePermission(member, perm)}
                              />
                            </div>
                          );
                        })}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        <div style={{ padding: '10px 20px', fontSize: '0.7rem', color: 'var(--text-muted)' }}>
          Grants take effect immediately — no re-login required. Every grant,
          revoke, and role change is recorded in the audit log.
        </div>
      </motion.div>
    </div>
  );
}
