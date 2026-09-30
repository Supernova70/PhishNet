import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Bell, BellOff, CheckCheck, AlertTriangle, ShieldAlert, Megaphone, ExternalLink } from 'lucide-react';
import { getAlerts, markAlertRead, markAllAlertsRead, type AlertItem } from '../api/forensics';
import { ScoreBadge, ClassificationBadge } from '../components/ui/Badge';
import { formatDistanceToNow } from 'date-fns';

const REASON_META: Record<string, { label: string; color: string; bg: string }> = {
  high_risk: { label: 'high risk score', color: 'var(--danger)', bg: 'var(--danger-subtle)' },
  spoof: { label: 'spoof / auth fail', color: 'var(--warning)', bg: 'var(--warning-subtle)' },
  bec: { label: 'BEC pattern', color: 'var(--danger)', bg: 'var(--danger-subtle)' },
};

function ReasonChips({ reasons }: { reasons: string[] }) {
  return (
    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
      {reasons.map((r) => {
        const meta = REASON_META[r] ?? { label: r, color: 'var(--text-muted)', bg: 'var(--bg-input)' };
        return (
          <span key={r} style={{ fontSize: '0.68rem', fontWeight: 700, padding: '2px 8px', borderRadius: 4, color: meta.color, background: meta.bg, border: `1px solid ${meta.color}` }}>
            {meta.label}
          </span>
        );
      })}
    </div>
  );
}

function AlertCard({ alert, onRead, onOpen }: { alert: AlertItem; onRead: () => void; onOpen: () => void }) {
  const icon = alert.reasons.includes('bec')
    ? <Megaphone size={16} />
    : alert.reasons.includes('spoof')
      ? <ShieldAlert size={16} />
      : <AlertTriangle size={16} />;
  const tone = alert.classification === 'dangerous' ? 'var(--danger)' : alert.classification === 'suspicious' ? 'var(--warning)' : 'var(--safe)';

  return (
    <div
      style={{
        background: alert.read ? 'var(--bg-card)' : 'var(--bg-input)',
        border: `1px solid ${alert.read ? 'var(--border-default)' : tone}`,
        borderLeft: `3px solid ${tone}`,
        borderRadius: 8,
        padding: '14px 18px',
        display: 'flex',
        gap: 14,
        alignItems: 'flex-start',
        opacity: alert.read ? 0.75 : 1,
      }}
    >
      <span style={{ color: tone, marginTop: 2 }}>{icon}</span>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <ScoreBadge score={alert.score} size="sm" />
          <ClassificationBadge classification={alert.classification} size="sm" />
          {!alert.read && (
            <span style={{ fontSize: '0.62rem', fontWeight: 800, color: 'var(--primary)', background: 'var(--primary-glow)', padding: '2px 8px', borderRadius: 4, letterSpacing: '0.06em' }}>
              NEW
            </span>
          )}
          <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
            {alert.created_at ? formatDistanceToNow(new Date(alert.created_at), { addSuffix: true }) : ''}
          </span>
        </div>
        <p style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)', marginTop: 8, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {alert.subject || '(no subject)'}
        </p>
        <p className="font-mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: 2 }}>
          {alert.sender}
        </p>
        <div style={{ marginTop: 8 }}>
          <ReasonChips reasons={alert.reasons} />
        </div>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6, flexShrink: 0 }}>
        <button
          onClick={onOpen}
          style={{ display: 'flex', alignItems: 'center', gap: 4, background: 'var(--primary-glow)', border: '1px solid var(--primary)', borderRadius: 4, color: 'var(--primary)', padding: '4px 10px', fontSize: '0.72rem', cursor: 'pointer', fontWeight: 600 }}
        >
          Open Scan <ExternalLink size={11} />
        </button>
        {!alert.read && (
          <button
            onClick={onRead}
            style={{ display: 'flex', alignItems: 'center', gap: 4, background: 'transparent', border: '1px solid var(--border-default)', borderRadius: 4, color: 'var(--text-muted)', padding: '4px 10px', fontSize: '0.72rem', cursor: 'pointer' }}
          >
            <BellOff size={11} /> Mark read
          </button>
        )}
      </div>
    </div>
  );
}

export function AlertsPage() {
  const navigate = useNavigate();
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [unread, setUnread] = useState(0);
  const [loading, setLoading] = useState(true);
  const [unreadOnly, setUnreadOnly] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async (onlyUnread: boolean) => {
    setLoading(true);
    try {
      setError(null);
      const data = await getAlerts(onlyUnread, 200);
      setAlerts(data.alerts);
      setUnread(data.unread);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load alerts');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    queueMicrotask(() => load(unreadOnly));
  }, [load, unreadOnly]);

  const handleRead = async (id: number) => {
    try {
      await markAlertRead(id);
      setAlerts((prev) => prev.map((a) => (a.id === id ? { ...a, read: true } : a)));
      setUnread((u) => Math.max(0, u - 1));
    } catch { /* stay optimistic */ }
  };

  const handleReadAll = async () => {
    try {
      await markAllAlertsRead();
      setAlerts((prev) => prev.map((a) => ({ ...a, read: true })));
      setUnread(0);
    } catch { /* ignore */ }
  };

  return (
    <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 16, maxWidth: 900 }}>
      {/* Toolbar */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Bell size={18} style={{ color: 'var(--primary)' }} />
          <div>
            <h2 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)' }}>Alert Feed</h2>
            <p style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
              {unread} unread of {alerts.length} shown — high-risk, spoof and BEC triggers
            </p>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            className="btn-ghost"
            onClick={() => setUnreadOnly((v) => !v)}
            style={{ fontSize: '0.75rem', padding: '6px 12px', borderColor: unreadOnly ? 'var(--primary)' : undefined, color: unreadOnly ? 'var(--primary)' : undefined }}
          >
            {unreadOnly ? 'Showing unread' : 'Unread only'}
          </button>
          <button className="btn-ghost" onClick={handleReadAll} disabled={unread === 0} style={{ fontSize: '0.75rem', padding: '6px 12px' }}>
            <CheckCheck size={12} /> Mark all read
          </button>
        </div>
      </div>

      {error && (
        <div style={{ padding: '10px 14px', background: 'var(--danger-subtle)', border: '1px solid var(--danger)', borderRadius: 6, fontSize: '0.78rem', color: 'var(--text-danger)' }}>
          {error}
        </div>
      )}

      {/* List */}
      {loading ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {[0, 1, 2].map((i) => <div key={i} className="skeleton" style={{ height: 120, borderRadius: 8 }} />)}
        </div>
      ) : alerts.length === 0 ? (
        <div style={{ padding: 48, textAlign: 'center', background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8 }}>
          <Bell size={36} style={{ color: 'var(--text-muted)', margin: '0 auto 10px' }} />
          <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
            {unreadOnly ? 'No unread alerts' : 'No alerts yet'}
          </p>
          <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: 4 }}>
            Alerts fire on high-risk verdicts, spoof/auth failures and BEC patterns.
          </p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {alerts.map((a) => (
            <AlertCard
              key={a.id}
              alert={a}
              onRead={() => handleRead(a.id)}
              onOpen={() => {
                if (!a.read) void handleRead(a.id);
                navigate(`/scans/${a.scan_id}`);
              }}
            />
          ))}
        </div>
      )}
    </div>
  );
}
