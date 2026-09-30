import { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Bell, CheckCheck } from 'lucide-react';
import { getAlerts, markAlertRead, markAllAlertsRead, type AlertItem } from '../../api/forensics';

// Header bell: polls the alert feed, dropdown of the 6 newest, mark-read inline.
export function AlertBell() {
  const navigate = useNavigate();
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [unread, setUnread] = useState(0);
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);

  const refresh = useCallback(async () => {
    try {
      const data = await getAlerts(false, 6);
      setAlerts(data.alerts);
      setUnread(data.unread);
    } catch { /* offline — bell just stays quiet */ }
  }, []);

  useEffect(() => {
    queueMicrotask(() => refresh());
    const id = setInterval(refresh, 30000);
    return () => clearInterval(id);
  }, [refresh]);

  // Close on outside click
  useEffect(() => {
    if (!open) return;
    const onClick = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onClick);
    return () => document.removeEventListener('mousedown', onClick);
  }, [open]);

  const handleRead = async (id: number) => {
    try {
      await markAlertRead(id);
      setAlerts((prev) => prev.map((a) => (a.id === id ? { ...a, read: true } : a)));
      setUnread((u) => Math.max(0, u - 1));
    } catch { /* ignore */ }
  };

  const handleReadAll = async () => {
    try {
      await markAllAlertsRead();
      setAlerts((prev) => prev.map((a) => ({ ...a, read: true })));
      setUnread(0);
    } catch { /* ignore */ }
  };

  const openAlert = (a: AlertItem) => {
    if (!a.read) void handleRead(a.id);
    setOpen(false);
    navigate(`/scans/${a.scan_id}`);
  };

  return (
    <div ref={rootRef} style={{ position: 'relative' }}>
      <button
        onClick={() => setOpen((v) => !v)}
        aria-label={unread > 0 ? `${unread} unread alerts` : 'Alerts'}
        style={{
          position: 'relative',
          background: 'transparent',
          border: '1px solid var(--border-default)',
          borderRadius: 6,
          padding: '6px 8px',
          cursor: 'pointer',
          color: unread > 0 ? 'var(--warning)' : 'var(--text-muted)',
          display: 'flex',
          alignItems: 'center',
        }}
      >
        <Bell size={15} />
        {unread > 0 && (
          <span
            style={{
              position: 'absolute',
              top: -6,
              right: -6,
              minWidth: 16,
              height: 16,
              padding: '0 4px',
              borderRadius: 8,
              background: 'var(--danger)',
              color: 'white',
              fontSize: '0.6rem',
              fontWeight: 800,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            {unread > 9 ? '9+' : unread}
          </span>
        )}
      </button>

      {open && (
        <div
          style={{
            position: 'absolute',
            top: 'calc(100% + 8px)',
            right: 0,
            width: 340,
            background: 'var(--bg-panel)',
            border: '1px solid var(--border-default)',
            borderRadius: 8,
            boxShadow: '0 12px 40px rgba(0,0,0,0.5)',
            zIndex: 100,
            overflow: 'hidden',
          }}
        >
          <div style={{ padding: '10px 14px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-primary)' }}>
              Alerts {unread > 0 ? `(${unread} unread)` : ''}
            </span>
            <button
              onClick={handleReadAll}
              disabled={unread === 0}
              style={{ background: 'transparent', border: 'none', color: unread > 0 ? 'var(--primary)' : 'var(--text-muted)', fontSize: '0.68rem', cursor: unread > 0 ? 'pointer' : 'default', display: 'flex', alignItems: 'center', gap: 4, opacity: unread > 0 ? 1 : 0.5 }}
            >
              <CheckCheck size={11} /> read all
            </button>
          </div>

          {alerts.length === 0 ? (
            <p style={{ padding: '18px 14px', fontSize: '0.75rem', color: 'var(--text-muted)', textAlign: 'center' }}>
              No alerts — quiet is good.
            </p>
          ) : (
            <div style={{ maxHeight: 320, overflowY: 'auto' }}>
              {alerts.map((a) => (
                <div
                  key={a.id}
                  onClick={() => openAlert(a)}
                  style={{
                    padding: '10px 14px',
                    borderBottom: '1px solid var(--border-subtle)',
                    cursor: 'pointer',
                    background: a.read ? 'transparent' : 'var(--primary-glow)',
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--bg-input)')}
                  onMouseLeave={(e) => (e.currentTarget.style.background = a.read ? 'transparent' : 'var(--primary-glow)')}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span className="font-mono" style={{ fontSize: '0.7rem', fontWeight: 700, color: a.classification === 'dangerous' ? 'var(--danger)' : 'var(--warning)' }}>
                      {a.score.toFixed(0)}
                    </span>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-primary)', fontWeight: 600, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {a.subject || '(no subject)'}
                    </span>
                    {!a.read && <span style={{ width: 7, height: 7, borderRadius: '50%', background: 'var(--primary)', flexShrink: 0 }} />}
                  </div>
                  <p style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginTop: 3 }}>
                    {a.reasons.join(' · ')}
                  </p>
                </div>
              ))}
            </div>
          )}

          <div style={{ padding: '8px 14px', borderTop: '1px solid var(--border-subtle)', textAlign: 'center' }}>
            <button
              onClick={() => { setOpen(false); navigate('/alerts'); }}
              style={{ background: 'transparent', border: 'none', color: 'var(--primary)', fontSize: '0.72rem', fontWeight: 600, cursor: 'pointer' }}
            >
              View all alerts →
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
