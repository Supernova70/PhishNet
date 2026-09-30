import { useState, useEffect } from 'react';

import { RefreshCw, AlertTriangle, Clock } from 'lucide-react';
import { format } from 'date-fns';
import { fetchEmails } from '../../api/client';
import { AlertBell } from './AlertBell';

interface HeaderProps {
  title: string;
  breadcrumbs?: Array<{ label: string; to?: string }>;
  threatCount?: number;
  onEmailsFetched?: () => void;
  toast?: (title: string, msg?: string) => void;
  toastError?: (title: string, msg?: string) => void;
}

export function Header({
  title,
  breadcrumbs = [],
  threatCount = 0,
  onEmailsFetched,
  toast,
  toastError,
}: HeaderProps) {
  const [time, setTime] = useState(() => format(new Date(), 'HH:mm:ss'));
  const [fetching, setFetching] = useState(false);

  useEffect(() => {
    const id = setInterval(() => setTime(format(new Date(), 'HH:mm:ss')), 1000);
    return () => clearInterval(id);
  }, []);

  const handleFetch = async () => {
    if (fetching) return;
    setFetching(true);
    try {
      const result = await fetchEmails(20);
      const fetched = result.new_emails ?? 0;
      toast?.(`Fetched ${fetched} new email${fetched !== 1 ? 's' : ''}`, `${result.total_fetched} total processed`);
      onEmailsFetched?.();
    } catch (err: unknown) {
      const msg = err instanceof Error && err.message === 'BACKEND_OFFLINE'
        ? 'Backend is offline'
        : 'Failed to fetch emails';
      toastError?.(msg);
    } finally {
      setFetching(false);
    }
  };

  return (
    <header className="app-header no-print" style={{
      height: 56,
      background: 'var(--bg-panel)',
      borderBottom: '1px solid var(--border-default)',
      display: 'flex',
      alignItems: 'center',
      padding: '0 20px',
      gap: 16,
      position: 'relative',
      // Above <main>: page panels use transforms (framer-motion) which
      // create z-index:0 stacking contexts that would otherwise paint
      // over the header's dropdowns (alert bell).
      zIndex: 10,
      flexShrink: 0,
    }}>
      {/* Scanline animation — clipped to the header box by its own
          wrapper so the header itself can keep overflow: visible */}
      <div
        style={{
          position: 'absolute',
          inset: 0,
          overflow: 'hidden',
          pointerEvents: 'none',
          zIndex: 0,
        }}
      >
        <div
          className="animate-scanline"
          style={{
            position: 'absolute',
            top: 0,
            left: 0,
            width: 60,
            height: '100%',
            background: 'linear-gradient(90deg, transparent, rgba(59,130,246,0.06), transparent)',
          }}
        />
      </div>

      {/* Title + Breadcrumb */}
      <div style={{ flex: 1, zIndex: 1 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {breadcrumbs.map((crumb, i) => (
            <span key={i} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{crumb.label}</span>
              {i < breadcrumbs.length - 1 && <span style={{ color: 'var(--text-muted)', fontSize: '0.65rem' }}>/</span>}
            </span>
          ))}
        </div>
        <h1 style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1 }}>
          {title}
        </h1>
      </div>

      {/* Right Controls */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, zIndex: 1 }}>
        {/* Threat Counter */}
        {threatCount > 0 && (
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            background: 'var(--danger-subtle)',
            border: '1px solid var(--danger)',
            borderRadius: 6,
            padding: '4px 10px',
          }}>
            <AlertTriangle size={13} style={{ color: 'var(--danger)' }} />
            <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-danger)' }}>
              {threatCount} threat{threatCount !== 1 ? 's' : ''} detected
            </span>
          </div>
        )}

        {/* Alert feed bell */}
        <AlertBell />

        {/* Fetch Button */}
        <button className="btn-primary" onClick={handleFetch} disabled={fetching} style={{ fontSize: '0.8rem', padding: '6px 14px' }}>
          <RefreshCw
            size={14}
            style={{ animation: fetching ? 'spin 1s linear infinite' : 'none' }}
          />
          {fetching ? 'Fetching...' : 'Fetch Emails'}
        </button>

        {/* Clock */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 5, color: 'var(--text-muted)' }}>
          <Clock size={13} />
          <span className="font-mono" style={{ fontSize: '0.8rem' }}>{time}</span>
        </div>
      </div>
    </header>
  );
}
