import { useEffect, useState, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Loader2,
  CheckCircle,
  XCircle,
  RefreshCw,
  Clock,
  AlertTriangle,
  ScanLine,
} from 'lucide-react';
import { ScoreBadge, ClassificationBadge } from '../components/ui/Badge';
import { formatDistanceToNow } from 'date-fns';
import type { Scan } from '../types';
import { subscribeToGlobalScans, type GlobalScanUpdate } from '../hooks/useScanSse';

// ─── Elapsed Timer ─────────────────────────────────────────────────────────────
function ElapsedTimer({ startedAt }: { startedAt: string | null }) {
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    if (!startedAt) return;
    const start = new Date(startedAt).getTime();
    const tick = () => setElapsed(Math.floor((Date.now() - start) / 1000));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [startedAt]);

  const mins = Math.floor(elapsed / 60);
  const secs = elapsed % 60;
  return (
    <span className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
      {mins > 0 ? `${mins}m ` : ''}{secs}s
    </span>
  );
}

// ─── Running Scan Card ─────────────────────────────────────────────────────────
function RunningCard({ scan }: { scan: Scan }) {
  const isRunning = scan.status === 'running';
  const statusColor = isRunning ? '#3B82F6' : '#F59E0B';
  const statusLabel = isRunning ? 'RUNNING' : 'PENDING';
  const statusBg = isRunning ? 'rgba(59,130,246,0.1)' : 'rgba(245,158,11,0.1)';

  return (
    <motion.div
      layout
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 20 }}
      style={{
        background: 'var(--bg-card)',
        border: `1px solid ${statusColor}40`,
        borderRadius: 8,
        padding: '16px 20px',
        display: 'flex',
        alignItems: 'center',
        gap: 16,
      }}
    >
      <Loader2
        size={20}
        style={{ color: statusColor, flexShrink: 0, animation: 'spin 1s linear infinite' }}
      />
      <div style={{ flex: 1, minWidth: 0 }}>
        <p style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-primary)' }}>
          Scanning email #{scan.email_number ?? scan.email_id}…
        </p>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 4 }}>
          <span className="font-mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
            Scan ID #{scan.id}
          </span>
          <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>·</span>
          <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 4 }}>
            <Clock size={11} /> Running for <ElapsedTimer startedAt={scan.started_at} />
          </span>
        </div>
      </div>
      <span style={{
        fontSize: '0.65rem',
        fontWeight: 700,
        color: statusColor,
        background: statusBg,
        border: `1px solid ${statusColor}40`,
        padding: '3px 8px',
        borderRadius: 4,
        letterSpacing: '0.08em',
        flexShrink: 0,
      }}>
        {statusLabel}
      </span>
    </motion.div>
  );
}

// ─── Active Scans Page ─────────────────────────────────────────────────────────
export function ActiveScans() {
  const navigate = useNavigate();
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [secondsSince, setSecondsSince] = useState(0);
  const [retrying, setRetrying] = useState<number | null>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchScans = async () => {
    try {
      const r = await fetch('/api/scans?limit=50');
      const data = await r.json();
      setScans(data.scans ?? []);
      setLastUpdated(new Date());
      setSecondsSince(0);
    } catch {
      // Keep previous data on error
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
    intervalRef.current = setInterval(fetchScans, 5000);
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, []);

  // Real-time SSE subscription for instant scan updates
  const handleScanUpdate = useCallback((update: GlobalScanUpdate) => {
    setScans((prev) =>
      prev.map((s) =>
        s.id === update.scan_id
          ? { ...s, status: 'complete' as const, verdict: s.verdict ?? { id: 0, scan_id: s.id, final_score: update.final_score ?? 0, classification: (update.classification as 'safe' | 'suspicious' | 'dangerous') ?? 'safe', ai_score: 0, ai_label: null, url_score: 0, attachment_score: 0, breakdown: null, created_at: new Date().toISOString() } }
          : s
      )
    );
  }, []);

  useEffect(() => {
    const unsub = subscribeToGlobalScans(handleScanUpdate);
    return unsub;
  }, [handleScanUpdate]);

  // Count-up timer since last update
  useEffect(() => {
    if (!lastUpdated) return;
    const id = setInterval(() => setSecondsSince((s) => s + 1), 1000);
    return () => clearInterval(id);
  }, [lastUpdated]);

  const handleRetry = async (scan: Scan) => {
    setRetrying(scan.email_id);
    try {
      await fetch(`/api/scans/${scan.email_id}`, { method: 'POST' });
      await fetchScans();
    } catch {
      // ignore
    } finally {
      setRetrying(null);
    }
  };

  const runningScans = scans.filter((s) => s.status === 'running' || s.status === 'pending');
  const completedScans = scans.filter((s) => s.status === 'complete').slice(0, 10);
  const failedScans = scans.filter((s) => s.status === 'error').slice(0, 5);

  return (
    <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <h1 style={{ fontSize: '1.25rem', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
            Active Scans
          </h1>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: 4 }}>
            Live view of scan queue — auto-refreshes every 5 seconds
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Last updated: {secondsSince}s ago
          </span>
          <button className="btn-ghost" onClick={fetchScans} style={{ padding: '6px 10px' }}>
            <RefreshCw size={14} />
          </button>
        </div>
      </div>

      {/* Section 1: Running Now */}
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
          <ScanLine size={16} style={{ color: '#3B82F6' }} />
          <h2 style={{ fontSize: '0.875rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.08em', margin: 0 }}>
            Running Now
          </h2>
          {runningScans.length > 0 && (
            <span style={{
              background: '#3B82F620',
              color: '#60A5FA',
              fontSize: '0.65rem',
              fontWeight: 700,
              padding: '2px 8px',
              borderRadius: 10,
              border: '1px solid #3B82F640',
            }}>
              {runningScans.length}
            </span>
          )}
        </div>

        {loading ? (
          <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, padding: 24, textAlign: 'center' }}>
            <Loader2 size={20} style={{ color: 'var(--text-muted)', animation: 'spin 1s linear infinite', margin: '0 auto 8px' }} />
            <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>Loading scans…</p>
          </div>
        ) : runningScans.length === 0 ? (
          <div style={{
            background: 'var(--bg-card)',
            border: '1px solid var(--border-default)',
            borderRadius: 8,
            padding: '28px 24px',
            display: 'flex',
            alignItems: 'center',
            gap: 14,
          }}>
            <div style={{
              width: 8,
              height: 8,
              borderRadius: '50%',
              background: '#10B981',
              boxShadow: '0 0 0 3px #10B98130',
              animation: 'pulse 3s ease-in-out infinite',
              flexShrink: 0,
            }} />
            <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>
              No active scans — system is idle
            </p>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <AnimatePresence>
              {runningScans.map((scan) => (
                <RunningCard key={scan.id} scan={scan} />
              ))}
            </AnimatePresence>
          </div>
        )}
      </div>

      {/* Section 2: Completed Recently */}
      {completedScans.length > 0 && (
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
            <CheckCircle size={16} style={{ color: '#10B981' }} />
            <h2 style={{ fontSize: '0.875rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.08em', margin: 0 }}>
              Completed Recently
            </h2>
          </div>
          <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, overflow: 'hidden' }}>
            {completedScans.map((scan, i) => (
              <div
                key={scan.id}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 12,
                  padding: '10px 16px',
                  borderBottom: i < completedScans.length - 1 ? '1px solid var(--border-subtle)' : 'none',
                }}
              >
                <span className="font-mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)', minWidth: 64 }}>
                  #{scan.id}
                </span>
                {scan.verdict && (
                  <>
                    <ScoreBadge score={scan.verdict.final_score} size="sm" />
                    <ClassificationBadge classification={scan.verdict.classification} size="sm" />
                  </>
                )}
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', flex: 1 }}>
                  Email #{scan.email_number ?? scan.email_id}
                </span>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                  {scan.completed_at ? formatDistanceToNow(new Date(scan.completed_at), { addSuffix: true }) : '—'}
                </span>
                <button
                  onClick={() => navigate(`/scans/${scan.id}`)}
                  style={{
                    background: 'var(--primary-glow)',
                    border: '1px solid var(--primary)',
                    borderRadius: 4,
                    color: 'var(--primary)',
                    padding: '3px 10px',
                    fontSize: '0.7rem',
                    cursor: 'pointer',
                    fontWeight: 600,
                    flexShrink: 0,
                  }}
                >
                  View
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Section 3: Failed */}
      {failedScans.length > 0 && (
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
            <AlertTriangle size={16} style={{ color: '#EF4444' }} />
            <h2 style={{ fontSize: '0.875rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.08em', margin: 0 }}>
              Failed Scans
            </h2>
          </div>
          <div style={{ border: '1px solid rgba(239,68,68,0.3)', borderRadius: 8, overflow: 'hidden' }}>
            {failedScans.map((scan, i) => (
              <div
                key={scan.id}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 12,
                  padding: '10px 16px',
                  background: 'rgba(239,68,68,0.05)',
                  borderBottom: i < failedScans.length - 1 ? '1px solid rgba(239,68,68,0.15)' : 'none',
                }}
              >
                <XCircle size={14} style={{ color: '#EF4444', flexShrink: 0 }} />
                <span className="font-mono" style={{ fontSize: '0.75rem', color: '#FCA5A5' }}>
                  Scan #{scan.id} failed
                </span>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', flex: 1 }}>
                  Email #{scan.email_number ?? scan.email_id}
                </span>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                  {scan.completed_at ? formatDistanceToNow(new Date(scan.completed_at), { addSuffix: true }) : '—'}
                </span>
                <button
                  onClick={() => handleRetry(scan)}
                  disabled={retrying === scan.email_id}
                  style={{
                    background: 'rgba(239,68,68,0.1)',
                    border: '1px solid rgba(239,68,68,0.4)',
                    borderRadius: 4,
                    color: '#FCA5A5',
                    padding: '3px 10px',
                    fontSize: '0.7rem',
                    cursor: retrying === scan.email_id ? 'not-allowed' : 'pointer',
                    fontWeight: 600,
                    flexShrink: 0,
                    display: 'flex',
                    alignItems: 'center',
                    gap: 4,
                  }}
                >
                  {retrying === scan.email_id
                    ? <><Loader2 size={11} style={{ animation: 'spin 1s linear infinite' }} /> Retrying</>
                    : 'Retry'
                  }
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Empty state if no scans at all */}
      {!loading && scans.length === 0 && (
        <div style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          padding: 64,
          gap: 12,
          color: 'var(--text-muted)',
        }}>
          <ScanLine size={40} />
          <p style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-secondary)' }}>No scans yet</p>
          <p style={{ fontSize: '0.875rem' }}>Run scans on emails from the Email Inbox</p>
          <button
            className="btn-ghost"
            onClick={() => navigate('/emails')}
            style={{ marginTop: 8, fontSize: '0.875rem', padding: '8px 20px' }}
          >
            Go to Email Inbox
          </button>
        </div>
      )}
    </div>
  );
}
