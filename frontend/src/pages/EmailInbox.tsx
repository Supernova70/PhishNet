import { useEffect, useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Search,
  Paperclip,
  AlertCircle,
  ShieldCheck,
  ScanSearch,
  CheckCircle,
  XCircle,
  RefreshCw,
  FileText,
  Code,
  File,
} from 'lucide-react';
import { getEmails, getEmail, fetchEmails, bulkScan } from '../api/client';
import { usePollScan } from '../hooks/usePollScan';

import { LoadingDots } from '../components/ui/LoadingDots';
import { formatDistanceToNow, format } from 'date-fns';
import type { Email, EmailDetail, Attachment } from '../types';

type FilterType = 'all' | 'has_attachments' | 'scanned' | 'unscanned';

// ─── Sender Avatar ─────────────────────────────────────────────────────────────
function SenderAvatar({ sender }: { sender: string }) {
  const domain = sender.includes('@') ? sender.split('@')[1] : sender;
  const letter = domain ? domain[0].toUpperCase() : '?';
  const hue = domain ? domain.charCodeAt(0) * 37 % 360 : 200;
  return (
    <div style={{
      width: 36,
      height: 36,
      borderRadius: '50%',
      background: `hsl(${hue}, 50%, 25%)`,
      border: `1px solid hsl(${hue}, 50%, 35%)`,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      fontSize: '0.875rem',
      fontWeight: 700,
      color: `hsl(${hue}, 70%, 75%)`,
      flexShrink: 0,
    }}>
      {letter}
    </div>
  );
}

// ─── Scan Status Chip ──────────────────────────────────────────────────────────
const CHIP_STYLES: Record<string, { label: string; bg: string; color: string; border: string }> = {
  unscanned: { label: 'Unscanned', bg: 'transparent', color: 'var(--text-muted)', border: 'var(--border-default)' },
  pending: { label: 'Queued', bg: 'rgba(56,189,248,0.10)', color: '#7DD3FC', border: 'rgba(56,189,248,0.45)' },
  running: { label: 'Scanning…', bg: 'rgba(56,189,248,0.10)', color: '#7DD3FC', border: 'rgba(56,189,248,0.45)' },
  error: { label: 'Scan failed', bg: 'rgba(239,68,68,0.10)', color: '#FCA5A5', border: 'rgba(239,68,68,0.45)' },
  safe: { label: 'Safe', bg: 'rgba(16,185,129,0.12)', color: '#6EE7B7', border: 'rgba(16,185,129,0.5)' },
  suspicious: { label: 'Suspicious', bg: 'rgba(245,158,11,0.12)', color: '#FCD34D', border: 'rgba(245,158,11,0.5)' },
  dangerous: { label: 'Dangerous', bg: 'rgba(239,68,68,0.12)', color: '#FCA5A5', border: 'rgba(239,68,68,0.5)' },
  scanned: { label: 'Scanned', bg: 'rgba(16,185,129,0.12)', color: '#6EE7B7', border: 'rgba(16,185,129,0.5)' },
};

function ScanStatusChip({ email }: { email: Email }) {
  let key: string;
  if (email.scan_count === 0) key = 'unscanned';
  else if (email.latest_scan_status === 'pending') key = 'pending';
  else if (email.latest_scan_status === 'running') key = 'running';
  else if (email.latest_scan_status === 'error') key = 'error';
  else if (email.latest_scan_status === 'complete' && email.latest_scan_classification)
    key = email.latest_scan_classification;
  else if (email.latest_scan_status === 'complete') key = 'scanned';
  else key = 'unscanned';

  const cfg = CHIP_STYLES[key];
  return (
    <span
      title={
        key === 'unscanned'
          ? 'Not scanned yet — open it and run a scan'
          : key === 'running' || key === 'pending'
            ? 'Scan queued / running in the background'
            : key === 'error'
              ? 'Last scan failed'
              : `Scanned — ${cfg.label}`
      }
      style={{
        flexShrink: 0,
        fontSize: '0.58rem',
        fontWeight: 700,
        padding: '1px 7px',
        borderRadius: 9,
        textTransform: 'uppercase' as const,
        letterSpacing: '0.05em',
        whiteSpace: 'nowrap',
        background: cfg.bg,
        color: cfg.color,
        border: `1px solid ${cfg.border}`,
      }}
    >
      {cfg.label}
    </span>
  );
}

// ─── File Type Icon ─────────────────────────────────────────────────────────────
function FileTypeIcon({ filename }: { filename: string; contentType: string | null }) {
  const ext = filename.split('.').pop()?.toLowerCase() ?? '';
  if (['pdf'].includes(ext)) return <FileText size={18} style={{ color: '#EF4444' }} />;
  if (['exe', 'dll', 'bat', 'ps1'].includes(ext)) return <Code size={18} style={{ color: '#F59E0B' }} />;
  if (['doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'].includes(ext)) return <FileText size={18} style={{ color: '#3B82F6' }} />;
  return <File size={18} style={{ color: 'var(--text-muted)' }} />;
}

// ─── Attachment Card ────────────────────────────────────────────────────────────
function AttachmentCard({ att }: { att: Attachment }) {
  const [copied, setCopied] = useState(false);
  const sizeStr = att.size_bytes > 1024 * 1024
    ? `${(att.size_bytes / 1024 / 1024).toFixed(1)} MB`
    : `${Math.round(att.size_bytes / 1024)} KB`;

  return (
    <div style={{
      background: 'var(--bg-input)',
      border: '1px solid var(--border-default)',
      borderRadius: 8,
      padding: 12,
      display: 'flex',
      gap: 12,
      alignItems: 'flex-start',
    }}>
      <div style={{ flexShrink: 0, marginTop: 2 }}>
        <FileTypeIcon filename={att.filename} contentType={att.content_type} />
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <p style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-primary)', wordBreak: 'break-all' }}>
          {att.filename}
        </p>
        <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 2 }}>
          {att.content_type ?? 'Unknown type'} · {sizeStr}
        </p>
        {att.sha256_hash && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 6 }}>
            <span className="font-mono" style={{ fontSize: '0.65rem', color: 'var(--text-muted)', wordBreak: 'break-all' }}>
              SHA256: {att.sha256_hash.slice(0, 32)}…
            </span>
            <button
              onClick={() => { navigator.clipboard.writeText(att.sha256_hash!); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
              style={{ background: 'none', border: 'none', cursor: 'pointer', color: copied ? 'var(--safe)' : 'var(--text-muted)', padding: 2, fontSize: '0.65rem' }}
            >
              {copied ? '✓' : '⧉'}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Scan Button ────────────────────────────────────────────────────────────────
type ScanState = 'idle' | 'scanning' | 'complete' | 'failed';

function RunScanButton({ emailId, alreadyScanned, onComplete }: { emailId: number; alreadyScanned: boolean; onComplete: () => void }) {
  const navigate = useNavigate();
  const [state, setState] = useState<ScanState>(alreadyScanned ? 'complete' : 'idle');
  const [scanError, setScanError] = useState<string>('');
  const [scanId, setScanId] = useState<number | null>(null);
  const [verdict, setVerdict] = useState<{ final_score: number; classification: string; ai_score?: number; url_score?: number; attachment_score?: number } | null>(null);
  const { scan: polledScan, error: pollError, startPolling } = usePollScan();

  useEffect(() => {
    if (!alreadyScanned) return;
    queueMicrotask(() => setState('complete'));
    // Resolve the latest finished scan so "View Analysis" can navigate to it.
    let cancelled = false;
    fetch(`/api/emails/${emailId}/latest-scan`)
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        const scan = data && !data.scan ? data : data?.scan;
        if (!cancelled && scan && typeof scan.id === 'number' && scan.status === 'complete') {
          setScanId(scan.id);
          if (scan.verdict) setVerdict(scan.verdict);
        }
      })
      .catch(() => { /* keep the disabled "Scan Complete" fallback */ });
    return () => { cancelled = true; };
  }, [alreadyScanned, emailId]);

  useEffect(() => {
    if (state !== 'scanning' || !polledScan) return;
    queueMicrotask(() => {
      if (polledScan.status === 'complete') {
        setVerdict(polledScan.verdict);
        setState('complete');
        onComplete();
      } else if (polledScan.status === 'error') {
        setScanError('The background scan failed. Check backend logs for details.');
        setState('failed');
      }
    });
  }, [polledScan, state, onComplete]);

  useEffect(() => {
    if (state !== 'scanning' || !pollError) return;
    queueMicrotask(() => {
      setScanError(pollError);
      setState('failed');
    });
  }, [pollError, state]);

  const handleScan = async () => {
    if (state === 'scanning') return;
    setState('scanning');
    setScanError('');
    setVerdict(null);

    try {
      const response = await fetch(`/api/scans/${emailId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });

      const data = await response.json();

      if (!response.ok) {
        // Backend returned 500 with error details
        const detail = data?.detail ?? data;
        const errorMsg = detail?.message ?? detail?.error ?? (typeof detail === 'string' ? detail : 'Unknown error');
        const errorType = detail?.type ?? 'Error';
        setScanError(`${errorType}: ${errorMsg}`);
        setState('failed');
        return;
      }

      if (data.status === 'queued' && data.scan_id) {
        setScanId(data.scan_id);
        startPolling(data.scan_id);
      } else {
        setScanError('Unexpected response from server');
        setState('failed');
      }
    } catch {
      setScanError('Cannot reach backend — is Docker running?');
      setState('failed');
    }
  };

  const configs: Record<ScanState, { label: string; icon: React.ReactNode; bg: string; color: string; border: string }> = {
    idle:     { label: 'Run Scan',       icon: <ScanSearch size={14} />,  bg: 'var(--primary)',       color: 'white',              border: 'var(--primary)' },
    scanning: { label: 'Scanning…',      icon: <LoadingDots />,             bg: 'var(--bg-input)',      color: 'var(--primary)',       border: 'var(--primary)' },
    complete: { label: 'Scan Complete',  icon: <CheckCircle size={14} />,  bg: 'var(--safe-subtle)',   color: 'var(--text-safe)',     border: 'var(--safe)' },
    failed:   { label: 'Failed — Retry', icon: <XCircle size={14} />,      bg: 'var(--danger-subtle)', color: 'var(--text-danger)',   border: 'var(--danger)' },
  };
  const cfg = configs[state];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      {state === 'complete' && scanId !== null ? (
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <button
            className="btn-primary"
            onClick={() => navigate(`/scans/${scanId}`)}
            style={{ fontSize: '0.875rem', padding: '8px 18px' }}
          >
            <ScanSearch size={14} />
            View Analysis →
          </button>
          <button
            className="btn-ghost"
            onClick={handleScan}
            style={{ fontSize: '0.8rem', padding: '7px 14px' }}
            title="Run the scan again"
          >
            <RefreshCw size={13} />
            Re-scan
          </button>
        </div>
      ) : (
        <motion.button
          layout
          onClick={handleScan}
          disabled={state === 'scanning' || state === 'complete'}
          style={{
            background: cfg.bg,
            color: cfg.color,
            border: `1px solid ${cfg.border}`,
            borderRadius: 6,
            padding: '8px 18px',
            fontSize: '0.875rem',
            fontWeight: 600,
            cursor: state === 'scanning' || state === 'complete' ? 'not-allowed' : 'pointer',
            display: 'inline-flex',
            alignItems: 'center',
            gap: 8,
            transition: 'all 250ms ease',
            width: 'fit-content',
          }}
        >
          {cfg.icon}
          {cfg.label}
        </motion.button>
      )}

      {/* Scanning indicator */}
      {state === 'scanning' && (
        <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          Scan #{scanId ?? '…'} is running in the background…
        </p>
      )}

      {/* Error message */}
      {state === 'failed' && scanError && (
        <div style={{
          border: '1px solid rgba(239,68,68,0.4)',
          background: 'rgba(239,68,68,0.06)',
          borderRadius: 6,
          padding: '8px 12px',
          fontSize: '0.78rem',
          color: '#FCA5A5',
          display: 'flex',
          alignItems: 'flex-start',
          gap: 8,
        }}>
          <AlertCircle size={14} style={{ flexShrink: 0, marginTop: 2 }} />
          <span>⚠ Scan error: {scanError}</span>
        </div>
      )}

      {/* Inline verdict after successful scan */}
      {state === 'complete' && verdict && scanId && (
        <div style={{
          background: 'var(--bg-input)',
          border: '1px solid var(--border-subtle)',
          borderRadius: 6,
          padding: '10px 14px',
          display: 'flex',
          flexDirection: 'column',
          gap: 8,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span className="font-mono" style={{
              fontSize: '1rem',
              fontWeight: 700,
              color: verdict.final_score >= 70 ? '#EF4444' : verdict.final_score >= 30 ? '#F59E0B' : '#10B981',
            }}>
              {verdict.final_score.toFixed(0)}
            </span>
            <span style={{
              fontSize: '0.7rem',
              fontWeight: 600,
              padding: '2px 8px',
              borderRadius: 3,
              background: verdict.classification === 'dangerous' ? '#EF444420' : verdict.classification === 'suspicious' ? '#F59E0B20' : '#10B98120',
              color: verdict.classification === 'dangerous' ? '#FCA5A5' : verdict.classification === 'suspicious' ? '#FCD34D' : '#6EE7B7',
              textTransform: 'uppercase' as const,
              letterSpacing: '0.06em',
            }}>
              {verdict.classification}
            </span>
          </div>
          <button
            onClick={() => navigate(`/scans/${scanId}`)}
            style={{ background: 'none', border: 'none', color: 'var(--primary)', cursor: 'pointer', fontSize: '0.75rem', fontWeight: 600, padding: 0, textAlign: 'left' as const }}
          >
            View Full Report →
          </button>
        </div>
      )}
    </div>
  );
}

// ─── Email Detail Panel ─────────────────────────────────────────────────────────
function EmailDetailPanel({ emailId, onScanComplete }: { emailId: number; onScanComplete: () => void }) {
  const [detail, setDetail] = useState<EmailDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [viewMode, setViewMode] = useState<'text' | 'html' | null>(null);

  useEffect(() => {
    queueMicrotask(() => setLoading(true));
    getEmail(emailId).then(setDetail).finally(() => setLoading(false));
  }, [emailId]);

  if (loading) {
    return (
      <div style={{ padding: 32, display: 'flex', flexDirection: 'column', gap: 12 }}>
        {[80, 60, 200, 100].map((h, i) => <div key={i} className="skeleton" style={{ height: h, borderRadius: 6 }} />)}
      </div>
    );
  }

  if (!detail) return null;

  const isScanned = detail.scan_count > 0;
  // HTML Preview is the default tab (falls back to Plain Text for
  // text-only emails) until the user picks a tab explicitly.
  const activeMode: 'text' | 'html' =
    viewMode ?? (detail.has_html && detail.body_html ? 'html' : 'text');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      {/* Email Header */}
      <div style={{ padding: '20px 24px', borderBottom: '1px solid var(--border-subtle)', background: 'var(--bg-input)' }}>
        <h2 style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: 12, lineHeight: 1.4 }}>
          {detail.subject || '(no subject)'}
        </h2>
        {[
          { label: 'From', value: detail.sender },
          { label: 'To', value: detail.to_address ?? '—' },
          { label: 'Date', value: detail.date ? format(new Date(detail.date), 'PPpp') : '—' },
          ...(detail.has_attachments ? [{ label: 'Attachments', value: `${detail.attachment_count} file${detail.attachment_count !== 1 ? 's' : ''}` }] : []),
        ].map(({ label, value }) => (
          <div key={label} style={{ display: 'flex', gap: 8, marginBottom: 4 }}>
            <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)', minWidth: 72, fontWeight: 600 }}>{label}:</span>
            <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>{value}</span>
          </div>
        ))}
      </div>

      {/* Action Bar */}
      <div style={{ padding: '12px 24px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', alignItems: 'center', gap: 12 }}>
        <RunScanButton emailId={detail.id} alreadyScanned={isScanned} onComplete={onScanComplete} />
        {isScanned && (
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            {detail.scan_count} scan{detail.scan_count !== 1 ? 's' : ''} run
          </span>
        )}
      </div>

      {/* Body Preview */}
      <div style={{ flex: 1, overflow: 'auto', padding: '16px 24px', display: 'flex', flexDirection: 'column', gap: 16 }}>
        {/* Toggle */}
        <div style={{ display: 'flex', gap: 4, background: 'var(--bg-input)', borderRadius: 6, padding: 3, width: 'fit-content' }}>
          {(['html', 'text'] as const).map((mode) => (
            <button
              key={mode}
              onClick={() => setViewMode(mode)}
              style={{
                padding: '4px 14px',
                fontSize: '0.75rem',
                fontWeight: 600,
                borderRadius: 4,
                border: 'none',
                cursor: 'pointer',
                background: activeMode === mode ? 'var(--bg-card)' : 'transparent',
                color: activeMode === mode ? 'var(--text-primary)' : 'var(--text-muted)',
                transition: 'all 200ms',
              }}
            >
              {mode === 'text' ? 'Plain Text' : 'HTML Preview'}
            </button>
          ))}
        </div>

        {activeMode === 'text' ? (
          <pre className="font-mono" style={{
            fontSize: '0.78rem',
            color: 'var(--text-secondary)',
            lineHeight: 1.7,
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-word',
            background: 'var(--bg-input)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 6,
            padding: 16,
            minHeight: 120,
          }}>
            {detail.body_text ?? '(no plain text body)'}
          </pre>
        ) : (
          <div style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', borderRadius: 6, overflow: 'hidden' }}>
            {detail.has_html && detail.body_html ? (
              <iframe
                srcDoc={detail.body_html}
                sandbox="allow-same-origin"
                style={{ width: '100%', minHeight: 300, border: 'none', background: 'white' }}
                title="Email HTML Preview"
              />
            ) : (
              <p style={{ padding: 24, color: 'var(--text-muted)', fontSize: '0.875rem' }}>No HTML content available</p>
            )}
          </div>
        )}

        {/* Attachments */}
        {detail.has_attachments && detail.attachments.length > 0 && (
          <div>
            <p style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
              <Paperclip size={13} /> Attachments ({detail.attachments.length})
            </p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {detail.attachments.map((att) => <AttachmentCard key={att.id} att={att} />)}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Email Inbox Page ──────────────────────────────────────────────────────────
export function EmailInbox() {
  const [emails, setEmails] = useState<Email[]>([]);
  const [loading, setLoading] = useState(true);
  const [fetching, setFetching] = useState(false);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState<FilterType>('all');
  const [, setError] = useState<string | null>(null);
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set());
  const [bulkScanning, setBulkScanning] = useState(false);
  const [bulkProgress, setBulkProgress] = useState<{ queued: number; done: number } | null>(null);

  const loadEmails = async (opts?: { quiet?: boolean }) => {
    if (!opts?.quiet) setLoading(true);
    try {
      const data = await getEmails(0, 100);
      // Sort newest first (fetched_at DESC) as a client-side safety net
      const sorted = [...data].sort((a, b) => {
        const dateA = new Date(a.fetched_at).getTime();
        const dateB = new Date(b.fetched_at).getTime();
        return dateB - dateA; // descending — newest first
      });
      setEmails(sorted);
      if (!opts?.quiet && sorted.length > 0 && !selectedId) setSelectedId(sorted[0].id);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load');
    } finally {
      if (!opts?.quiet) setLoading(false);
    }
  };

  const handleFetch = async () => {
    setFetching(true);
    try {
      await fetchEmails(20);
      await loadEmails();
    } finally {
      setFetching(false);
    }
  };

  const toggleSelect = (id: number) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleSelectAll = () => {
    if (selectedIds.size === filtered.length) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(filtered.map((e) => e.id)));
    }
  };

  const handleBulkScan = async () => {
    const ids = Array.from(selectedIds);
    if (ids.length === 0) return;
    setBulkScanning(true);
    setBulkProgress({ queued: ids.length, done: 0 });
    try {
      await bulkScan(ids);
      setBulkProgress({ queued: ids.length, done: ids.length });
      setSelectedIds(new Set());
      setTimeout(() => {
        setBulkProgress(null);
        loadEmails();
      }, 2000);
    } catch {
      setBulkProgress(null);
    } finally {
      setBulkScanning(false);
    }
  };

  useEffect(() => { loadEmails(); }, []);

  // Keep scan-status chips fresh while background scans are queued/running.
  const hasActiveScans = emails.some(
    (e) => e.latest_scan_status === 'pending' || e.latest_scan_status === 'running'
  );
  useEffect(() => {
    if (!hasActiveScans) return;
    const t = setInterval(() => { void loadEmails({ quiet: true }); }, 4000);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hasActiveScans]);

  const filtered = useMemo(() => {
    let list = emails;
    if (search) {
      const q = search.toLowerCase();
      list = list.filter((e) => e.sender.toLowerCase().includes(q) || e.subject.toLowerCase().includes(q));
    }
    if (filter === 'has_attachments') list = list.filter((e) => e.has_attachments);
    else if (filter === 'scanned') list = list.filter((e) => e.scan_count > 0);
    else if (filter === 'unscanned') list = list.filter((e) => e.scan_count === 0);
    return list;
  }, [emails, search, filter]);

  return (
    <div style={{ display: 'flex', height: '100%', overflow: 'hidden' }}>
      {/* Left Panel */}
      <div style={{ width: 380, minWidth: 380, borderRight: '1px solid var(--border-default)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        {/* Toolbar */}
        <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div style={{ display: 'flex', gap: 8 }}>
            <div style={{ flex: 1, position: 'relative' }}>
              <Search size={14} style={{ position: 'absolute', left: 9, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)', pointerEvents: 'none' }} />
              <input
                className="dark-input"
                style={{ width: '100%', paddingLeft: 30 }}
                placeholder="Search sender, subject…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
            <button className="btn-ghost" onClick={handleFetch} disabled={fetching} style={{ padding: '6px 10px', flexShrink: 0 }}>
              <RefreshCw size={14} style={{ animation: fetching ? 'spin 1s linear infinite' : 'none' }} />
            </button>
          </div>
          {/* Filter Pills */}
          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', alignItems: 'center' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: 4, cursor: 'pointer', marginRight: 4 }}>
              <input
                type="checkbox"
                checked={selectedIds.size === filtered.length && filtered.length > 0}
                onChange={toggleSelectAll}
                style={{ width: 14, height: 14, accentColor: 'var(--primary)' }}
              />
              <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>All</span>
            </label>
            {(['all', 'has_attachments', 'scanned', 'unscanned'] as FilterType[]).map((f) => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                style={{
                  padding: '3px 10px',
                  fontSize: '0.7rem',
                  fontWeight: 600,
                  borderRadius: 12,
                  border: `1px solid ${filter === f ? 'var(--primary)' : 'var(--border-default)'}`,
                  background: filter === f ? 'var(--primary-glow)' : 'transparent',
                  color: filter === f ? 'var(--primary)' : 'var(--text-muted)',
                  cursor: 'pointer',
                  textTransform: 'capitalize',
                  whiteSpace: 'nowrap',
                }}
              >
                {f.replace('_', ' ')}
              </button>
            ))}
          </div>
          <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
            Showing {filtered.length} of {emails.length} emails
          </span>
          {/* Bulk Actions */}
          {selectedIds.size > 0 && (
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', padding: '8px 12px', background: 'var(--primary-glow)', borderRadius: 6, border: '1px solid var(--primary)' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--primary)', fontWeight: 700 }}>
                {selectedIds.size} selected
              </span>
              <button
                onClick={handleBulkScan}
                disabled={bulkScanning}
                style={{
                  padding: '4px 12px',
                  fontSize: '0.75rem',
                  fontWeight: 700,
                  borderRadius: 4,
                  border: '1px solid var(--primary)',
                  background: bulkScanning ? 'var(--bg-input)' : 'var(--primary)',
                  color: bulkScanning ? 'var(--primary)' : 'white',
                  cursor: bulkScanning ? 'not-allowed' : 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                }}
              >
                {bulkScanning ? '⏳' : '⚡'} {bulkScanning ? 'Scanning…' : 'Scan Selected'}
              </button>
              <button
                onClick={() => setSelectedIds(new Set())}
                style={{ padding: '4px 8px', fontSize: '0.75rem', background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
              >
                Clear
              </button>
            </div>
          )}
          {bulkProgress && !bulkScanning && (
            <div style={{ fontSize: '0.75rem', color: 'var(--safe)', fontWeight: 600 }}>
              ✓ {bulkProgress.done} scan{bulkProgress.done !== 1 ? 's' : ''} queued
            </div>
          )}
        </div>

        {/* Email List */}
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {loading ? (
            Array.from({ length: 5 }).map((_, i) => (
              <div key={i} style={{ padding: 14, borderBottom: '1px solid var(--border-subtle)', display: 'flex', gap: 10 }}>
                <div className="skeleton" style={{ width: 36, height: 36, borderRadius: '50%', flexShrink: 0 }} />
                <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 6 }}>
                  <div className="skeleton" style={{ height: 12, width: '60%', borderRadius: 4 }} />
                  <div className="skeleton" style={{ height: 10, width: '90%', borderRadius: 4 }} />
                </div>
              </div>
            ))
          ) : filtered.length === 0 ? (
            <div style={{ padding: 40, textAlign: 'center' }}>
              <ShieldCheck size={36} style={{ color: 'var(--safe)', margin: '0 auto 12px' }} />
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem' }}>No emails found</p>
              <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', marginTop: 4 }}>Click Fetch Emails to pull from your inbox</p>
            </div>
          ) : (
            <AnimatePresence initial={false}>
              {filtered.map((email, i) => {
                const isSelected = email.id === selectedId;
                return (
                  <motion.div
                    key={email.id}
                    initial={{ opacity: 0, y: -10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: i * 0.03 }}
                    onClick={() => setSelectedId(email.id)}
                    style={{
                      padding: '12px 14px',
                      borderBottom: '1px solid var(--border-subtle)',
                      cursor: 'pointer',
                      background: isSelected ? 'var(--primary-glow)' : 'transparent',
                      borderLeft: `3px solid ${isSelected ? 'var(--primary)' : email.scan_count > 0 ? 'transparent' : 'transparent'}`,
                      transition: 'all 200ms ease',
                      display: 'flex',
                      gap: 10,
                    }}
                    onMouseEnter={(e) => { if (!isSelected) (e.currentTarget as HTMLDivElement).style.background = 'var(--bg-input)'; }}
                    onMouseLeave={(e) => { if (!isSelected) (e.currentTarget as HTMLDivElement).style.background = 'transparent'; }}
                  >
                    <input
                      type="checkbox"
                      checked={selectedIds.has(email.id)}
                      onClick={(e) => { e.stopPropagation(); toggleSelect(email.id); }}
                      onChange={() => {}}
                      style={{ width: 16, height: 16, marginTop: 10, accentColor: 'var(--primary)', cursor: 'pointer', flexShrink: 0 }}
                    />
                    <SenderAvatar sender={email.sender} />
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 4 }}>
                        <p style={{ fontSize: '0.8rem', fontWeight: email.scan_count === 0 ? 700 : 500, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {email.sender.split('@')[0]}
                        </p>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexShrink: 0 }}>
                          {email.has_attachments && <Paperclip size={11} style={{ color: 'var(--text-muted)' }} />}
                          <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                            {email.date ? formatDistanceToNow(new Date(email.date), { addSuffix: true }) : '—'}
                          </span>
                        </div>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 2 }}>
                        <p style={{ flex: 1, minWidth: 0, fontSize: '0.75rem', color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {email.subject || '(no subject)'}
                        </p>
                        <ScanStatusChip email={email} />
                      </div>
                    </div>
                  </motion.div>
                );
              })}
            </AnimatePresence>
          )}
        </div>
      </div>

      {/* Right Panel */}
      <div style={{ flex: 1, overflow: 'hidden', background: 'var(--bg-page)' }}>
        {selectedId ? (
          <EmailDetailPanel emailId={selectedId} onScanComplete={loadEmails} />
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', gap: 12 }}>
            <ShieldCheck size={48} style={{ color: 'var(--text-muted)' }} />
            <p style={{ color: 'var(--text-muted)' }}>Select an email to preview</p>
          </div>
        )}
      </div>
    </div>
  );
}
