import { useEffect, useMemo, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Paperclip,
  FileText,
  Code,
  File,
  Search,
  Shield,
  AlertTriangle,
} from 'lucide-react';
import { getAttachments } from '../api/client';
import { ClassificationBadge, ScoreBadge } from '../components/ui/Badge';
import type { AttachmentSummary } from '../api/client';

// ─── File Type Icon ───────────────────────────────────────────────────────────
function FileTypeIcon({ filename }: { filename: string }) {
  const ext = filename.split('.').pop()?.toLowerCase() ?? '';
  if (['pdf'].includes(ext)) return <FileText size={20} style={{ color: '#EF4444' }} />;
  if (['exe', 'dll', 'bat', 'ps1', 'cmd'].includes(ext)) return <Code size={20} style={{ color: '#F59E0B' }} />;
  if (['doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'].includes(ext)) return <FileText size={20} style={{ color: '#3B82F6' }} />;
  if (['zip', 'rar', '7z', 'tar', 'gz'].includes(ext)) return <File size={20} style={{ color: '#8B5CF6' }} />;
  return <File size={20} style={{ color: 'var(--text-muted)' }} />;
}

// ─── Attachment Card ──────────────────────────────────────────────────────────
function AttachmentCard({
  att,
  onClick,
}: {
  att: AttachmentSummary;
  onClick: () => void;
}) {
  const sizeStr =
    att.size_bytes > 1024 * 1024
      ? `${(att.size_bytes / 1024 / 1024).toFixed(1)} MB`
      : `${Math.round(att.size_bytes / 1024)} KB`;

  const ext = att.filename.split('.').pop()?.toLowerCase() ?? '';
  const isDangerous = ['exe', 'dll', 'bat', 'ps1', 'cmd', 'vbs'].includes(ext);

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      onClick={onClick}
      style={{
        background: 'var(--bg-card)',
        border: '1px solid var(--border-default)',
        borderRadius: 8,
        padding: 16,
        cursor: 'pointer',
        transition: 'all 200ms ease',
        display: 'flex',
        gap: 14,
        alignItems: 'flex-start',
      }}
      onMouseEnter={(e) => {
        (e.currentTarget as HTMLDivElement).style.borderColor = 'var(--primary)';
        (e.currentTarget as HTMLDivElement).style.transform = 'translateY(-1px)';
      }}
      onMouseLeave={(e) => {
        (e.currentTarget as HTMLDivElement).style.borderColor = 'var(--border-default)';
        (e.currentTarget as HTMLDivElement).style.transform = 'none';
      }}
    >
      <div style={{ flexShrink: 0, marginTop: 2 }}>
        <FileTypeIcon filename={att.filename} />
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
          <p
            style={{
              fontSize: '0.875rem',
              fontWeight: 700,
              color: 'var(--text-primary)',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
              flex: 1,
            }}
          >
            {att.filename}
          </p>
          {isDangerous && (
            <AlertTriangle size={14} style={{ color: 'var(--danger)', flexShrink: 0 }} />
          )}
        </div>
        <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: 6 }}>
          {att.content_type ?? 'Unknown type'} · {sizeStr}
        </p>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
            From: {att.email_sender.split('<')[0].trim()}
          </span>
          {att.latest_classification && (
            <ClassificationBadge classification={att.latest_classification} />
          )}
          {att.latest_scan_score !== null && (
            <ScoreBadge score={att.latest_scan_score} size="sm" />
          )}
        </div>
        {att.sha256_hash && (
          <p
            className="font-mono"
            style={{ fontSize: '0.6rem', color: 'var(--text-muted)', marginTop: 6, wordBreak: 'break-all' }}
          >
            SHA256: {att.sha256_hash.slice(0, 32)}…
          </p>
        )}
      </div>
    </motion.div>
  );
}

// ─── Attachments Page ─────────────────────────────────────────────────────────
type SortKey = 'date' | 'filename' | 'score' | 'size';

export function AttachmentsPage() {
  const [attachments, setAttachments] = useState<AttachmentSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [sortKey, setSortKey] = useState<SortKey>('date');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const [, setError] = useState<string | null>(null);

  useEffect(() => {
    getAttachments(0, 200)
      .then(setAttachments)
      .catch((err) => setError(err instanceof Error ? err.message : 'Failed to load'))
      .finally(() => setLoading(false));
  }, []);

  const filtered = useMemo(() => {
    const q = search.toLowerCase();
    const list = search
      ? attachments.filter(
          (a) =>
            a.filename.toLowerCase().includes(q) ||
            a.email_sender.toLowerCase().includes(q) ||
            a.email_subject.toLowerCase().includes(q)
        )
      : attachments;
    const dir = sortDir === 'desc' ? -1 : 1;
    return [...list].sort((a, b) => {
      let cmp = 0;
      if (sortKey === 'filename') cmp = a.filename.localeCompare(b.filename);
      else if (sortKey === 'score') cmp = (a.latest_scan_score ?? -1) - (b.latest_scan_score ?? -1);
      else if (sortKey === 'size') cmp = a.size_bytes - b.size_bytes;
      else cmp = a.id - b.id; // insertion order ≈ ingest date
      return cmp === 0 ? b.id - a.id : cmp * dir;
    });
  }, [attachments, search, sortKey, sortDir]);

  const stats = {
    total: attachments.length,
    dangerous: attachments.filter((a) => a.latest_classification === 'dangerous').length,
    suspicious: attachments.filter((a) => a.latest_classification === 'suspicious').length,
    safe: attachments.filter((a) => a.latest_classification === 'safe').length,
  };

  return (
    <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 20, maxWidth: 1100 }}>
      {/* Header */}
      <div>
        <h1 style={{ fontSize: '1.25rem', fontWeight: 800, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 10 }}>
          <Paperclip size={22} style={{ color: 'var(--primary)' }} />
          Attachment Analysis
        </h1>
        <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: 4 }}>
          Browse and inspect all email attachments and their scan results
        </p>
      </div>

      {/* Stats */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
        {[
          { label: 'Total', value: stats.total, color: 'var(--primary)' },
          { label: 'Dangerous', value: stats.dangerous, color: 'var(--danger)' },
          { label: 'Suspicious', value: stats.suspicious, color: 'var(--warning)' },
          { label: 'Safe', value: stats.safe, color: 'var(--safe)' },
        ].map((s) => (
          <div
            key={s.label}
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-default)',
              borderRadius: 8,
              padding: 16,
              textAlign: 'center',
            }}
          >
            <p className="font-mono" style={{ fontSize: '1.5rem', fontWeight: 900, color: s.color }}>
              {s.value}
            </p>
            <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              {s.label}
            </p>
          </div>
        ))}
      </div>

      {/* Search + Sort */}
      <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
        <div style={{ position: 'relative', flex: 1 }}>
          <Search size={14} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
          <input
            className="dark-input"
            style={{ width: '100%', paddingLeft: 36 }}
            placeholder="Search by filename, sender, or subject…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Sort:</span>
          <select
            className="dark-input"
            style={{ fontSize: '0.75rem', padding: '5px 8px' }}
            value={sortKey}
            onChange={(e) => setSortKey(e.target.value as SortKey)}
          >
            <option value="date">Date</option>
            <option value="filename">Filename</option>
            <option value="score">Score</option>
            <option value="size">Size</option>
          </select>
          <button
            onClick={() => setSortDir((d) => (d === 'desc' ? 'asc' : 'desc'))}
            title={sortDir === 'desc' ? 'Descending — click for ascending' : 'Ascending — click for descending'}
            style={{
              padding: '5px 10px',
              borderRadius: 6,
              border: '1px solid var(--border-default)',
              background: 'transparent',
              color: 'var(--text-secondary)',
              fontSize: '0.72rem',
              fontWeight: 600,
              cursor: 'pointer',
              whiteSpace: 'nowrap',
            }}
          >
            {sortDir === 'desc' ? '↓ desc' : '↑ asc'}
          </button>
        </div>
      </div>

      {/* Attachment Grid */}
      {loading ? (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 12 }}>
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="skeleton" style={{ height: 120, borderRadius: 8 }} />
          ))}
        </div>
      ) : filtered.length === 0 ? (
        <div style={{ padding: 48, textAlign: 'center' }}>
          <Shield size={48} style={{ color: 'var(--text-muted)', margin: '0 auto 16px' }} />
          <p style={{ color: 'var(--text-secondary)', fontSize: '1rem' }}>
            {search ? 'No attachments match your search' : 'No attachments found'}
          </p>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', marginTop: 4 }}>
            {search ? 'Try a different search term' : 'Fetch emails with attachments to see them here'}
          </p>
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(400px, 1fr))', gap: 12 }}>
          <AnimatePresence>
            {filtered.map((att) => (
              <AttachmentCard key={att.id} att={att} onClick={() => {}} />
            ))}
          </AnimatePresence>
        </div>
      )}

      <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textAlign: 'center' }}>
        Showing {filtered.length} of {attachments.length} attachments
      </p>
    </div>
  );
}
