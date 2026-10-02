import { useEffect, useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { AlertCircle, ScanSearch, Brain, Link2, Paperclip } from 'lucide-react';
import { getScans, getEmails } from '../api/client';
import { ClassificationBadge } from '../components/ui/Badge';
import { ScoreBar } from '../components/ui/ScoreBar';
import { formatDistanceToNow } from 'date-fns';
import type { Scan, Email } from '../types';

type ClassFilter = 'all' | 'dangerous' | 'suspicious' | 'safe';
type StatusFilter = 'all' | 'complete' | 'running' | 'error';
type SortKey = 'date' | 'score' | 'subject';

// ─── Skeleton ScanCard ────────────────────────────────────────────────────────
function ScanCardSkeleton() {
  return (
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, padding: 20, display: 'flex', gap: 20 }}>
      <div className="skeleton" style={{ width: 80, height: 80, borderRadius: 8 }} />
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 8 }}>
        <div className="skeleton" style={{ height: 14, width: '40%', borderRadius: 4 }} />
        <div className="skeleton" style={{ height: 10, width: '70%', borderRadius: 4 }} />
        <div className="skeleton" style={{ height: 8, width: '100%', borderRadius: 4 }} />
        <div className="skeleton" style={{ height: 8, width: '80%', borderRadius: 4 }} />
      </div>
    </div>
  );
}

// ─── Scan Card ────────────────────────────────────────────────────────────────
function ScanCard({ scan, email, index, onClick }: { scan: Scan; email?: Email; index: number; onClick: () => void }) {
  const v = scan.verdict;
  const clsColor = v?.classification === 'dangerous' ? 'var(--danger)' : v?.classification === 'suspicious' ? 'var(--warning)' : 'var(--safe)';

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.08, duration: 0.3 }}
      onClick={onClick}
      onMouseEnter={(e) => {
        (e.currentTarget as HTMLDivElement).style.background = 'var(--bg-input)';
        (e.currentTarget as HTMLDivElement).style.borderColor = 'var(--border-emphasis)';
      }}
      onMouseLeave={(e) => {
        (e.currentTarget as HTMLDivElement).style.background = 'var(--bg-card)';
        (e.currentTarget as HTMLDivElement).style.borderColor = 'var(--border-default)';
      }}
      style={{
        background: 'var(--bg-card)',
        border: '1px solid var(--border-default)',
        borderLeft: `4px solid ${clsColor}`,
        borderRadius: 8,
        padding: 20,
        display: 'flex',
        gap: 20,
        cursor: 'pointer',
        transition: 'all 200ms ease',
      }}
    >
      {/* Score */}
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minWidth: 80 }}>
        {v ? (
          <>
            <span
              className="font-mono"
              style={{
                fontSize: '3rem',
                fontWeight: 700,
                lineHeight: 1,
                color: clsColor,
                filter: `drop-shadow(0 0 8px ${clsColor}60)`,
              }}
            >
              {v.final_score.toFixed(0)}
            </span>
            <ClassificationBadge classification={v.classification} size="sm" />
          </>
        ) : (
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'capitalize' }}>{scan.status}</span>
        )}
      </div>

      {/* Main Info */}
      <div style={{ flex: 1, minWidth: 0 }}>
        <p style={{ fontSize: '0.875rem', fontWeight: 700, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginBottom: 4 }}>
          {email?.subject ?? '(no subject)'}
        </p>
        <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: 12 }}>
          {email?.sender ?? `Email #${scan.email_number ?? scan.email_id}`} · {scan.completed_at ? formatDistanceToNow(new Date(scan.completed_at), { addSuffix: true }) : '—'}
        </p>

        {/* Engine Scores */}
        {v && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <Brain size={13} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
              <div style={{ flex: 1 }}><ScoreBar score={v.ai_score ?? 0} label="ML" /></div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <Link2 size={13} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
              <div style={{ flex: 1 }}><ScoreBar score={v.url_score ?? 0} label="URL" /></div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <Paperclip size={13} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
              <div style={{ flex: 1 }}><ScoreBar score={v.attachment_score ?? 0} label="Attachment" /></div>
            </div>
          </div>
        )}
      </div>

      {/* Action */}
      <div style={{ display: 'flex', alignItems: 'center' }}>
        <button
          onClick={(e) => { e.stopPropagation(); onClick(); }}
          style={{
            background: 'var(--primary-glow)',
            border: '1px solid var(--primary)',
            color: 'var(--primary)',
            borderRadius: 6,
            padding: '6px 14px',
            fontSize: '0.8rem',
            fontWeight: 600,
            cursor: 'pointer',
            whiteSpace: 'nowrap',
          }}
        >
          View Details
        </button>
      </div>
    </motion.div>
  );
}

// ─── Scan Results Page ────────────────────────────────────────────────────────
export function ScanResults() {
  const navigate = useNavigate();
  const [scans, setScans] = useState<Scan[]>([]);
  const [emails, setEmails] = useState<Email[]>([]);
  const [loading, setLoading] = useState(true);
  const [classFilter, setClassFilter] = useState<ClassFilter>('all');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [scoreMin, setScoreMin] = useState(0);
  const [scoreMax, setScoreMax] = useState(100);
  const [sortKey, setSortKey] = useState<SortKey>('date');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      try {
        const [s, e] = await Promise.all([getScans(0, 200), getEmails(0, 200)]);
        setScans(s);
        setEmails(e);
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : 'Failed to load scans');
      } finally {
        setLoading(false);
      }
    };
    load();
  }, []);

  const emailMap = useMemo(() => new Map(emails.map((e) => [e.id, e])), [emails]);

  const filtered = useMemo(() => {
    let list = scans;
    if (classFilter !== 'all') list = list.filter((s) => s.verdict?.classification === classFilter);
    if (statusFilter !== 'all') list = list.filter((s) => s.status === statusFilter);
    list = list.filter((s) => {
      if (!s.verdict) return statusFilter !== 'all';
      return s.verdict.final_score >= scoreMin && s.verdict.final_score <= scoreMax;
    });
    const dir = sortDir === 'desc' ? -1 : 1;
    return [...list].sort((a, b) => {
      let cmp = 0;
      if (sortKey === 'date') {
        cmp = (a.completed_at || a.started_at || '').localeCompare(b.completed_at || b.started_at || '');
      } else if (sortKey === 'subject') {
        cmp = (emailMap.get(a.email_id)?.subject ?? '').localeCompare(emailMap.get(b.email_id)?.subject ?? '');
      } else {
        cmp = (a.verdict?.final_score ?? -1) - (b.verdict?.final_score ?? -1);
      }
      return cmp === 0 ? b.id - a.id : cmp * dir;
    });
  }, [scans, classFilter, statusFilter, scoreMin, scoreMax, sortKey, sortDir, emailMap]);

  if (error) {
    return (
      <div style={{ padding: 24 }}>
        <div style={{ border: '1px solid var(--danger)', borderRadius: 8, background: 'var(--danger-subtle)', padding: 20, display: 'flex', gap: 12 }}>
          <AlertCircle size={20} style={{ color: 'var(--danger)' }} />
          <div>
            <p style={{ fontWeight: 600, color: 'var(--text-danger)' }}>Failed to load scans</p>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>{error}</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Filters */}
      <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, padding: '14px 20px', display: 'flex', gap: 20, flexWrap: 'wrap', alignItems: 'center' }}>
        {/* Classification */}
        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginRight: 4 }}>Class:</span>
          {(['all', 'dangerous', 'suspicious', 'safe'] as ClassFilter[]).map((f) => (
            <button key={f} onClick={() => setClassFilter(f)} style={{
              padding: '4px 12px',
              borderRadius: 12,
              border: `1px solid ${classFilter === f ? 'var(--primary)' : 'var(--border-default)'}`,
              background: classFilter === f ? 'var(--primary-glow)' : 'transparent',
              color: classFilter === f ? 'var(--primary)' : 'var(--text-muted)',
              fontSize: '0.75rem',
              fontWeight: 600,
              cursor: 'pointer',
              textTransform: 'capitalize',
            }}>
              {f}
            </button>
          ))}
        </div>

        {/* Status */}
        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginRight: 4 }}>Status:</span>
          {(['all', 'complete', 'running', 'error'] as StatusFilter[]).map((f) => (
            <button key={f} onClick={() => setStatusFilter(f)} style={{
              padding: '4px 12px',
              borderRadius: 12,
              border: `1px solid ${statusFilter === f ? 'var(--primary)' : 'var(--border-default)'}`,
              background: statusFilter === f ? 'var(--primary-glow)' : 'transparent',
              color: statusFilter === f ? 'var(--primary)' : 'var(--text-muted)',
              fontSize: '0.75rem',
              fontWeight: 600,
              cursor: 'pointer',
              textTransform: 'capitalize',
            }}>
              {f}
            </button>
          ))}
        </div>

        {/* Score Range */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Score:</span>
          <input type="range" min={0} max={100} value={scoreMin} onChange={(e) => setScoreMin(+e.target.value)} style={{ width: 80, accentColor: 'var(--primary)' }} />
          <span className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', minWidth: 24 }}>{scoreMin}</span>
          <span style={{ color: 'var(--text-muted)' }}>–</span>
          <input type="range" min={0} max={100} value={scoreMax} onChange={(e) => setScoreMax(+e.target.value)} style={{ width: 80, accentColor: 'var(--primary)' }} />
          <span className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', minWidth: 24 }}>{scoreMax}</span>
        </div>

        {/* Sort */}
        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Sort:</span>
          <select
            className="dark-input"
            style={{ fontSize: '0.75rem', padding: '4px 8px' }}
            value={sortKey}
            onChange={(e) => setSortKey(e.target.value as SortKey)}
          >
            <option value="date">Date</option>
            <option value="score">Score</option>
            <option value="subject">Subject</option>
          </select>
          <button
            onClick={() => setSortDir((d) => (d === 'desc' ? 'asc' : 'desc'))}
            title={sortDir === 'desc' ? 'Descending — click for ascending' : 'Ascending — click for descending'}
            style={{
              padding: '4px 10px',
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

        <span style={{ marginLeft: 'auto', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          {filtered.length} result{filtered.length !== 1 ? 's' : ''}
        </span>
      </div>

      {/* Cards */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        {loading ? (
          Array.from({ length: 3 }).map((_, i) => <ScanCardSkeleton key={i} />)
        ) : filtered.length === 0 ? (
          <div style={{ textAlign: 'center', padding: 64 }}>
            <ScanSearch size={48} style={{ color: 'var(--text-muted)', margin: '0 auto 16px' }} />
            <p style={{ color: 'var(--text-secondary)', fontSize: '1rem', fontWeight: 600 }}>No scans yet</p>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem', marginTop: 6 }}>
              Run scans on emails from the Email Inbox to see results here
            </p>
          </div>
        ) : (
          filtered.map((scan, i) => (
            <ScanCard
              key={scan.id}
              scan={scan}
              email={emailMap.get(scan.email_id)}
              index={i}
              onClick={() => navigate(`/scans/${scan.id}`)}
            />
          ))
        )}
      </div>
    </div>
  );
}
