import { useEffect, useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { Link2, Search, ExternalLink, Copy, Check } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import type { Scan } from '../types';
import { getVtUrlLink } from '../utils/virustotal';
import { resolveScreenshotUrl } from '../api/client';

// ─── Types ─────────────────────────────────────────────────────────────────────
interface UrlEntry {
  url: string;
  score: number;
  heuristic_score?: number;
  vt_malicious: number;
  vt_suspicious?: number;
  vt_total?: number;
  vt_error?: string | null;
  top_flags: string[];
  scan_id: number;
  email_id: number;
  scanned_at: string | null;
  is_shortener?: boolean;
  dynamic_status?: string;
  screenshot_url?: string | null;
  playwright_screenshot_path?: string | null;
}

/** Read an optional field from a loosely-typed verdict breakdown row. */
function optional<T>(obj: unknown, key: string): T | undefined {
  return (obj as Record<string, T | undefined>)[key];
}

type RiskFilter = 'all' | 'high' | 'medium' | 'low';
type SortKey = 'score' | 'url' | 'scan_id' | 'date';

// ─── KPI Card ──────────────────────────────────────────────────────────────────
function KpiCard({ title, value, accent }: { title: string; value: number; accent: string }) {
  return (
    <div style={{
      background: 'var(--bg-card)',
      border: `1px solid var(--border-default)`,
      borderLeft: `3px solid ${accent}`,
      borderRadius: 8,
      padding: '16px 20px',
    }}>
      <p style={{ fontSize: '0.7rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>
        {title}
      </p>
      <p className="font-mono" style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1 }}>
        {value.toLocaleString()}
      </p>
    </div>
  );
}

// ─── URL Row ───────────────────────────────────────────────────────────────────
function UrlRow({ entry, expanded, onExpand }: {
  entry: UrlEntry;
  expanded: boolean;
  onExpand: () => void;
}) {
  const navigate = useNavigate();
  const [copied, setCopied] = useState(false);

  const scoreColor = entry.score >= 70 ? '#EF4444' : entry.score >= 30 ? '#F59E0B' : '#10B981';
  const scoreBg = entry.score >= 70 ? 'rgba(239,68,68,0.12)' : entry.score >= 30 ? 'rgba(245,158,11,0.12)' : 'rgba(16,185,129,0.12)';

  const displayUrl = entry.url.length > 60 ? entry.url.slice(0, 60) + '…' : entry.url;
  const screenshotUrl = resolveScreenshotUrl(
    entry.screenshot_url,
    entry.playwright_screenshot_path,
  );

  // Determine VT detection label and color based on available data
  let vtText: string;
  let vtColor: string;
  if ((entry.vt_total ?? 0) > 0) {
    if (entry.vt_malicious > 0) {
      vtText = `${entry.vt_malicious} malicious`;
      vtColor = '#FCA5A5';
    } else if ((entry.vt_suspicious ?? 0) > 0) {
      vtText = `${entry.vt_suspicious} suspicious`;
      vtColor = '#FCD34D';
    } else {
      vtText = `Clean (${entry.vt_total} engines)`;
      vtColor = '#10B981';
    }
  } else if (entry.vt_error && entry.vt_error.includes('No API keys')) {
    vtText = 'VT not configured';
    vtColor = '#F59E0B';
  } else if (entry.vt_error && entry.vt_error.includes('rate limit')) {
    vtText = 'Rate limited';
    vtColor = '#F59E0B';
  } else if (entry.vt_error) {
    vtText = 'VT error';
    vtColor = '#EF4444';
  } else {
    vtText = 'Not checked';
    vtColor = 'var(--text-muted)';
  }

  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(entry.url);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <>
      <tr
        onClick={onExpand}
        style={{ cursor: 'pointer' }}
        onMouseEnter={(e) => ((e.currentTarget as HTMLTableRowElement).style.background = 'var(--bg-input)')}
        onMouseLeave={(e) => ((e.currentTarget as HTMLTableRowElement).style.background = expanded ? 'rgba(99,102,241,0.05)' : '')}
      >
        <td style={{ maxWidth: 260, padding: '10px 12px' }}>
          <span title={entry.url} style={{ color: 'var(--text-secondary)', wordBreak: 'break-all', fontFamily: 'JetBrains Mono, monospace', fontSize: '0.72rem' }}>
            {displayUrl}
          </span>
        </td>
        <td style={{ padding: '10px 12px' }}>
          <span className="font-mono" style={{
            fontSize: '0.78rem',
            fontWeight: 700,
            color: scoreColor,
            background: scoreBg,
            padding: '2px 8px',
            borderRadius: 4,
          }}>
            {Math.round(entry.score)}
          </span>
        </td>
        <td style={{ padding: '10px 12px' }}>
          <span className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            {entry.heuristic_score != null ? Math.round(entry.heuristic_score) : '—'}
          </span>
        </td>
        <td style={{ padding: '10px 12px' }}>
          <span style={{ fontSize: '0.75rem', color: vtColor }}>{vtText}</span>
        </td>
        <td style={{ padding: '10px 12px' }}>
          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
            {entry.top_flags.slice(0, 2).map((f, i) => (
              <span key={i} style={{
                fontSize: '0.6rem',
                fontWeight: 600,
                color: '#94A3B8',
                background: 'var(--bg-input)',
                border: '1px solid var(--border-subtle)',
                padding: '1px 6px',
                borderRadius: 3,
                whiteSpace: 'nowrap',
              }}>
                {f.slice(0, 20)}{f.length > 20 ? '…' : ''}
              </span>
            ))}
            {entry.top_flags.length > 2 && (
              <span style={{ fontSize: '0.6rem', color: 'var(--text-muted)' }}>+{entry.top_flags.length - 2}</span>
            )}
          </div>
        </td>
        <td style={{ padding: '10px 12px' }}>
          <button
            onClick={(e) => { e.stopPropagation(); navigate(`/scans/${entry.scan_id}`); }}
            style={{ background: 'none', border: 'none', color: 'var(--primary)', cursor: 'pointer', fontSize: '0.75rem', fontWeight: 600, padding: 0 }}
          >
            #{entry.scan_id}
          </button>
        </td>
        <td style={{ padding: '10px 12px' }}>
          <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
            {entry.scanned_at ? formatDistanceToNow(new Date(entry.scanned_at), { addSuffix: true }) : '—'}
          </span>
        </td>
      </tr>

      {/* Expanded Row */}
      {expanded && (
        <tr style={{ background: 'rgba(99,102,241,0.04)' }}>
          <td colSpan={7} style={{ padding: '12px 16px 20px' }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {/* Full URL + copy */}
              <div style={{
                background: 'var(--bg-input)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 6,
                padding: '10px 14px',
                display: 'flex',
                alignItems: 'flex-start',
                gap: 10,
              }}>
                <span className="font-mono" style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', flex: 1, wordBreak: 'break-all' }}>
                  {entry.url}
                </span>
                <button onClick={handleCopy} style={{ background: 'none', border: 'none', cursor: 'pointer', color: copied ? '#10B981' : 'var(--text-muted)', flexShrink: 0 }}>
                  {copied ? <Check size={14} /> : <Copy size={14} />}
                </button>
              </div>

              {/* All flags */}
              {entry.top_flags.length > 0 && (
                <div>
                  <p style={{ fontSize: '0.65rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 6 }}>
                    Heuristic Flags
                  </p>
                  <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                    {entry.top_flags.map((f, i) => (
                      <span key={i} style={{
                        fontSize: '0.72rem',
                        color: '#94A3B8',
                        background: 'var(--bg-input)',
                        border: '1px solid var(--border-subtle)',
                        padding: '3px 10px',
                        borderRadius: 4,
                      }}>
                        {f}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Parent scan info */}
              <p style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                Found in{' '}
                <button
                  onClick={() => navigate(`/scans/${entry.scan_id}`)}
                  style={{ background: 'none', border: 'none', color: 'var(--primary)', cursor: 'pointer', fontSize: '0.72rem', fontWeight: 600, padding: 0 }}
                >
                  scan #{entry.scan_id}
                </button>{' '}
                of email #{entry.email_id}
              </p>

              {/* VT error detail */}
              {entry.vt_error && (
                <div style={{ color: '#FCD34D', fontSize: '12px', marginTop: '4px' }}>
                  ⚠ VT: {entry.vt_error}
                </div>
              )}

              {entry.dynamic_status && (
                <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>
                  Browser analysis: {entry.dynamic_status}
                </div>
              )}

              {screenshotUrl && (
                <a href={screenshotUrl} target="_blank" rel="noopener noreferrer">
                  <img
                    src={screenshotUrl}
                    alt={`Browser evidence for ${entry.url}`}
                    loading="lazy"
                    style={{ width: '100%', maxWidth: 720, borderRadius: 6, border: '1px solid var(--border-default)' }}
                  />
                </a>
              )}

              {/* Open in VirusTotal */}
              <a
                href={getVtUrlLink(entry.url)}
                target="_blank"
                rel="noopener noreferrer"
                onClick={(e) => e.stopPropagation()}
                style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: '0.75rem', color: 'var(--primary)', textDecoration: 'none', fontWeight: 600 }}
              >
                <ExternalLink size={12} /> Open in VirusTotal ↗
              </a>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

// ─── URL Analysis Page ─────────────────────────────────────────────────────────
export function UrlAnalysis() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [riskFilter, setRiskFilter] = useState<RiskFilter>('all');
  const [sortBy, setSortBy] = useState<SortKey>('score');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const [expandedUrl, setExpandedUrl] = useState<string | null>(null);

  useEffect(() => {
    const load = async () => {
      try {
        const r = await fetch('/api/scans?limit=200');
        const data = await r.json();
        setScans(data.scans ?? []);
      } catch {
        // ignore
      } finally {
        setLoading(false);
      }
    };
    load();
  }, []);

  // Extract all URL entries from scan verdicts
  const allUrls: UrlEntry[] = useMemo(() => {
    const seen = new Set<string>();
    const urls: UrlEntry[] = [];

    scans
      .filter((s) => s.verdict?.breakdown?.url?.per_url)
      .forEach((s) => {
        s.verdict!.breakdown!.url.per_url.forEach((u) => {
          const key = `${u.url}::${s.id}`;
          if (!seen.has(key)) {
            seen.add(key);
            const vtDet = u.vt_detections;
            urls.push({
              url: u.url,
              score: u.score ?? u.final_score ?? 0,
              heuristic_score: u.heuristic_score,
              vt_malicious: u.vt_malicious ?? vtDet?.malicious ?? 0,
              vt_suspicious: optional<number>(u, 'vt_suspicious') ?? vtDet?.suspicious ?? 0,
              vt_total: optional<number>(u, 'vt_total') ?? vtDet?.total ?? 0,
              vt_error: optional<string | null>(u, 'vt_error') ?? null,
              top_flags: u.top_flags ?? u.flags ?? [],
              scan_id: s.id,
              email_id: s.email_id,
              scanned_at: s.completed_at,
              is_shortener: false,
              dynamic_status: u.dynamic_status,
              screenshot_url: u.screenshot_url,
              playwright_screenshot_path: u.playwright_screenshot_path,
            });
          }
        });
      });

    return urls.sort((a, b) => b.score - a.score);
  }, [scans]);

  // KPIs
  const totalUrls = allUrls.length;
  const highRisk = allUrls.filter((u) => u.score >= 70).length;
  const vtFlagged = allUrls.filter((u) => u.vt_malicious > 0).length;

  // VT Status: derive from url data
  const vtStatus = useMemo(() => {
    if (allUrls.length === 0) return { label: 'No Data', color: 'var(--text-muted)', subtitle: 'Run scans to see VT status' };
    const anyVtRan = allUrls.some((u) => (u.vt_total ?? 0) > 0);
    if (anyVtRan) return { label: 'Active', color: '#10B981', subtitle: 'VirusTotal checks running' };
    const allNoKeys = allUrls.every((u) => u.vt_error && u.vt_error.includes('No API keys'));
    if (allNoKeys) return { label: 'Not Configured', color: '#F59E0B', subtitle: 'Set VIRUSTOTAL_API_KEYS in .env' };
    return { label: 'Pending', color: '#3B82F6', subtitle: 'Keys configured, results pending' };
  }, [allUrls]);

  // Filter + sort
  const filtered = useMemo(() => {
    let list = allUrls;

    if (search) {
      const q = search.toLowerCase();
      list = list.filter((u) => u.url.toLowerCase().includes(q));
    }

    if (riskFilter === 'high') list = list.filter((u) => u.score >= 70);
    else if (riskFilter === 'medium') list = list.filter((u) => u.score >= 30 && u.score < 70);
    else if (riskFilter === 'low') list = list.filter((u) => u.score < 30);

    const dir = sortDir === 'desc' ? -1 : 1;
    const sorted = [...list].sort((a, b) => {
      if (sortBy === 'url') return a.url.localeCompare(b.url) * dir;
      if (sortBy === 'scan_id') return (a.scan_id - b.scan_id) * dir;
      if (sortBy === 'date') {
        return (a.scanned_at || '').localeCompare(b.scanned_at || '') * dir;
      }
      return (a.score - b.score) * dir;
    });
    return sorted;
  }, [allUrls, search, riskFilter, sortBy, sortDir]);

  const riskPills: { label: string; value: RiskFilter; color: string }[] = [
    { label: 'All', value: 'all', color: 'var(--primary)' },
    { label: 'High Risk (≥70)', value: 'high', color: '#EF4444' },
    { label: 'Medium (30–69)', value: 'medium', color: '#F59E0B' },
    { label: 'Low (<30)', value: 'low', color: '#10B981' },
  ];

  return (
    <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* KPI Bar */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16 }}>
        <KpiCard title="Total URLs Analyzed" value={totalUrls} accent="var(--primary)" />
        <KpiCard title="High Risk URLs" value={highRisk} accent="#EF4444" />
        <KpiCard title="VT Flagged" value={vtFlagged} accent="#F59E0B" />
        {/* VT Status card */}
        <div style={{
          background: 'var(--bg-card)',
          border: `1px solid var(--border-default)`,
          borderLeft: `3px solid ${vtStatus.color}`,
          borderRadius: 8,
          padding: '16px 20px',
        }}>
          <p style={{ fontSize: '0.7rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>VT Status</p>
          <p className="font-mono" style={{ fontSize: '1rem', fontWeight: 700, color: vtStatus.color, lineHeight: 1.2 }}>{vtStatus.label}</p>
          <p style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginTop: 4 }}>{vtStatus.subtitle}</p>
        </div>
      </div>

      {/* Filter Bar */}
      <div style={{
        background: 'var(--bg-card)',
        border: '1px solid var(--border-default)',
        borderRadius: 8,
        padding: '14px 16px',
        display: 'flex',
        gap: 12,
        alignItems: 'center',
        flexWrap: 'wrap',
      }}>
        {/* Search */}
        <div style={{ position: 'relative', flex: 1, minWidth: 200 }}>
          <Search size={14} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)', pointerEvents: 'none' }} />
          <input
            className="dark-input"
            style={{ width: '100%', paddingLeft: 32 }}
            placeholder="Search URLs…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>

        {/* Risk pills */}
        <div style={{ display: 'flex', gap: 4 }}>
          {riskPills.map((p) => (
            <button
              key={p.value}
              onClick={() => setRiskFilter(p.value)}
              style={{
                padding: '4px 12px',
                fontSize: '0.72rem',
                fontWeight: 600,
                borderRadius: 12,
                border: `1px solid ${riskFilter === p.value ? p.color : 'var(--border-default)'}`,
                background: riskFilter === p.value ? `${p.color}20` : 'transparent',
                color: riskFilter === p.value ? p.color : 'var(--text-muted)',
                cursor: 'pointer',
                whiteSpace: 'nowrap',
              }}
            >
              {p.label}
            </button>
          ))}
        </div>

        {/* Sort */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>Sort:</span>
          <select
            className="dark-input"
            style={{ fontSize: '0.72rem', padding: '4px 8px' }}
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value as SortKey)}
          >
            <option value="score">Score</option>
            <option value="date">Date</option>
            <option value="url">URL</option>
            <option value="scan_id">Scan ID</option>
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
              fontSize: '0.7rem',
              fontWeight: 600,
              cursor: 'pointer',
              whiteSpace: 'nowrap',
            }}
          >
            {sortDir === 'desc' ? '↓ desc' : '↑ asc'}
          </button>
        </div>
      </div>

      {/* URL Table */}
      <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, overflow: 'hidden' }}>
        {loading ? (
          <div style={{ padding: 24 }}>
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="skeleton" style={{ height: 40, borderRadius: 4, marginBottom: 8 }} />
            ))}
          </div>
        ) : filtered.length === 0 ? (
          <div style={{ padding: 64, textAlign: 'center', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12 }}>
            <Link2 size={36} style={{ color: 'var(--text-muted)' }} />
            <p style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
              {allUrls.length === 0 ? 'No URL data yet' : 'No URLs match filters'}
            </p>
            <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>
              {allUrls.length === 0
                ? 'Run scans on emails to see URL analysis results here'
                : 'Try adjusting the search or risk filter'}
            </p>
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="dark-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr>
                  <th style={{ padding: '10px 12px', textAlign: 'left' }}>URL</th>
                  <th style={{ padding: '10px 12px', textAlign: 'left' }}>SCORE</th>
                  <th style={{ padding: '10px 12px', textAlign: 'left' }}>HEURISTIC</th>
                  <th style={{ padding: '10px 12px', textAlign: 'left' }}>VT DETECTIONS</th>
                  <th style={{ padding: '10px 12px', textAlign: 'left' }}>FLAGS</th>
                  <th style={{ padding: '10px 12px', textAlign: 'left' }}>SCAN ID</th>
                  <th style={{ padding: '10px 12px', textAlign: 'left' }}>TIME</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((entry) => {
                  const key = `${entry.url}::${entry.scan_id}`;
                  return (
                    <UrlRow
                      key={key}
                      entry={entry}
                      expanded={expandedUrl === key}
                      onExpand={() => setExpandedUrl(expandedUrl === key ? null : key)}
                    />
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {filtered.length > 0 && (
        <p style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textAlign: 'right' }}>
          Showing {filtered.length} of {allUrls.length} URLs · Click any row to expand details
        </p>
      )}
    </div>
  );
}
