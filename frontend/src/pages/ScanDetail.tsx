import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { ArrowLeft, Brain, Link2, Paperclip, ExternalLink, AlertTriangle, ChevronDown, ChevronRight, ShieldAlert, FileText } from 'lucide-react';
import { getScan, getEmail, resolveScreenshotUrl, getThreatSummary, type ThreatSummary } from '../api/client';
import { ClassificationBadge, ScoreBadge } from '../components/ui/Badge';
import { ScoreBar } from '../components/ui/ScoreBar';
import { ScoreGauge } from '../components/ui/ScoreGauge';
import { JsonViewer } from '../components/ui/JsonViewer';
import { HeaderForensics } from '../components/forensics/HeaderForensics';
import { formatDistanceToNow, format } from 'date-fns';
import type { Scan, EmailDetail, ScanBreakdown } from '../types';
import { getVtUrlLink, getVtFileLink } from '../utils/virustotal';

// ─── Verdict Hero ─────────────────────────────────────────────────────────────
function VerdictHero({ scan }: { scan: Scan }) {
  const v = scan.verdict!;
  const cls = v.classification;
  const isDangerous = cls === 'dangerous';
  const isSuspicious = cls === 'suspicious';

  const bgColor = isDangerous ? 'var(--danger-subtle)' : isSuspicious ? 'var(--warning-subtle)' : 'var(--safe-subtle)';
  const borderColor = isDangerous ? 'var(--danger)' : isSuspicious ? 'var(--warning)' : 'var(--safe)';
  const textColor = isDangerous ? 'var(--danger)' : isSuspicious ? 'var(--warning)' : 'var(--safe)';
  const animClass = isDangerous ? 'animate-pulse-danger' : isSuspicious ? 'animate-pulse-warning' : '';

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.97 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.4 }}
      className={animClass}
      style={{
        background: bgColor,
        border: `1px solid ${borderColor}`,
        borderRadius: 8,
        padding: '28px 32px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: 24,
      }}
    >
      <div>
        <p style={{ fontSize: '0.7rem', fontWeight: 700, letterSpacing: '0.14em', color: textColor, textTransform: 'uppercase', marginBottom: 8 }}>
          Final Verdict
        </p>
        <div style={{ display: 'flex', alignItems: 'baseline', gap: 16 }}>
          <span style={{ fontSize: '3.5rem', fontWeight: 900, color: textColor, letterSpacing: '-0.02em', lineHeight: 1, textTransform: 'uppercase' }}>
            {cls}
          </span>
          <span className="font-mono" style={{ fontSize: '4.5rem', fontWeight: 700, color: textColor, lineHeight: 1, filter: `drop-shadow(0 0 20px ${borderColor}80)` }}>
            {v.final_score.toFixed(1)}
          </span>
        </div>
        <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: 10 }}>
          {scan.completed_at ? `Scanned ${formatDistanceToNow(new Date(scan.completed_at), { addSuffix: true })}` : 'Scan in progress'}
        </p>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 8 }}>
        <span className="font-mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)', background: 'var(--bg-input)', padding: '3px 8px', borderRadius: 4 }}>
          SCAN #{scan.id}
        </span>
        <ClassificationBadge classification={cls} />
      </div>
    </motion.div>
  );
}

// ─── Engine Card ──────────────────────────────────────────────────────────────
function EngineCard({ name, score, icon, children }: { name: string; score: number; icon: React.ReactNode; children?: React.ReactNode }) {
  const label = score >= 70 ? 'HIGH RISK' : score >= 30 ? 'MEDIUM RISK' : 'CLEAN';
  const color = score >= 70 ? 'var(--danger)' : score >= 30 ? 'var(--warning)' : 'var(--safe)';

  return (
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{ color }}>{icon}</span>
        <p style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>{name}</p>
      </div>
      <div style={{ display: 'flex', justifyContent: 'center' }}>
        <ScoreGauge score={score} size={130} />
      </div>
      <div style={{ textAlign: 'center' }}>
        <span style={{
          fontSize: '0.7rem',
          fontWeight: 700,
          letterSpacing: '0.1em',
          color,
          background: score >= 70 ? 'var(--danger-subtle)' : score >= 30 ? 'var(--warning-subtle)' : 'var(--safe-subtle)',
          padding: '3px 10px',
          borderRadius: 4,
        }}>
          {label}
        </span>
      </div>
      {children}
    </div>
  );
}

// ─── URL Row ──────────────────────────────────────────────────────────────────
function UrlRow({ urlEntry }: { urlEntry: ScanBreakdown['url']['per_url'][0] }) {
  const [expanded, setExpanded] = useState(false);
  const { url, score, top_flags, flags, vt_malicious } = urlEntry;
  const displayFlags = top_flags ?? flags ?? [];
  const screenshotUrl = resolveScreenshotUrl(
    urlEntry.screenshot_url,
    urlEntry.playwright_screenshot_path,
  );

  return (
    <div style={{ borderBottom: '1px solid var(--border-subtle)' }}>
      <div
        onClick={() => setExpanded((e) => !e)}
        style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 16px', cursor: 'pointer', transition: 'background 200ms' }}
        onMouseEnter={(e) => (e.currentTarget as HTMLDivElement).style.background = 'var(--bg-input)'}
        onMouseLeave={(e) => (e.currentTarget as HTMLDivElement).style.background = 'transparent'}
      >
        {expanded ? <ChevronDown size={13} style={{ color: 'var(--text-muted)', flexShrink: 0 }} /> : <ChevronRight size={13} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />}
        <span className="font-mono" style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {url}
        </span>
        <ScoreBadge score={score} size="sm" />
        {vt_malicious > 0 && (
          <span style={{ fontSize: '0.7rem', background: 'var(--danger-subtle)', color: 'var(--text-danger)', padding: '2px 6px', borderRadius: 4 }}>
            {vt_malicious} VT hits
          </span>
        )}
      </div>
      {expanded && (
        <div style={{ padding: '12px 32px 16px', background: 'var(--bg-input)' }}>
          <p className="font-mono" style={{ fontSize: '0.72rem', color: 'var(--text-muted)', wordBreak: 'break-all', marginBottom: 12 }}>{url}</p>
          {displayFlags.length > 0 && (
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 10 }}>
              {displayFlags.map((flag, i) => (
                <span key={i} style={{
                  fontSize: '0.7rem',
                  fontWeight: 600,
                  padding: '2px 8px',
                  borderRadius: 4,
                  background: 'var(--danger-subtle)',
                  color: 'var(--text-danger)',
                  border: '1px solid rgba(239,68,68,0.3)',
                }}>
                  {flag}
                </span>
              ))}
            </div>
          )}
          {urlEntry.vt_error && (
            <p style={{ color: 'var(--text-warning)', fontSize: '0.72rem', marginBottom: 10 }}>
              VirusTotal: {urlEntry.vt_error}
            </p>
          )}
          {urlEntry.dynamic_status && (
            <p style={{ color: 'var(--text-muted)', fontSize: '0.72rem', marginBottom: 10 }}>
              Browser analysis: {urlEntry.dynamic_status}
              {urlEntry.final_url ? ` · Final URL: ${urlEntry.final_url}` : ''}
            </p>
          )}
          {screenshotUrl && (
            <a
              href={screenshotUrl}
              target="_blank"
              rel="noreferrer noopener"
              onClick={(e) => e.stopPropagation()}
              style={{ display: 'block', marginBottom: 12 }}
            >
              <img
                src={screenshotUrl}
                alt={`Browser evidence for ${url}`}
                loading="lazy"
                style={{ width: '100%', maxWidth: 720, borderRadius: 6, border: '1px solid var(--border-default)' }}
              />
            </a>
          )}
          <a
            href={getVtUrlLink(url)}
            target="_blank"
            rel="noreferrer noopener"
            onClick={(e) => e.stopPropagation()}
            style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: '0.75rem', color: 'var(--primary)', textDecoration: 'none' }}
          >
            <ExternalLink size={12} /> Open in VirusTotal ↗
          </a>
        </div>
      )}
    </div>
  );
}

// ─── YARA Match Card ──────────────────────────────────────────────────────────
function YaraMatchCard({ match }: { match: {
  rule: string;
  severity: string;
  tags: string[];
  description: string;
  explanation?: string;
  matched_strings?: string[];
  evidence?: Array<{ string: string; offset: number; preview: string; count: number }>;
} }) {
  return (
    <div style={{
      background: 'var(--danger-subtle)',
      border: '1px solid rgba(239,68,68,0.3)',
      borderRadius: 6,
      padding: '10px 14px',
      display: 'flex',
      gap: 10,
      alignItems: 'flex-start',
    }}>
      <AlertTriangle size={14} style={{ color: 'var(--danger)', flexShrink: 0, marginTop: 2 }} />
      <div style={{ minWidth: 0, flex: 1 }}>
        <p className="font-mono" style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-danger)' }}>{match.rule}</p>
        <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: 2 }}>{match.description}</p>
        {match.explanation && (
          <p style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontStyle: 'italic', marginTop: 4 }}>
            {match.explanation}
          </p>
        )}
        {match.evidence && match.evidence.length > 0 && (
          <div style={{ marginTop: 8, display: 'flex', flexDirection: 'column', gap: 3 }}>
            <p style={{ fontSize: '0.65rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              Matched evidence
            </p>
            {match.evidence.map((ev, i) => (
              <p key={i} className="font-mono" style={{
                fontSize: '0.7rem',
                color: 'var(--text-secondary)',
                background: 'var(--bg-input)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 4,
                padding: '3px 8px',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
              }}>
                {ev.string} @ 0x{ev.offset.toString(16)}{' · '}{ev.count}×{' · '}“{ev.preview}”
              </p>
            ))}
          </div>
        )}
        <div style={{ display: 'flex', gap: 4, marginTop: 6, flexWrap: 'wrap' }}>
          <span style={{ fontSize: '0.65rem', background: 'rgba(239,68,68,0.2)', color: 'var(--text-danger)', padding: '1px 6px', borderRadius: 3, fontWeight: 700 }}>
            {match.severity.toUpperCase()}
          </span>
          {match.tags.map((t, i) => (
            <span key={i} style={{ fontSize: '0.65rem', background: 'var(--bg-input)', color: 'var(--text-muted)', padding: '1px 6px', borderRadius: 3 }}>{t}</span>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── AI Threat Summary Card ───────────────────────────────────────────────────
function ThreatSummaryCard({ scanId }: { scanId: number }) {
  const [summary, setSummary] = useState<ThreatSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getThreatSummary(scanId)
      .then(setSummary)
      .catch((err) => setError(err instanceof Error ? err.message : 'Failed to load'))
      .finally(() => setLoading(false));
  }, [scanId]);

  if (loading) {
    return (
      <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, padding: 20 }}>
        <div className="skeleton" style={{ height: 16, width: '30%', borderRadius: 4, marginBottom: 12 }} />
        <div className="skeleton" style={{ height: 12, width: '100%', borderRadius: 4, marginBottom: 8 }} />
        <div className="skeleton" style={{ height: 12, width: '80%', borderRadius: 4 }} />
      </div>
    );
  }

  if (error || !summary) return null;

  const borderColor = summary.classification === 'dangerous'
    ? 'var(--danger)' : summary.classification === 'suspicious'
    ? 'var(--warning)' : 'var(--safe)';

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      style={{
        background: 'var(--bg-card)',
        border: `1px solid ${borderColor}`,
        borderRadius: 8,
        padding: 24,
        display: 'flex',
        flexDirection: 'column',
        gap: 16,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <ShieldAlert size={20} style={{ color: borderColor }} />
        <p style={{ fontSize: '0.9rem', fontWeight: 700, color: 'var(--text-primary)' }}>
          AI Threat Analysis
        </p>
      </div>

      {/* Summary Paragraph */}
      <p style={{
        fontSize: '0.875rem',
        color: 'var(--text-secondary)',
        lineHeight: 1.7,
        background: 'var(--bg-input)',
        borderLeft: `3px solid ${borderColor}`,
        padding: '12px 16px',
        borderRadius: '0 6px 6px 0',
      }}>
        {summary.summary}
      </p>

      {/* Key Findings */}
      {summary.key_findings.length > 0 && (
        <div>
          <p style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>
            Key Findings
          </p>
          <ul style={{ display: 'flex', flexDirection: 'column', gap: 6, paddingLeft: 0, listStyle: 'none' }}>
            {summary.key_findings.map((finding, i) => (
              <li key={i} style={{
                fontSize: '0.8rem',
                color: 'var(--text-secondary)',
                padding: '6px 10px',
                background: 'var(--bg-input)',
                borderRadius: 4,
                borderLeft: '2px solid var(--primary)',
              }}>
                {finding}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Risk Factors */}
      {summary.risk_factors.length > 0 && (
        <div>
          <p style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>
            Risk Factors
          </p>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {summary.risk_factors.map((rf, i) => (
              <span key={i} style={{
                fontSize: '0.7rem',
                fontWeight: 600,
                padding: '3px 10px',
                borderRadius: 4,
                background: rf.severity === 'high' ? 'var(--danger-subtle)' : 'var(--warning-subtle)',
                color: rf.severity === 'high' ? 'var(--text-danger)' : 'var(--text-warning)',
                border: `1px solid ${rf.severity === 'high' ? 'rgba(239,68,68,0.3)' : 'rgba(245,158,11,0.3)'}`,
              }}>
                {rf.engine}: {rf.detail}
              </span>
            ))}
          </div>
        </div>
      )}
    </motion.div>
  );
}

// ─── Scan Detail Page ─────────────────────────────────────────────────────────
export function ScanDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [scan, setScan] = useState<Scan | null>(null);
  const [email, setEmail] = useState<EmailDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    queueMicrotask(() => setLoading(true));
    getScan(Number(id))
      .then(async (s) => {
        setScan(s);
        try {
          const em = await getEmail(s.email_id);
          setEmail(em);
        } catch {
          /* email context is optional — scan still renders */
        }
      })
      .catch((err: unknown) => setError(err instanceof Error ? err.message : 'Failed to load scan'))
      .finally(() => setLoading(false));
  }, [id]);

  if (loading) {
    return (
      <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 20 }}>
        {[140, 300, 200, 240].map((h, i) => <div key={i} className="skeleton" style={{ height: h, borderRadius: 8 }} />)}
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div style={{ padding: 24 }}>
        <div style={{ border: '1px solid var(--danger)', borderRadius: 8, background: 'var(--danger-subtle)', padding: 20 }}>
          <p style={{ color: 'var(--text-danger)', fontWeight: 600 }}>{error ?? 'Scan not found'}</p>
          <button className="btn-ghost" onClick={() => navigate('/scans')} style={{ marginTop: 12, fontSize: '0.8rem' }}>← Back to Scans</button>
        </div>
      </div>
    );
  }

  const v = scan.verdict;
  const bd = v?.breakdown;

  return (
    <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 20, maxWidth: 1100 }}>
      {/* Back */}
      <button className="btn-ghost" onClick={() => navigate('/scans')} style={{ width: 'fit-content', fontSize: '0.8rem' }}>
        <ArrowLeft size={14} /> Back to Results
      </button>

      {/* Verdict Hero */}
      {v ? <VerdictHero scan={scan} /> : (
        <div style={{ padding: 32, background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, textAlign: 'center' }}>
          <p style={{ color: 'var(--text-muted)' }}>Scan status: <strong style={{ color: 'var(--text-primary)', textTransform: 'capitalize' }}>{scan.status}</strong></p>
        </div>
      )}

      {/* AI Threat Summary */}
      {v && <ThreatSummaryCard scanId={scan.id} />}

      {/* Email Info */}
      {email && (
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, padding: '16px 20px' }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
            <div>
              <p style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>Email Details</p>
              <p style={{ fontSize: '0.875rem', fontWeight: 700, color: 'var(--text-primary)' }}>{email.subject}</p>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: 4 }}>From: {email.sender} · {email.date ? format(new Date(email.date), 'PPpp') : '—'}</p>
            </div>
            <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
              <button
                className="btn-ghost"
                onClick={() => navigate(`/scans/${scan.id}/report`)}
                style={{ fontSize: '0.72rem', padding: '5px 12px', display: 'flex', alignItems: 'center', gap: 4 }}
              >
                <FileText size={12} /> Forensic Report
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Header forensics */}
      <HeaderForensics emailId={scan.email_id} flags={bd?.header?.flags ?? []} rules={bd?.header?.rules ?? []} />

      {/* Engine Breakdown */}
      {v && (
        <>
          <div>
            <p style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 12 }}>Engine Analysis</p>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16 }}>
              <EngineCard name="ML Engine" score={v.ai_score ?? 0} icon={<Brain size={16} />}>
                {bd?.ai && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 4 }}>
                    <ScoreBar score={bd.ai.score} label="Confidence" />
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Label:</span>
                      <span style={{ fontSize: '0.75rem', fontWeight: 700, color: bd.ai.is_phishing ? 'var(--text-danger)' : 'var(--text-safe)' }}>
                        {bd.ai.is_phishing ? 'Phishing' : 'Legitimate'}
                      </span>
                    </div>
                  </div>
                )}
              </EngineCard>
              <EngineCard name="URL Engine" score={v.url_score ?? 0} icon={<Link2 size={16} />}>
                {bd?.url && (
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'flex', flexDirection: 'column', gap: 4 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span>Total URLs</span><span className="font-mono" style={{ color: 'var(--text-primary)' }}>{bd.url.total_urls}</span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span>High Risk</span><span className="font-mono" style={{ color: 'var(--text-danger)' }}>{bd.url.high_risk_urls.length}</span>
                    </div>
                  </div>
                )}
              </EngineCard>
              <EngineCard name="Attachment Engine" score={v.attachment_score ?? 0} icon={<Paperclip size={16} />}>
                {bd?.attachment && (
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'flex', flexDirection: 'column', gap: 4 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span>Files</span><span className="font-mono" style={{ color: 'var(--text-primary)' }}>{bd.attachment.total_files}</span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span>High Risk</span><span className="font-mono" style={{ color: 'var(--text-danger)' }}>{bd.attachment.high_risk_files.length}</span>
                    </div>
                  </div>
                )}
              </EngineCard>
            </div>
          </div>

          {/* URL Analysis */}
          {bd?.url && bd.url.per_url.length > 0 && (
            <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, overflow: 'hidden' }}>
              <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', alignItems: 'center', gap: 8 }}>
                <Link2 size={16} style={{ color: 'var(--primary)' }} />
                <p style={{ fontSize: '0.875rem', fontWeight: 700, color: 'var(--text-primary)' }}>URL Analysis</p>
                <span className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginLeft: 4 }}>{bd.url.per_url.length} URL{bd.url.per_url.length !== 1 ? 's' : ''}</span>
              </div>
              {/* Table header */}
              <div style={{ display: 'flex', gap: 12, padding: '8px 16px', background: 'var(--bg-input)', borderBottom: '1px solid var(--border-subtle)' }}>
                {['URL', 'Score', 'VT Hits'].map((h) => (
                  <span key={h} style={{ fontSize: '0.65rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{h}</span>
                ))}
              </div>
              {bd.url.per_url.map((urlEntry, i) => <UrlRow key={i} urlEntry={urlEntry} />)}
            </div>
          )}

          {/* Attachment Analysis */}
          {bd?.attachment && bd.attachment.per_file.length > 0 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <p style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                <Paperclip size={13} style={{ display: 'inline', marginRight: 6 }} />
                Attachment Analysis
              </p>
              {bd.attachment.per_file.map((file, i) => (
                <div key={i} style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, padding: 20 }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
                    <div>
                      <p style={{ fontSize: '0.875rem', fontWeight: 700, color: 'var(--text-primary)' }}>{file.filename}</p>
                      <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 2 }}>{file.file_type}</p>
                    </div>
                    <ScoreBadge score={file.risk_score} />
                  </div>
                  <ScoreBar score={file.risk_score} label="Risk Score" />

                  {/* Why this score — explainable breakdown */}
                  {(file.score_breakdown?.length ?? 0) > 0 && (
                    <div style={{ marginTop: 12, padding: '10px 12px', background: 'var(--bg-input)', borderRadius: 6, border: '1px solid var(--border-subtle)' }}>
                      <p style={{ fontSize: '0.65rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>
                        Why this score
                      </p>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                        {file.score_breakdown!.map((entry, k) => (
                          <div key={k} style={{ display: 'flex', gap: 8, alignItems: 'baseline' }}>
                            <span className="font-mono" style={{
                              fontSize: '0.7rem', fontWeight: 700, flexShrink: 0, minWidth: 44, textAlign: 'right',
                              color: entry.points >= 60 ? '#EF4444' : entry.points >= 25 ? '#F59E0B' : 'var(--text-muted)',
                            }}>
                              +{entry.points}
                            </span>
                            <div style={{ minWidth: 0 }}>
                              <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-primary)' }}>{entry.signal}</span>
                              {entry.detail && (
                                <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}> — {entry.detail}</span>
                              )}
                              {entry.evidence && entry.evidence.length > 0 && (
                                <div style={{ marginTop: 3, display: 'flex', flexDirection: 'column', gap: 2 }}>
                                  {entry.evidence.map((ev, ei) => (
                                    <p key={ei} className="font-mono" style={{
                                      fontSize: '0.68rem', color: 'var(--text-secondary)',
                                      overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                                    }}>{ev}</p>
                                  ))}
                                </div>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Embedded URLs (metadata vs payload) */}
                  {(file.embedded_urls?.length ?? 0) > 0 && (
                    <div style={{ marginTop: 12 }}>
                      <p style={{ fontSize: '0.65rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 4 }}>
                        Embedded URLs ({file.embedded_urls!.length})
                      </p>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                        {file.embedded_urls!.map((u, ui) => (
                          <p key={ui} className="font-mono" style={{
                            fontSize: '0.68rem', color: 'var(--text-secondary)',
                            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                          }}>{u}</p>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* VT Hash Results */}
                  {(file.vt_total ?? 0) > 0 && (
                    <div style={{ marginTop: 12, padding: '8px 12px', background: 'var(--bg-input)', borderRadius: 6, border: '1px solid var(--border-subtle)' }}>
                      <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 600 }}>VT Hash Check: </span>
                      <span style={{
                        fontFamily: 'JetBrains Mono, monospace',
                        fontSize: '0.72rem',
                        color: (file.vt_malicious ?? 0) > 0 ? '#EF4444' : '#10B981',
                        fontWeight: 700,
                      }}>
                        {(file.vt_malicious ?? 0) > 0
                          ? `${file.vt_malicious} malicious · ${file.vt_suspicious ?? 0} suspicious`
                          : `Clean (${file.vt_total} engines checked)`
                        }
                      </span>
                    </div>
                  )}

                  {/* VT Error */}
                  {file.vt_error && (
                    <div style={{ fontSize: '0.72rem', color: '#FCD34D', marginTop: 8, display: 'flex', alignItems: 'center', gap: 4 }}>
                      ⚠ VT: {file.vt_error}
                    </div>
                  )}

                  {/* Open in VirusTotal (file hash link) */}
                  {file.sha256 && (
                    <div style={{ marginTop: 10 }}>
                      <a
                        href={getVtFileLink(file.sha256)}
                        target="_blank"
                        rel="noopener noreferrer"
                        style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: 4,
                          color: '#3B82F6',
                          fontSize: '0.75rem',
                          textDecoration: 'none',
                          fontWeight: 600,
                        }}
                      >
                        <ExternalLink size={12} />
                        Open in VirusTotal ↗
                      </a>
                    </div>
                  )}

                  {file.yara_matches.length > 0 && (
                    <div style={{ marginTop: 16, display: 'flex', flexDirection: 'column', gap: 8 }}>
                      <p style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                        YARA Matches ({file.yara_matches.length})
                      </p>
                      {file.yara_matches.map((m, j) => <YaraMatchCard key={j} match={m} />)}
                    </div>
                  )}

                  {file.findings.length > 0 && (
                    <div style={{ marginTop: 14 }}>
                      <p style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 6 }}>Findings</p>
                      <ul style={{ paddingLeft: 16, display: 'flex', flexDirection: 'column', gap: 4 }}>
                        {file.findings.map((f, j) => (
                          <li key={j} style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{f}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* Raw Breakdown */}
          {v.breakdown && <JsonViewer data={v.breakdown} title="Raw Breakdown JSON" />}
        </>
      )}
    </div>
  );
}
