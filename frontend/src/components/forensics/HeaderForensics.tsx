import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { FileSearch, Globe, ShieldCheck, ShieldX, ShieldQuestion, Radio, Code2, ChevronDown, ChevronRight } from 'lucide-react';
import { getHeaderEvidence, type HeaderEvidence, type AuthResults } from '../../api/forensics';

type AuthTone = 'pass' | 'fail' | 'neutral';

function authTone(result: string | null | undefined): AuthTone {
  if (!result) return 'neutral';
  const r = result.toLowerCase();
  if (r === 'pass' || r === 'softpass' || r === 'best') return 'pass';
  if (r === 'fail' || r === 'permerror' || r === 'hardfail') return 'fail';
  return 'neutral';
}

function AuthPill({ label, result, domain }: { label: string; result: string | null; domain?: string | null }) {
  const tone = authTone(result);
  const color = tone === 'pass' ? 'var(--safe)' : tone === 'fail' ? 'var(--danger)' : 'var(--text-muted)';
  const bg = tone === 'pass' ? 'var(--safe-subtle)' : tone === 'fail' ? 'var(--danger-subtle)' : 'var(--bg-input)';
  const Icon = tone === 'pass' ? ShieldCheck : tone === 'fail' ? ShieldX : ShieldQuestion;
  return (
    <div style={{ background: bg, border: `1px solid ${tone === 'neutral' ? 'var(--border-default)' : color}`, borderRadius: 6, padding: '8px 12px', minWidth: 120 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        <Icon size={13} style={{ color }} />
        <span style={{ fontSize: '0.65rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
          {label}
        </span>
      </div>
      <p style={{ fontSize: '0.85rem', fontWeight: 700, color, marginTop: 3 }}>
        {result || 'none'}
      </p>
      {domain && (
        <p className="font-mono" style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginTop: 2, wordBreak: 'break-all' }}>
          {domain}
        </p>
      )}
    </div>
  );
}

function AuthBlock({ auth }: { auth: AuthResults }) {
  const aligned = auth.alignment?.toLowerCase() === 'aligned';
  return (
    <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
      <AuthPill label="SPF" result={auth.spf_result} domain={auth.spf_domain} />
      <AuthPill label="DKIM" result={auth.dkim_result} domain={auth.dkim_domain} />
      <AuthPill label="DMARC" result={auth.dmarc_result} domain={auth.dmarc_domain} />
      <div style={{ background: 'var(--bg-input)', border: '1px solid var(--border-default)', borderRadius: 6, padding: '8px 12px', minWidth: 120 }}>
        <span style={{ fontSize: '0.65rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
          Alignment
        </span>
        <p style={{ fontSize: '0.85rem', fontWeight: 700, marginTop: 3, color: auth.alignment ? (aligned ? 'var(--safe)' : 'var(--danger)') : 'var(--text-muted)' }}>
          {auth.alignment || 'unknown'}
        </p>
      </div>
    </div>
  );
}

// ─── Weighted anomaly flags (plan §6.2, FE-C1) ────────────────────────────────

interface WeightedRule {
  rule: string;
  weight: number;
  detail: string;
}

function isWeightedRule(r: unknown): r is WeightedRule {
  return (
    !!r && typeof r === 'object' &&
    'rule' in r && 'weight' in r && 'detail' in r
  );
}

function weightTone(weight: number): string {
  if (weight >= 15) return 'var(--danger)';
  if (weight >= 8) return 'var(--warning)';
  return 'var(--text-muted)';
}

function WeightedFlags({ rules }: { rules: unknown[] }) {
  const fired = rules.filter(isWeightedRule);
  if (fired.length === 0) return null;
  const total = fired.reduce((sum, r) => sum + r.weight, 0);
  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginBottom: 6 }}>
        <p style={{ fontSize: '0.65rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
          Anomaly Flags
        </p>
        <span className="font-mono" style={{ fontSize: '0.65rem', color: total > 0 ? 'var(--danger)' : 'var(--text-muted)' }}>
          +{total} header score
        </span>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
        {fired.map((r, i) => (
          <div
            key={`${r.rule}-${i}`}
            style={{ display: 'flex', alignItems: 'baseline', gap: 8, background: 'var(--bg-input)', borderRadius: 4, padding: '5px 10px', fontSize: '0.72rem' }}
          >
            <span
              className="font-mono"
              style={{ fontWeight: 800, minWidth: 34, textAlign: 'right', color: weightTone(r.weight) }}
            >
              +{r.weight}
            </span>
            <span style={{ fontWeight: 700, color: 'var(--text-secondary)', minWidth: 160 }}>{r.rule}</span>
            <span style={{ color: 'var(--text-muted)', wordBreak: 'break-word' }}>{r.detail}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Raw header viewer (plan §6.2, FE-C1) ─────────────────────────────────────

function RawHeaderViewer({ headers }: { headers: Record<string, unknown> }) {
  const [open, setOpen] = useState(false);
  const [filter, setFilter] = useState('');

  const entries = Object.entries(headers);
  const needle = filter.trim().toLowerCase();
  const visible = needle
    ? entries.filter(([key, value]) =>
        key.toLowerCase().includes(needle) ||
        (Array.isArray(value)
          ? value.some((v) => String(v).toLowerCase().includes(needle))
          : String(value ?? '').toLowerCase().includes(needle)))
    : entries;

  return (
    <div style={{ border: '1px solid var(--border-subtle)', borderRadius: 6, overflow: 'hidden' }}>
      <div
        style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px', cursor: 'pointer', background: 'var(--bg-input)' }}
        onClick={() => setOpen((v) => !v)}
      >
        <Code2 size={13} style={{ color: 'var(--primary)' }} />
        <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-secondary)' }}>
          Raw Headers
        </span>
        <span className="font-mono" style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>
          {entries.length} field{entries.length !== 1 ? 's' : ''}
        </span>
        {open ? <ChevronDown size={13} style={{ color: 'var(--text-muted)', marginLeft: 'auto' }} /> : <ChevronRight size={13} style={{ color: 'var(--text-muted)', marginLeft: 'auto' }} />}
      </div>
      {open && (
        <div style={{ borderTop: '1px solid var(--border-subtle)' }}>
          <input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter headers (key or value)…"
            style={{ width: 'calc(100% - 20px)', margin: '8px 10px 4px', padding: '5px 9px', fontSize: '0.72rem', background: 'var(--bg-input)', border: '1px solid var(--border-default)', borderRadius: 4, color: 'var(--text-primary)' }}
          />
          <div style={{ maxHeight: 280, overflowY: 'auto', padding: '4px 10px 10px' }}>
            {visible.length === 0 && (
              <p style={{ fontSize: '0.72rem', color: 'var(--text-muted)', padding: '6px 0' }}>No headers match “{filter}”.</p>
            )}
            {visible.map(([key, value]) => {
              const values = Array.isArray(value) ? value.map(String) : [String(value ?? '')];
              return (
                <div key={key} style={{ padding: '5px 0', borderBottom: '1px solid var(--border-subtle)' }}>
                  <p className="font-mono" style={{ fontSize: '0.68rem', fontWeight: 700, color: 'var(--primary)' }}>{key}</p>
                  {values.map((v, i) => (
                    <p key={i} className="font-mono" style={{ fontSize: '0.68rem', color: 'var(--text-secondary)', wordBreak: 'break-all', whiteSpace: 'pre-wrap', marginTop: 2 }}>
                      {v}
                    </p>
                  ))}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Panel ────────────────────────────────────────────────────────────────────
interface HeaderForensicsProps {
  emailId: number;
  flags?: string[];
  /** Fired anomaly rules from `breakdown.header.rules` (FE-C1) */
  rules?: unknown[];
}

export function HeaderForensics({ emailId, flags = [], rules = [] }: HeaderForensicsProps) {
  const navigate = useNavigate();
  const [evidence, setEvidence] = useState<HeaderEvidence | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    getHeaderEvidence(emailId)
      .then((data) => { if (!cancelled) setEvidence(data); })
      .catch(() => { /* panel degrades to "unavailable" */ })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [emailId]);

  if (loading) {
    return (
      <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, padding: 20 }}>
        <div className="skeleton" style={{ height: 16, width: '30%', borderRadius: 4, marginBottom: 12 }} />
        <div className="skeleton" style={{ height: 56, borderRadius: 6 }} />
      </div>
    );
  }

  const present = evidence?.present ?? false;

  return (
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, overflow: 'hidden' }}>
      {/* Header */}
      <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <FileSearch size={16} style={{ color: 'var(--primary)' }} />
          <p style={{ fontSize: '0.875rem', fontWeight: 700, color: 'var(--text-primary)' }}>Header Forensics</p>
          {!present && (
            <span style={{ fontSize: '0.68rem', color: 'var(--text-warning)', background: 'var(--warning-subtle)', padding: '2px 8px', borderRadius: 4, fontWeight: 600 }}>
              raw retention unavailable
            </span>
          )}
        </div>
        <button
          className="btn-ghost"
          onClick={() => navigate(`/emails/${emailId}/trace`)}
          style={{ fontSize: '0.72rem', padding: '4px 10px', display: 'flex', alignItems: 'center', gap: 4 }}
        >
          <Radio size={12} /> Origin Trace
        </button>
      </div>

      <div style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 16 }}>
        {/* Auth results */}
        {evidence?.auth ? (
          <AuthBlock auth={evidence.auth} />
        ) : (
          <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
            No stored authentication results for this email.
          </p>
        )}

        {/* Anomaly flags with weights (FE-C1) — falls back to plain chips */}
        {rules.filter(isWeightedRule).length > 0 ? (
          <WeightedFlags rules={rules} />
        ) : (
          flags.length > 0 && (
            <div>
              <p style={{ fontSize: '0.65rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 6 }}>
                Header Flags
              </p>
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                {flags.map((f, i) => (
                  <span key={i} style={{ fontSize: '0.7rem', fontWeight: 600, padding: '3px 10px', borderRadius: 4, background: 'var(--danger-subtle)', color: 'var(--text-danger)', border: '1px solid rgba(239,68,68,0.3)' }}>
                    {f}
                  </span>
                ))}
              </div>
            </div>
          )
        )}

        {/* Hops summary */}
        {evidence && evidence.hops.length > 0 && (
          <div>
            <p style={{ fontSize: '0.65rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 6 }}>
              Received Chain — {evidence.hops.length} hop{evidence.hops.length !== 1 ? 's' : ''}
            </p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {evidence.hops.slice(0, 6).map((h) => (
                <div key={h.hop_index} style={{ display: 'flex', gap: 10, alignItems: 'baseline', fontSize: '0.72rem', background: 'var(--bg-input)', borderRadius: 4, padding: '5px 10px' }}>
                  <span className="font-mono" style={{ color: 'var(--text-muted)', minWidth: 22 }}>#{h.hop_index}</span>
                  <span className="font-mono" style={{ color: 'var(--text-secondary)', wordBreak: 'break-all' }}>
                    {h.from_host || '?'} {h.from_ip ? `[${h.from_ip}]` : ''}
                  </span>
                  <span style={{ color: 'var(--text-muted)' }}>→ {h.by_host || '?'}</span>
                  <span style={{ marginLeft: 'auto', fontSize: '0.62rem', fontWeight: 700, color: h.is_internal ? 'var(--primary)' : 'var(--text-muted)' }}>
                    {h.is_internal ? 'int' : 'ext'}
                  </span>
                </div>
              ))}
              {evidence.hops.length > 6 && (
                <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>
                  +{evidence.hops.length - 6} more — see Origin Trace
                </span>
              )}
            </div>
          </div>
        )}

        {/* Raw RFC822 header block (FE-C1) */}
        {present && evidence?.headers && (
          <RawHeaderViewer headers={evidence.headers} />
        )}

        {/* Evidence integrity */}
        {evidence?.raw_sha256 && (
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', fontSize: '0.68rem', color: 'var(--text-muted)' }}>
            <Globe size={11} />
            <span>raw sha256:</span>
            <code className="font-mono" style={{ background: 'var(--bg-input)', padding: '2px 6px', borderRadius: 3, wordBreak: 'break-all' }}>
              {evidence.raw_sha256}
            </code>
            {evidence.size_bytes != null && <span>· {evidence.size_bytes.toLocaleString()} bytes</span>}
          </div>
        )}

        {!present && (
          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', lineHeight: 1.5 }}>
            This email was ingested without raw header retention, so the full evidence
            is unavailable. Authentication results and verdict flags are still shown above.
          </p>
        )}
      </div>
    </div>
  );
}
