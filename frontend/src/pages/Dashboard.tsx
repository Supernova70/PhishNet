import { lazy, Suspense, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  TrendingUp,
  AlertTriangle,
  AlertCircle,
  ShieldCheck,
  ShieldAlert,
  Megaphone,
  Globe,
  Brain,
  Link2,
  Paperclip,
  Download,
} from 'lucide-react';
import { getEmails, getScans, exportScansCsv } from '../api/client';
import { getAlerts, getCampaigns, getIpStats, getAttributionStats, type AttributionStats } from '../api/forensics';
import { AttributionDonut } from '../components/charts/AttributionDonut';
import { useCountUp } from '../hooks/useCountUp';
import { ClassificationBadge, ScoreBadge } from '../components/ui/Badge';
import { ThreatTimeline } from '../components/charts/ThreatTimeline';
import { ClassificationDonut } from '../components/charts/ClassificationDonut';
import { formatDistanceToNow } from 'date-fns';
import type { Email, Scan } from '../types';

// Code-split the 3D globe (pulls in three.js) so the dashboard shell
// loads instantly and the globe chunk arrives in parallel.
const IpGlobe = lazy(() => import('../components/globe/IpGlobe'));

// ─── KPI Card ─────────────────────────────────────────────────────────────────
interface KpiCardProps {
  title: string;
  value: number;
  icon: React.ReactNode;
  iconColor: string;
  borderColor: string;
  glowColor: string;
  subtitle?: string;
  trend?: string;
  delay?: number;
}

function KpiCard({ title, value, icon, iconColor, borderColor, glowColor, subtitle, trend, delay = 0 }: KpiCardProps) {
  const count = useCountUp(value, 1200, delay);
  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay: delay / 1000, ease: 'easeOut' }}
      style={{
        background: 'var(--bg-card)',
        border: `1px solid var(--border-default)`,
        borderLeft: `3px solid ${borderColor}`,
        borderRadius: 8,
        padding: '20px',
        display: 'flex',
        flexDirection: 'column',
        gap: 8,
        boxShadow: `inset 0 0 30px ${glowColor}`,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
          {title}
        </span>
        <span style={{ color: iconColor }}>{icon}</span>
      </div>
      <span className="font-mono" style={{ fontSize: '2rem', fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1 }}>
        {count.toLocaleString()}
      </span>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{subtitle}</span>
        {trend && (
          <span style={{
            fontSize: '0.7rem',
            fontWeight: 600,
            color: trend.startsWith('+') ? 'var(--text-safe)' : 'var(--text-warning)',
            background: trend.startsWith('+') ? 'var(--safe-subtle)' : 'var(--warning-subtle)',
            padding: '1px 6px',
            borderRadius: 4,
          }}>
            {trend}
          </span>
        )}
      </div>
    </motion.div>
  );
}

// ─── Intel Strip ──────────────────────────────────────────────────────────────
interface IntelStripProps {
  spoofCount: number;
  openCampaigns: number;
  topCountries: Array<{ country: string | null; count: number }>;
  attribution: AttributionStats | null;
}

function IntelStrip({ spoofCount, openCampaigns, topCountries, attribution }: IntelStripProps) {
  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
        gap: 16,
        background: 'var(--bg-card)',
        border: '1px solid var(--border-default)',
        borderRadius: 8,
        padding: '14px 20px',
        alignItems: 'center',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <ShieldAlert size={16} style={{ color: 'var(--warning)' }} />
        <div>
          <p style={{ fontSize: '0.62rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Spoof / auth-fail alerts</p>
          <p className="font-mono" style={{ fontSize: '1.1rem', fontWeight: 700, color: spoofCount > 0 ? 'var(--warning)' : 'var(--text-primary)' }}>
            {spoofCount}
          </p>
        </div>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <Megaphone size={16} style={{ color: 'var(--primary)' }} />
        <div>
          <p style={{ fontSize: '0.62rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Open campaigns</p>
          <p className="font-mono" style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-primary)' }}>
            {openCampaigns}
          </p>
        </div>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, minWidth: 0 }}>
        <Globe size={16} style={{ color: 'var(--safe)', flexShrink: 0 }} />
        <div style={{ minWidth: 0 }}>
          <p style={{ fontSize: '0.62rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Top origin countries</p>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 3 }}>
            {topCountries.length === 0 ? (
              <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>no cached geo intel yet</span>
            ) : (
              topCountries.slice(0, 4).map((c, i) => (
                <span key={i} className="font-mono" style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', background: 'var(--bg-input)', padding: '2px 8px', borderRadius: 4 }}>
                  {c.country || 'unknown'} <span style={{ color: 'var(--text-muted)' }}>· {c.count}</span>
                </span>
              ))
            )}
          </div>
        </div>
      </div>
      {/* Attribution split donut (plan §6, FE-C5) */}
      <AttributionDonut stats={attribution} />
    </div>
  );
}

// ─── Skeleton ────────────────────────────────────────────────────────────────
function DashboardSkeleton() {
  return (
    <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 16 }}>
        {[0,1,2,3].map(i => (
          <div key={i} className="skeleton" style={{ height: 120, borderRadius: 8 }} />
        ))}
      </div>
      <div style={{ display: 'flex', gap: 16, height: 280 }}>
        <div className="skeleton" style={{ flex: 3, borderRadius: 8 }} />
        <div className="skeleton" style={{ flex: 2, borderRadius: 8 }} />
      </div>
      <div className="skeleton" style={{ height: 320, borderRadius: 8 }} />
    </div>
  );
}

// ─── Recent Activity Table ────────────────────────────────────────────────────
function RecentActivity({ scans, emails, onViewScan }: { scans: Scan[]; emails: Email[]; onViewScan: (id: number) => void }) {
  const recent = scans.slice(0, 15);
  const emailMap = new Map(emails.map((e) => [e.id, e]));

  if (recent.length === 0) {
    return (
      <div style={{ padding: 48, textAlign: 'center' }}>
        <ShieldCheck size={40} style={{ color: 'var(--safe)', margin: '0 auto 12px' }} />
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem' }}>No scan activity yet</p>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', marginTop: 4 }}>Run scans on emails to see results here</p>
      </div>
    );
  }

  return (
    <table className="dark-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
      <thead>
        <tr>
          <th>Email ID</th>
          <th>Sender</th>
          <th>Subject</th>
          <th>Score</th>
          <th>Classification</th>
          <th>Engines</th>
          <th>Time</th>
          <th>Action</th>
        </tr>
      </thead>
      <tbody>
        {recent.map((scan) => {
          const email = emailMap.get(scan.email_id);
          const v = scan.verdict;
          return (
            <tr
              key={scan.id}
              onClick={() => onViewScan(scan.id)}
              style={{
                borderLeft: v
                  ? `2px solid ${v.classification === 'dangerous' ? 'var(--danger)' : v.classification === 'suspicious' ? 'var(--warning)' : 'transparent'}`
                  : undefined,
                cursor: 'pointer',
                opacity: 1,
              }}
              onMouseEnter={(e) => ((e.currentTarget as HTMLTableRowElement).style.background = 'var(--bg-input)')}
              onMouseLeave={(e) => ((e.currentTarget as HTMLTableRowElement).style.background = '')}
            >
              <td>
                <span className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  #{scan.email_id}
                </span>
              </td>
              <td style={{ maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {email?.sender ?? '—'}
              </td>
              <td style={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--text-primary)' }}>
                {email?.subject ?? '(no subject)'}
              </td>
              <td>
                {v ? <ScoreBadge score={v.final_score} size="sm" /> : <span style={{ color: 'var(--text-muted)' }}>—</span>}
              </td>
              <td>
                {v ? <ClassificationBadge classification={v.classification} size="sm" /> : (
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{scan.status}</span>
                )}
              </td>
              <td>
                {v ? (
                  <div style={{ display: 'flex', gap: 6 }}>
                    <Brain size={14} style={{ color: (v.ai_score ?? 0) > 0 ? 'var(--safe)' : 'var(--text-muted)' }} />
                    <Link2 size={14} style={{ color: (v.url_score ?? 0) > 0 ? 'var(--safe)' : 'var(--text-muted)' }} />
                    <Paperclip size={14} style={{ color: (v.attachment_score ?? 0) > 0 ? 'var(--safe)' : 'var(--text-muted)' }} />
                  </div>
                ) : '—'}
              </td>
              <td style={{ whiteSpace: 'nowrap' }}>
                {scan.completed_at
                  ? formatDistanceToNow(new Date(scan.completed_at), { addSuffix: true })
                  : '—'}
              </td>
              <td>
                <button
                  onClick={(e) => { e.stopPropagation(); onViewScan(scan.id); }}
                  style={{
                    background: 'var(--primary-glow)',
                    border: '1px solid var(--primary)',
                    borderRadius: 4,
                    color: 'var(--primary)',
                    padding: '3px 10px',
                    fontSize: '0.75rem',
                    cursor: 'pointer',
                    fontWeight: 600,
                    whiteSpace: 'nowrap',
                  }}
                >
                  View Scan
                </button>
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

// ─── Dashboard Page ───────────────────────────────────────────────────────────
export function Dashboard() {
  const navigate = useNavigate();
  const [emails, setEmails] = useState<Email[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [spoofCount, setSpoofCount] = useState(0);
  const [openCampaigns, setOpenCampaigns] = useState(0);
  const [topCountries, setTopCountries] = useState<Array<{ country: string | null; count: number }>>([]);
  const [attribution, setAttribution] = useState<AttributionStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [e, s, intel] = await Promise.all([
        getEmails(0, 200),
        getScans(0, 200),
        Promise.allSettled([getAlerts(), getCampaigns('open'), getIpStats(), getAttributionStats()]),
      ]);
      setEmails(e);
      setScans(s);
      const [alertsR, campaignsR, statsR, attrR] = intel;
      if (alertsR.status === 'fulfilled') {
        setSpoofCount(alertsR.value.alerts.filter((a) => a.reasons.includes('spoof')).length);
      }
      if (campaignsR.status === 'fulfilled') setOpenCampaigns(campaignsR.value.length);
      if (statsR.status === 'fulfilled') setTopCountries(statsR.value.countries);
      if (attrR.status === 'fulfilled') setAttribution(attrR.value);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadData(); }, []);

  if (loading) return <DashboardSkeleton />;

  if (error) {
    return (
      <div style={{ padding: 24 }}>
        <div style={{ border: '1px solid var(--danger)', borderRadius: 8, background: 'var(--danger-subtle)', padding: 20, display: 'flex', gap: 12, alignItems: 'flex-start' }}>
          <AlertCircle size={20} style={{ color: 'var(--danger)', flexShrink: 0 }} />
          <div>
            <p style={{ fontWeight: 600, color: 'var(--text-danger)' }}>Failed to load dashboard</p>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>{error}</p>
            <button className="btn-ghost" onClick={loadData} style={{ marginTop: 12, fontSize: '0.8rem' }}>Retry</button>
          </div>
        </div>
      </div>
    );
  }

  const completedScans = scans.filter((s) => s.status === 'complete' && s.verdict);
  const threatsCount = completedScans.filter((s) => s.verdict?.classification === 'dangerous').length;
  const suspiciousCount = completedScans.filter((s) => s.verdict?.classification === 'suspicious').length;
  const safeCount = completedScans.filter((s) => s.verdict?.classification === 'safe').length;

  return (
    <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* KPI Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16 }}>
        <KpiCard title="Total Emails" value={emails.length} icon={<TrendingUp size={18} />} iconColor="var(--primary)" borderColor="var(--primary)" glowColor="var(--primary-glow)" subtitle="All fetched emails" trend="+12% vs yesterday" delay={0} />
        <KpiCard title="Threats Detected" value={threatsCount} icon={<AlertTriangle size={18} />} iconColor="var(--danger)" borderColor="var(--danger)" glowColor="var(--danger-glow)" subtitle="High-risk classification" trend={threatsCount > 0 ? `+${threatsCount}` : '0 new'} delay={80} />
        <KpiCard title="Suspicious" value={suspiciousCount} icon={<AlertCircle size={18} />} iconColor="var(--warning)" borderColor="var(--warning)" glowColor="var(--warning-glow)" subtitle="Requires investigation" delay={160} />
        <KpiCard title="Clean" value={safeCount} icon={<ShieldCheck size={18} />} iconColor="var(--safe)" borderColor="var(--safe)" glowColor="var(--safe-glow)" subtitle="Safe classification" delay={240} />
      </div>

      {/* Forensics intel strip */}
      <IntelStrip spoofCount={spoofCount} openCampaigns={openCampaigns} topCountries={topCountries} attribution={attribution} />

      {/* Timeline + Donut */}
      <div style={{ display: 'flex', gap: 16, height: 280 }}>
        <div style={{ flex: 3, background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, padding: '16px 16px 8px', minWidth: 0 }}>
          <p style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: 12, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Threat Timeline — Last 7 Days
          </p>
          <div style={{ height: 210, minWidth: 0 }}>
            <ThreatTimeline scans={scans} />
          </div>
        </div>
        <div style={{ flex: 2, background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, padding: '16px', minWidth: 0 }}>
          <p style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: 12, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Classification Breakdown
          </p>
          <div style={{ height: 210, minWidth: 0 }}>
            <ClassificationDonut scans={scans} />
          </div>
        </div>
      </div>

      {/* 3D threat globe */}
      <Suspense
        fallback={
          <div
            style={{
              height: 500,
              background: 'var(--bg-card)',
              border: '1px solid var(--border-default)',
              borderRadius: 8,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '0.8rem',
              color: 'var(--text-muted)',
            }}
          >
            Loading globe…
          </div>
        }
      >
        <IpGlobe />
      </Suspense>

      {/* Recent Activity */}
      <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, overflow: 'hidden' }}>
        <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <p style={{ fontSize: '0.875rem', fontWeight: 700, color: 'var(--text-primary)' }}>Recent Scan Activity</p>
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              className="btn-ghost"
              onClick={async () => {
                try { await exportScansCsv(); } catch { /* silent */ }
              }}
              style={{ fontSize: '0.75rem', padding: '4px 12px', display: 'flex', alignItems: 'center', gap: 4 }}
            >
              <Download size={12} />
              Export CSV
            </button>
            <button className="btn-ghost" onClick={() => navigate('/scans')} style={{ fontSize: '0.75rem', padding: '4px 12px' }}>
              View All
            </button>
          </div>
        </div>
        <div style={{ overflowX: 'auto' }}>
          <RecentActivity scans={scans} emails={emails} onViewScan={(id) => navigate(`/scans/${id}`)} />
        </div>
      </div>
    </div>
  );
}
