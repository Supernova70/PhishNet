import { useCallback, useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
  ArrowLeft,
  FileText,
  Download,
  Fingerprint,
  Link2,
  Radio,
  FileSearch,
  ScrollText,
  CheckCircle2,
  AlertTriangle,
  Printer,
  FileJson,
} from 'lucide-react';
import { getReport, type ForensicReport } from '../api/forensics';
import { ClassificationBadge, ScoreBadge } from '../components/ui/Badge';
import { format } from 'date-fns';

function Section({ title, icon, children }: { title: string; icon: React.ReactNode; children: React.ReactNode }) {
  return (
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, overflow: 'hidden' }}>
      <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{ color: 'var(--primary)', display: 'flex' }}>{icon}</span>
        <p style={{ fontSize: '0.875rem', fontWeight: 700, color: 'var(--text-primary)' }}>{title}</p>
      </div>
      <div style={{ padding: 16 }}>{children}</div>
    </div>
  );
}

function Field({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div>
      <p style={{ fontSize: '0.62rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{label}</p>
      <p className={mono ? 'font-mono' : undefined} style={{ fontSize: '0.8rem', color: 'var(--text-primary)', marginTop: 2, wordBreak: 'break-word' }}>
        {value ?? '—'}
      </p>
    </div>
  );
}

export function ReportPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [data, setData] = useState<ForensicReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [exporting, setExporting] = useState(false);
  const [exported, setExported] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async (doExport: boolean) => {
    if (!id) return;
    try {
      setError(null);
      const result = await getReport(Number(id), doExport);
      setData(result);
      if (doExport) setExported(result.integrity.report_sha256);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load report');
    } finally {
      setLoading(false);
      setExporting(false);
    }
  }, [id]);

  useEffect(() => {
    queueMicrotask(() => load(false));
  }, [load]);

  const handleExport = () => {
    setExporting(true);
    void load(true);
  };

  if (loading) {
    return (
      <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 16 }}>
        {[120, 220, 260, 200].map((h, i) => <div key={i} className="skeleton" style={{ height: h, borderRadius: 8 }} />)}
      </div>
    );
  }

  if (error || !data) {
    return (
      <div style={{ padding: 24 }}>
        <div style={{ border: '1px solid var(--danger)', borderRadius: 8, background: 'var(--danger-subtle)', padding: 20 }}>
          <p style={{ color: 'var(--text-danger)', fontWeight: 600 }}>{error ?? 'Report not found'}</p>
          <button className="btn-ghost" onClick={() => navigate('/scans')} style={{ marginTop: 12, fontSize: '0.8rem' }}>
            <ArrowLeft size={14} /> Back to Scans
          </button>
        </div>
      </div>
    );
  }

  const { report, integrity } = data;
  const v = report.verdict;

  // Plan §6.6 (FE-C3): print-friendly page + JSON export
  const handlePrint = () => {
    // The browser's PDF save dialog derives the filename from the page
    // title — build a unique, self-explanatory one for the print run.
    const prevTitle = document.title;
    const subject = (report.email.subject || '')
      .replace(/[\\/:*?"<>|]+/g, ' ')
      .replace(/\s+/g, ' ')
      .trim()
      .slice(0, 60);
    const cls = v?.classification ? `-${v.classification}` : '';
    document.title = subject
      ? `Phishing-Guard-report-scan-${report.scan.id}${cls}-${subject}`
      : `Phishing-Guard-report-scan-${report.scan.id}${cls}`;
    window.print();
    setTimeout(() => { document.title = prevTitle; }, 500);
  };

  const handleExportJson = () => {
    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `phishnet-report-scan-${report.scan.id}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 20, maxWidth: 1000 }}>
      {/* Top bar */}
      <div className="no-print" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
        <button className="btn-ghost" onClick={() => navigate(`/scans/${report.scan.id}`)} style={{ fontSize: '0.8rem' }}>
          <ArrowLeft size={14} /> Back to Scan
        </button>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <span className="font-mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)', background: 'var(--bg-input)', padding: '3px 8px', borderRadius: 4 }}>
            REPORT · SCAN #{report.scan.id}
          </span>
          <button className="btn-ghost" onClick={handlePrint} title="Print or save as PDF" style={{ fontSize: '0.75rem', padding: '6px 14px', display: 'flex', alignItems: 'center', gap: 5 }}>
            <Printer size={13} />
            Print / PDF
          </button>
          <button className="btn-ghost" onClick={handleExportJson} title="Download report as JSON" style={{ fontSize: '0.75rem', padding: '6px 14px', display: 'flex', alignItems: 'center', gap: 5 }}>
            <FileJson size={13} />
            Export JSON
          </button>
          <button className="btn-primary" onClick={handleExport} disabled={exporting} style={{ fontSize: '0.75rem', padding: '6px 14px' }}>
            <Download size={13} />
            {exporting ? 'Exporting…' : 'Export & Seal'}
          </button>
        </div>
      </div>

      {exported && (
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', padding: '10px 14px', background: 'var(--safe-subtle)', border: '1px solid var(--safe)', borderRadius: 6 }}>
          <CheckCircle2 size={14} style={{ color: 'var(--safe)' }} />
          <span style={{ fontSize: '0.78rem', color: 'var(--text-safe)' }}>
            Export sealed into the evidence chain — report sha256 <code className="font-mono">{exported.slice(0, 16)}…</code>
          </span>
        </div>
      )}

      {/* Verdict banner */}
      {v && (
        <div style={{
          background: v.classification === 'dangerous' ? 'var(--danger-subtle)' : v.classification === 'suspicious' ? 'var(--warning-subtle)' : 'var(--safe-subtle)',
          border: `1px solid ${v.classification === 'dangerous' ? 'var(--danger)' : v.classification === 'suspicious' ? 'var(--warning)' : 'var(--safe)'}`,
          borderRadius: 8,
          padding: '18px 24px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 16,
          flexWrap: 'wrap',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <ScoreBadge score={v.final_score} />
            <ClassificationBadge classification={v.classification} />
            <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
              AI {v.scores.ai} · URL {v.scores.url} · Attachment {v.scores.attachment} · Header {v.scores.header}
            </span>
          </div>
          <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace' }}>
            {integrity.generated_at.slice(0, 19).replace('T', ' ')} UTC
          </span>
        </div>
      )}

      {/* Case metadata */}
      <Section title="Case Metadata" icon={<FileText size={16} />}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 14 }}>
          <Field label="Subject" value={report.email.subject} />
          <Field label="From" value={report.email.sender} mono />
          <Field label="To" value={report.email.to} mono />
          <Field label="Message-ID" value={report.email.message_id} mono />
          <Field label="Sent" value={report.email.date || '—'} />
          <Field label="Scan completed" value={report.scan.completed_at ? format(new Date(report.scan.completed_at), 'PPpp') : '—'} />
          {report.campaign && (
            <Field label="Campaign" value={`#${report.campaign.id} ${report.campaign.name} (${report.campaign.email_count} emails)`} />
          )}
        </div>
      </Section>

      {/* Header forensics */}
      {report.header_forensics && (
        <Section title="Header Forensics" icon={<FileSearch size={16} />}>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: report.received_chain.length ? 14 : 0 }}>
            {((report.header_forensics.flags as string[] | undefined) ?? []).map((f, i) => (
              <span key={i} style={{ fontSize: '0.7rem', fontWeight: 600, padding: '3px 10px', borderRadius: 4, background: 'var(--danger-subtle)', color: 'var(--text-danger)', border: '1px solid rgba(239,68,68,0.3)' }}>
                {f}
              </span>
            ))}
            {(((report.header_forensics.flags as string[] | undefined) ?? []).length === 0) && (
              <span style={{ fontSize: '0.78rem', color: 'var(--safe)' }}>No header anomaly flags.</span>
            )}
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))', gap: 12 }}>
            <Field label="Origin IP" value={(report.header_forensics.origin_ip as string) || '—'} mono />
            <Field label="Origin host" value={(report.header_forensics.origin_host as string) || '—'} mono />
            <Field label="Hops" value={String(report.header_forensics.hop_count ?? 0)} />
            <Field label="Header score" value={String(report.header_forensics.score ?? 0)} />
          </div>
        </Section>
      )}

      {/* Origin + geo intel */}
      {report.origin && (
        <Section title="Origin Trace" icon={<Radio size={16} />}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 12 }}>
            <Field label="Origin IP" value={report.origin.ip} mono />
            <Field label="From host" value={report.origin.from_host || '—'} mono />
            <Field label="Country" value={report.origin.intel?.country || '—'} />
            <Field label="City" value={report.origin.intel?.city || '—'} />
            <Field label="ASN" value={report.origin.intel?.asn ? `AS${report.origin.intel.asn}` : '—'} />
            <Field label="ASN Org" value={report.origin.intel?.asn_org || '—'} />
            <Field label="VPN/TOR/Hosting" value={[
              report.origin.intel?.is_vpn && 'VPN',
              report.origin.intel?.is_tor && 'TOR',
              report.origin.intel?.is_hosting && 'hosting',
            ].filter(Boolean).join(', ') || 'none'} />
            <Field label="PTR" value={report.origin.intel?.ptr_host || '—'} mono />
          </div>
        </Section>
      )}

      {/* Received chain */}
      {report.received_chain.length > 0 && (
        <Section title={`Received Chain — ${report.received_chain.length} hops`} icon={<Link2 size={16} />}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {report.received_chain.map((h) => (
              <div key={h.hop_index} style={{ display: 'flex', gap: 10, alignItems: 'baseline', fontSize: '0.72rem', background: 'var(--bg-input)', borderRadius: 4, padding: '6px 10px', flexWrap: 'wrap' }}>
                <span className="font-mono" style={{ color: 'var(--text-muted)', minWidth: 22 }}>#{h.hop_index}</span>
                <span className="font-mono" style={{ color: 'var(--text-secondary)' }}>
                  {h.from_host || '?'} {h.from_ip ? `[${h.from_ip}]` : ''}
                </span>
                <span style={{ color: 'var(--text-muted)' }}>→ {h.by_host || '?'}</span>
                <span className="font-mono" style={{ color: 'var(--text-muted)', fontSize: '0.65rem' }}>{h.timestamp?.slice(0, 19) ?? ''}</span>
                <span style={{ marginLeft: 'auto', fontSize: '0.62rem', fontWeight: 700, color: h.is_internal ? 'var(--primary)' : 'var(--text-muted)' }}>
                  {h.is_internal ? 'internal' : 'external'}
                </span>
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* Indicators */}
      {report.indicators.length > 0 && (
        <Section title={`Indicators of Compromise — ${report.indicators.length}`} icon={<Fingerprint size={16} />}>
          <div style={{ overflowX: 'auto' }}>
            <table className="dark-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr><th>Type</th><th>Value</th><th>Scans</th></tr>
              </thead>
              <tbody>
                {report.indicators.map((i, idx) => (
                  <tr key={idx}>
                    <td>
                      <span style={{ fontSize: '0.68rem', fontWeight: 700, background: 'var(--bg-input)', padding: '2px 8px', borderRadius: 4, color: 'var(--text-secondary)' }}>
                        {i.type}
                      </span>
                    </td>
                    <td className="font-mono" style={{ fontSize: '0.75rem', wordBreak: 'break-all' }}>{i.value}</td>
                    <td className="font-mono" style={{ fontSize: '0.75rem' }}>{i.scan_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Section>
      )}

      {/* Evidence chain */}
      <Section title={`Chain of Custody — ${report.evidence_chain.length} entries`} icon={<ScrollText size={16} />}>
        {report.evidence_chain.length === 0 ? (
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>No custody entries recorded yet.</p>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {report.evidence_chain.map((e) => (
              <div key={e.id} style={{ background: 'var(--bg-input)', borderRadius: 4, padding: '8px 12px', fontSize: '0.7rem' }}>
                <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'baseline' }}>
                  <span className="font-mono" style={{ color: 'var(--primary)', fontWeight: 700 }}>#{e.id}</span>
                  <span style={{ color: 'var(--text-secondary)', fontWeight: 600 }}>{e.actor}</span>
                  <span className="font-mono" style={{ color: 'var(--text-muted)' }}>
                    {e.created_at ? e.created_at.slice(0, 19).replace('T', ' ') : ''}
                  </span>
                </div>
                <div className="font-mono" style={{ color: 'var(--text-muted)', marginTop: 3, wordBreak: 'break-all' }}>
                  raw: {e.raw_sha256 ? `${e.raw_sha256.slice(0, 24)}…` : '—'}
                  {' · '}report: {e.report_sha256 ? `${e.report_sha256.slice(0, 24)}…` : '—'}
                  {' · '}row: {e.row_hash ? `${e.row_hash.slice(0, 16)}…` : '—'}
                </div>
              </div>
            ))}
          </div>
        )}
      </Section>

      {/* Integrity footer */}
      <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, padding: 18 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
          <Fingerprint size={15} style={{ color: 'var(--primary)' }} />
          <p style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Report Integrity</p>
        </div>
        <div className="font-mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'flex', flexDirection: 'column', gap: 4 }}>
          <span>sha256: <span style={{ color: 'var(--text-primary)', wordBreak: 'break-all' }}>{integrity.report_sha256}</span></span>
          <span>app: {integrity.app_version} · generated {integrity.generated_at.slice(0, 19).replace('T', ' ')} UTC</span>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'flex-start', marginTop: 12, padding: '10px 12px', background: 'var(--warning-subtle)', border: '1px solid var(--warning)', borderRadius: 6 }}>
          <AlertTriangle size={13} style={{ color: 'var(--warning)', flexShrink: 0, marginTop: 2 }} />
          <p style={{ fontSize: '0.72rem', color: 'var(--text-warning)', lineHeight: 1.5 }}>{integrity.disclaimer}</p>
        </div>
      </div>
    </div>
  );
}
