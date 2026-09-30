import { useCallback, useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
  Megaphone,
  RefreshCw,
  ArrowLeft,
  AlertCircle,
  Search,
  Save,
} from 'lucide-react';
import {
  getCampaigns,
  getCampaign,
  reclusterCampaigns,
  updateCampaign,
  CAMPAIGN_STATUSES,
  type Campaign,
  type CampaignDetail,
} from '../api/forensics';
import { ScoreBadge, ClassificationBadge } from '../components/ui/Badge';
import { formatDistanceToNow } from 'date-fns';

// ─── Detail view ──────────────────────────────────────────────────────────────
function CampaignDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [detail, setDetail] = useState<CampaignDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  // Case-management state (FE-C2). notesDraft is `null` until edited so the
  // editor always reflects the server value for the currently loaded id.
  const [notesDraft, setNotesDraft] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [caseMessage, setCaseMessage] = useState<string | null>(null);
  const [caseError, setCaseError] = useState(false);
  const [memberSearch, setMemberSearch] = useState('');

  useEffect(() => {
    if (!id) return;
    queueMicrotask(() => {
      setLoading(true);
      setNotesDraft(null);
      setMemberSearch('');
      setCaseMessage(null);
    });
    getCampaign(Number(id))
      .then(setDetail)
      .catch((err: unknown) => setError(err instanceof Error ? err.message : 'Failed to load campaign'))
      .finally(() => setLoading(false));
  }, [id]);

  if (loading) {
    return (
      <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 16 }}>
        {[120, 300].map((h, i) => <div key={i} className="skeleton" style={{ height: h, borderRadius: 8 }} />)}
      </div>
    );
  }

  if (error || !detail) {
    return (
      <div style={{ padding: 24 }}>
        <div style={{ border: '1px solid var(--danger)', borderRadius: 8, background: 'var(--danger-subtle)', padding: 20 }}>
          <p style={{ color: 'var(--text-danger)', fontWeight: 600 }}>{error ?? 'Campaign not found'}</p>
          <button className="btn-ghost" onClick={() => navigate('/campaigns')} style={{ marginTop: 12, fontSize: '0.8rem' }}>
            <ArrowLeft size={14} /> Back to Campaigns
          </button>
        </div>
      </div>
    );
  }

  const { campaign, scans } = detail;
  const effectiveNotes = notesDraft ?? campaign.notes ?? '';

  const persist = async (patch: { status?: string; notes?: string }) => {
    setSaving(true);
    setCaseMessage(null);
    setCaseError(false);
    try {
      const updated = await updateCampaign(campaign.id, patch);
      setDetail((prev) => (prev ? { ...prev, campaign: { ...prev.campaign, ...updated } } : prev));
      if (patch.notes !== undefined) setNotesDraft(null);
      setCaseMessage('Saved.');
      return true;
    } catch (err: unknown) {
      setCaseError(true);
      setCaseMessage(err instanceof Error ? err.message : 'Save failed');
      return false;
    } finally {
      setSaving(false);
    }
  };

  const handleStatusChange = (status: string) => {
    void persist({ status });
  };

  const handleSaveNotes = () => {
    void persist({ notes: effectiveNotes });
  };

  const needle = memberSearch.trim().toLowerCase();
  const visibleScans = needle
    ? scans.filter((s) =>
        (s.subject ?? '').toLowerCase().includes(needle) ||
        (s.sender ?? '').toLowerCase().includes(needle))
    : scans;

  return (
    <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 20, maxWidth: 1000 }}>
      <button className="btn-ghost" onClick={() => navigate('/campaigns')} style={{ width: 'fit-content', fontSize: '0.8rem' }}>
        <ArrowLeft size={14} /> Back to Campaigns
      </button>

      {/* Header */}
      <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, padding: 24 }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <Megaphone size={20} style={{ color: 'var(--primary)' }} />
              <h2 style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-primary)' }}>{campaign.name}</h2>
            </div>
            <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: 6 }}>
              #{campaign.id} · {campaign.email_count} email{campaign.email_count !== 1 ? 's' : ''} · status {campaign.status} · confidence {(campaign.confidence * 100).toFixed(0)}%
            </p>
          </div>
          <ScoreBadge score={campaign.avg_score} />
        </div>
        <div style={{ display: 'flex', gap: 20, marginTop: 16, flexWrap: 'wrap' }}>
          <div>
            <p style={{ fontSize: '0.62rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>First seen</p>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-primary)' }}>
              {campaign.first_seen ? formatDistanceToNow(new Date(campaign.first_seen), { addSuffix: true }) : '—'}
            </p>
          </div>
          <div>
            <p style={{ fontSize: '0.62rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Last seen</p>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-primary)' }}>
              {campaign.last_seen ? formatDistanceToNow(new Date(campaign.last_seen), { addSuffix: true }) : '—'}
            </p>
          </div>
        </div>
      </div>

      {/* Case management: status + notes (plan §5 B4 → FE-C2) */}
      <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, padding: 20, display: 'flex', flexDirection: 'column', gap: 12 }}>
        <div style={{ display: 'flex', gap: 16, alignItems: 'flex-end', flexWrap: 'wrap' }}>
          <label style={{ display: 'flex', flexDirection: 'column', gap: 4, fontSize: '0.68rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Status
            <select
              value={campaign.status}
              onChange={(e) => handleStatusChange(e.target.value)}
              disabled={saving}
              style={{ background: 'var(--bg-input)', border: '1px solid var(--border-default)', borderRadius: 4, color: 'var(--text-primary)', padding: '6px 10px', fontSize: '0.8rem', minWidth: 150 }}
            >
              {CAMPAIGN_STATUSES.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </label>
          {caseMessage && (
            <span style={{ fontSize: '0.75rem', color: caseError ? 'var(--danger)' : 'var(--safe)' }}>{caseMessage}</span>
          )}
        </div>
        <label style={{ display: 'flex', flexDirection: 'column', gap: 4, fontSize: '0.68rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
          Analyst notes
        </label>
        <textarea
          value={effectiveNotes}
          onChange={(e) => setNotesDraft(e.target.value)}
          placeholder="Triage notes: scope, containment steps, related incidents…"
          rows={3}
          style={{ background: 'var(--bg-input)', border: '1px solid var(--border-default)', borderRadius: 4, color: 'var(--text-primary)', padding: '8px 10px', fontSize: '0.8rem', resize: 'vertical', fontFamily: 'inherit' }}
        />
        <button
          className="btn-ghost"
          onClick={handleSaveNotes}
          disabled={saving || effectiveNotes === (campaign.notes ?? '')}
          style={{ width: 'fit-content', fontSize: '0.75rem', padding: '6px 14px', display: 'flex', alignItems: 'center', gap: 5 }}
        >
          <Save size={12} /> {saving ? 'Saving…' : 'Save Notes'}
        </button>
      </div>

      {/* Members */}
      <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, overflow: 'hidden' }}>
        <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap' }}>
          <p style={{ fontSize: '0.875rem', fontWeight: 700, color: 'var(--text-primary)' }}>Member Scans ({scans.length})</p>
          <label style={{ display: 'flex', alignItems: 'center', gap: 6, background: 'var(--bg-input)', border: '1px solid var(--border-default)', borderRadius: 4, padding: '4px 8px' }}>
            <Search size={12} style={{ color: 'var(--text-muted)' }} />
            <input
              value={memberSearch}
              onChange={(e) => setMemberSearch(e.target.value)}
              placeholder="Search subject / sender / domain…"
              style={{ background: 'transparent', border: 'none', outline: 'none', color: 'var(--text-primary)', fontSize: '0.75rem', width: 210 }}
            />
          </label>
        </div>
        {scans.length === 0 ? (
          <p style={{ padding: 20, fontSize: '0.8rem', color: 'var(--text-muted)' }}>No member scans (recluster to re-link).</p>
        ) : visibleScans.length === 0 ? (
          <p style={{ padding: 20, fontSize: '0.8rem', color: 'var(--text-muted)' }}>No members match “{memberSearch}”.</p>
        ) : (
          <table className="dark-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th>Scan</th>
                <th>Subject</th>
                <th>Sender</th>
                <th>Score</th>
                <th>Classification</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {visibleScans.map((s) => (
                <tr key={s.scan_id}>
                  <td className="font-mono" style={{ fontSize: '0.75rem' }}>#{s.scan_id}</td>
                  <td style={{ maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {s.subject || '(no subject)'}
                  </td>
                  <td className="font-mono" style={{ fontSize: '0.72rem', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {s.sender || '—'}
                  </td>
                  <td><ScoreBadge score={s.final_score} size="sm" /></td>
                  <td>{s.classification ? <ClassificationBadge classification={s.classification} size="sm" /> : '—'}</td>
                  <td>
                    <button
                      onClick={() => navigate(`/scans/${s.scan_id}`)}
                      style={{ background: 'transparent', border: '1px solid var(--primary)', borderRadius: 4, color: 'var(--primary)', padding: '3px 10px', fontSize: '0.72rem', cursor: 'pointer', fontWeight: 600 }}
                    >
                      View
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// ─── List view ────────────────────────────────────────────────────────────────
function CampaignsList() {
  const navigate = useNavigate();
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [loading, setLoading] = useState(true);
  const [reclustering, setReclustering] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState('all');
  const [search, setSearch] = useState('');

  const load = useCallback(async (status?: string) => {
    setLoading(true);
    try {
      setError(null);
      setCampaigns(await getCampaigns(status));
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load campaigns');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    queueMicrotask(() => load(statusFilter === 'all' ? undefined : statusFilter));
  }, [load, statusFilter]);

  const handleRecluster = async () => {
    setReclustering(true);
    setMessage(null);
    try {
      const result = await reclusterCampaigns();
      setMessage(
        result.scans_total === 0
          ? 'No scans with verdicts yet — nothing to cluster.'
          : `Reclustered ${result.scans_clustered}/${result.scans_total} scans into ${result.campaigns.length} campaign(s).`,
      );
      await load(statusFilter === 'all' ? undefined : statusFilter);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Recluster failed');
    } finally {
      setReclustering(false);
    }
  };

  const needle = search.trim().toLowerCase();
  const visibleCampaigns = needle
    ? campaigns.filter((c) => {
        if (
          c.name.toLowerCase().includes(needle) ||
          String(c.id).includes(needle) ||
          c.status.toLowerCase().includes(needle)
        ) return true;
        // shared IoCs (origin IPs / domains) count as searchable too
        const shared = (c.summary as { shared_iocs?: Record<string, string[]> } | null)?.shared_iocs;
        return Object.values(shared ?? {}).some((values) =>
          values.some((v) => v.toLowerCase().includes(needle)));
      })
    : campaigns;

  return (
    <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Toolbar */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Megaphone size={18} style={{ color: 'var(--primary)' }} />
          <div>
            <h2 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)' }}>Campaigns</h2>
            <p style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
              {campaigns.length} cluster{campaigns.length !== 1 ? 's' : ''} linked by shared IoCs and subjects
            </p>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: 6, background: 'var(--bg-input)', border: '1px solid var(--border-default)', borderRadius: 4, padding: '5px 9px' }}>
            <Search size={13} style={{ color: 'var(--text-muted)' }} />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search campaigns…"
              style={{ background: 'transparent', border: 'none', outline: 'none', color: 'var(--text-primary)', fontSize: '0.78rem', width: 170 }}
            />
          </label>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            aria-label="Filter by status"
            style={{ background: 'var(--bg-input)', border: '1px solid var(--border-default)', borderRadius: 4, color: 'var(--text-primary)', padding: '6px 10px', fontSize: '0.78rem' }}
          >
            <option value="all">All statuses</option>
            <option value="open">open</option>
            <option value="new">new</option>
            <option value="investigating">investigating</option>
            <option value="closed">closed</option>
          </select>
          <button className="btn-ghost" onClick={handleRecluster} disabled={reclustering} style={{ fontSize: '0.75rem', padding: '6px 14px' }}>
            <RefreshCw size={12} style={{ animation: reclustering ? 'spin 1s linear infinite' : 'none' }} />
            {reclustering ? 'Reclustering…' : 'Recluster All'}
          </button>
        </div>
      </div>

      {message && (
        <div style={{ padding: '10px 14px', background: 'var(--safe-subtle)', border: '1px solid var(--safe)', borderRadius: 6, fontSize: '0.78rem', color: 'var(--text-safe)' }}>
          {message}
        </div>
      )}
      {error && (
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', padding: '10px 14px', background: 'var(--danger-subtle)', border: '1px solid var(--danger)', borderRadius: 6 }}>
          <AlertCircle size={14} style={{ color: 'var(--danger)' }} />
          <span style={{ fontSize: '0.78rem', color: 'var(--text-danger)' }}>{error}</span>
        </div>
      )}

      {/* Table */}
      <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, overflow: 'hidden' }}>
        {loading ? (
          <div style={{ padding: 16 }}>
            <div className="skeleton" style={{ height: 240, borderRadius: 6 }} />
          </div>
        ) : visibleCampaigns.length === 0 ? (
          <div style={{ padding: 48, textAlign: 'center' }}>
            <Megaphone size={36} style={{ color: 'var(--text-muted)', margin: '0 auto 10px' }} />
            <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
              {campaigns.length === 0 ? 'No campaigns clustered yet' : 'No campaigns match your search'}
            </p>
            {campaigns.length === 0 && (
              <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: 4 }}>
                Run scans and press <strong>Recluster All</strong> to group related attacks.
              </p>
            )}
          </div>
        ) : (
          <table className="dark-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th>Campaign</th>
                <th>Emails</th>
                <th>Avg score</th>
                <th>Confidence</th>
                <th>Status</th>
                <th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {visibleCampaigns.map((c) => (
                <tr key={c.id}>
                  <td>
                    <button
                      className="link-cell-btn"
                      onClick={() => navigate(`/campaigns/${c.id}`)}
                    >
                      <span className="link-cell-title" style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-primary)' }}>{c.name}</span>
                      <span className="font-mono" style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>#{c.id}</span>
                    </button>
                  </td>
                  <td className="font-mono" style={{ fontSize: '0.78rem' }}>{c.email_count}</td>
                  <td><ScoreBadge score={c.avg_score} size="sm" /></td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <div style={{ width: 60, height: 5, background: 'var(--bg-input)', borderRadius: 3, overflow: 'hidden' }}>
                        <div style={{ width: `${Math.round(c.confidence * 100)}%`, height: '100%', background: 'var(--primary)' }} />
                      </div>
                      <span className="font-mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                        {(c.confidence * 100).toFixed(0)}%
                      </span>
                    </div>
                  </td>
                  <td>
                    <span style={{ fontSize: '0.68rem', fontWeight: 700, padding: '2px 8px', borderRadius: 4, background: 'var(--bg-input)', color: c.status === 'open' ? 'var(--warning)' : 'var(--text-muted)', border: '1px solid var(--border-default)' }}>
                      {c.status}
                    </span>
                  </td>
                  <td style={{ fontSize: '0.72rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                    {c.last_seen ? formatDistanceToNow(new Date(c.last_seen), { addSuffix: true }) : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// ─── Route switch ─────────────────────────────────────────────────────────────
export function CampaignsPage() {
  const { id } = useParams<{ id?: string }>();
  return id ? <CampaignDetailPage /> : <CampaignsList />;
}
