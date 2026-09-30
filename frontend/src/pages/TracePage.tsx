import { useCallback, useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { MapContainer, TileLayer, Marker, Popup, Polyline } from 'react-leaflet';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import {
  ArrowLeft,
  RefreshCw,
  Globe,
  MapPin,
  Server,
  ShieldAlert,
  Radio,
} from 'lucide-react';
import { getTrace, type TraceResponse, type Hop } from '../api/forensics';

// Marker without leaflet's default icon assets (breaks under bundlers).
const originIcon = L.divIcon({
  className: '',
  html: '<div style="width:16px;height:16px;border-radius:50%;background:#ef4444;border:3px solid #fff;box-shadow:0 0 10px rgba(239,68,68,.9)"></div>',
  iconSize: [16, 16],
  iconAnchor: [8, 8],
});

// Intermediate hop marker for the cached-geo route polyline (FE-C6).
const hopIcon = L.divIcon({
  className: '',
  html: '<div style="width:11px;height:11px;border-radius:50%;background:#3b82f6;border:2px solid #fff;box-shadow:0 0 6px rgba(59,130,246,.8)"></div>',
  iconSize: [11, 11],
  iconAnchor: [5, 5],
});

function IntelChip({ label, value, color }: { label: string; value: string; color?: string }) {
  return (
    <div
      style={{
        background: 'var(--bg-input)',
        border: '1px solid var(--border-subtle)',
        borderRadius: 6,
        padding: '8px 12px',
        minWidth: 140,
      }}
    >
      <p style={{ fontSize: '0.62rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
        {label}
      </p>
      <p className="font-mono" style={{ fontSize: '0.8rem', fontWeight: 600, color: color ?? 'var(--text-primary)', marginTop: 3, wordBreak: 'break-word' }}>
        {value}
      </p>
    </div>
  );
}

function Flag({ label, active, tone }: { label: string; active: boolean; tone: 'danger' | 'warning' | 'safe' }) {
  const color = tone === 'danger' ? 'var(--danger)' : tone === 'warning' ? 'var(--warning)' : 'var(--safe)';
  const bg = tone === 'danger' ? 'var(--danger-subtle)' : tone === 'warning' ? 'var(--warning-subtle)' : 'var(--safe-subtle)';
  return (
    <span
      style={{
        fontSize: '0.7rem',
        fontWeight: 700,
        padding: '3px 10px',
        borderRadius: 4,
        border: `1px solid ${active ? color : 'var(--border-default)'}`,
        background: active ? bg : 'transparent',
        color: active ? color : 'var(--text-muted)',
        opacity: active ? 1 : 0.6,
      }}
    >
      {label}{active ? '' : ' —'}
    </span>
  );
}

function HopTable({ hops }: { hops: Hop[] }) {
  if (hops.length === 0) {
    return (
      <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', padding: 12 }}>
        No Received chain parsed for this email.
      </p>
    );
  }
  return (
    <div style={{ overflowX: 'auto' }}>
      <table className="dark-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr>
            <th>#</th>
            <th>From host</th>
            <th>From IP</th>
            <th>HELO</th>
            <th>By</th>
            <th>Proto</th>
            <th>Timestamp (UTC)</th>
            <th>Scope</th>
          </tr>
        </thead>
        <tbody>
          {hops.map((h) => (
            <tr key={h.hop_index} title={h.raw ?? undefined}>
              <td className="font-mono" style={{ fontSize: '0.75rem' }}>{h.hop_index}</td>
              <td className="font-mono" style={{ fontSize: '0.75rem', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {h.from_host || '—'}
              </td>
              <td className="font-mono" style={{ fontSize: '0.75rem' }}>{h.from_ip || '—'}</td>
              <td className="font-mono" style={{ fontSize: '0.75rem' }}>{h.helo || '—'}</td>
              <td className="font-mono" style={{ fontSize: '0.75rem', maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {h.by_host || '—'}
              </td>
              <td className="font-mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                {h.protocol || '—'}
              </td>
              <td style={{ fontSize: '0.72rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                {h.timestamp ? h.timestamp.replace('T', ' ').slice(0, 19) : '—'}
              </td>
              <td>
                <span
                  style={{
                    fontSize: '0.65rem',
                    fontWeight: 700,
                    padding: '2px 8px',
                    borderRadius: 4,
                    background: h.is_internal ? 'var(--primary-glow)' : 'transparent',
                    border: `1px solid ${h.is_internal ? 'var(--primary)' : 'var(--border-default)'}`,
                    color: h.is_internal ? 'var(--primary)' : 'var(--text-muted)',
                  }}
                >
                  {h.is_internal ? 'internal' : 'external'}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function TracePage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [trace, setTrace] = useState<TraceResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async (refresh: boolean) => {
    if (!id) return;
    try {
      setError(null);
      const data = await getTrace(Number(id), refresh);
      setTrace(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load trace');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [id]);

  useEffect(() => {
    queueMicrotask(() => load(false));
  }, [load]);

  // Background geo enrichment: the backend queues missing IPs and reports
  // `enriching > 0` — re-poll until the cache is filled (max 4 tries).
  const [autoTries, setAutoTries] = useState(0);
  useEffect(() => {
    if (!trace?.enriching || autoTries >= 4) return;
    const timer = setTimeout(() => {
      setAutoTries((n) => n + 1);
      void load(false);
    }, 3000);
    return () => clearTimeout(timer);
  }, [trace, autoTries, load]);

  const handleRefresh = () => {
    setRefreshing(true);
    void load(true);
  };

  if (loading) {
    return (
      <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 16 }}>
        {[140, 360, 260].map((h, i) => <div key={i} className="skeleton" style={{ height: h, borderRadius: 8 }} />)}
      </div>
    );
  }

  if (error || !trace) {
    return (
      <div style={{ padding: 24 }}>
        <div style={{ border: '1px solid var(--danger)', borderRadius: 8, background: 'var(--danger-subtle)', padding: 20 }}>
          <p style={{ color: 'var(--text-danger)', fontWeight: 600 }}>{error ?? 'Trace not found'}</p>
          <button className="btn-ghost" onClick={() => navigate('/emails')} style={{ marginTop: 12, fontSize: '0.8rem' }}>
            <ArrowLeft size={14} /> Back to Inbox
          </button>
        </div>
      </div>
    );
  }

  const { origin, intel, hops } = trace;
  const hasCoords = intel?.lat != null && intel?.lon != null;

  // Cached per-hop geo (DB-only on the backend) → route polyline (FE-C6).
  const hopCoords = hops
    .filter((h) => h.geo != null && h.geo.lat != null && h.geo.lon != null)
    .sort((a, b) => a.hop_index - b.hop_index)
    .map((h) => ({
      idx: h.hop_index,
      ip: h.from_ip,
      host: h.from_host,
      country: h.geo!.country,
      lat: h.geo!.lat,
      lon: h.geo!.lon,
    }));
  const route: Array<[number, number]> = hopCoords.map((p) => [p.lat, p.lon]);
  const showRoute = route.length >= 2;
  const hopsWithoutGeo = hops.length - hopCoords.length;

  // Center/zoom: origin wins; otherwise the middle of the cached route.
  const centerPos: [number, number] =
    hasCoords && origin
      ? [intel!.lat!, intel!.lon!]
      : route.length > 0
        ? [route[Math.floor(route.length / 2)][0], route[Math.floor(route.length / 2)][1]]
        : [20, 0];
  let zoom = 5;
  if (showRoute) {
    const lats = route.map((r) => r[0]);
    const lons = route.map((r) => r[1]);
    const span = Math.max(
      Math.max(...lats) - Math.min(...lats),
      Math.max(...lons) - Math.min(...lons),
    );
    zoom = span > 40 ? 2 : span > 15 ? 3 : span > 5 ? 4 : 5;
  }

  return (
    <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 20, maxWidth: 1100 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
        <button className="btn-ghost" onClick={() => navigate(-1)} style={{ fontSize: '0.8rem' }}>
          <ArrowLeft size={14} /> Back
        </button>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          {!!trace.enriching && (
            <span style={{ fontSize: '0.7rem', color: 'var(--primary)', display: 'flex', alignItems: 'center', gap: 6 }}>
              <RefreshCw size={11} style={{ animation: 'spin 1s linear infinite' }} />
              Enriching {trace.enriching} IP{trace.enriching !== 1 ? 's' : ''}…
            </span>
          )}
          <span className="font-mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)', background: 'var(--bg-input)', padding: '3px 8px', borderRadius: 4 }}>
            EMAIL #{trace.email_id}
          </span>
          <button className="btn-ghost" onClick={handleRefresh} disabled={refreshing} style={{ fontSize: '0.75rem', padding: '5px 12px' }}>
            <RefreshCw size={12} style={{ animation: refreshing ? 'spin 1s linear infinite' : 'none' }} />
            {refreshing ? 'Enriching…' : 'Refresh Intel'}
          </button>
        </div>
      </div>

      {/* Origin card */}
      <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, padding: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
          <Radio size={16} style={{ color: 'var(--danger)' }} />
          <p style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Origin Hop
          </p>
        </div>
        {origin ? (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 10 }}>
            <IntelChip label="Origin IP" value={origin.ip} color="var(--danger)" />
            <IntelChip label="Hop index" value={`#${origin.hop_index}`} />
            <IntelChip label="From host" value={origin.from_host || '—'} />
            <IntelChip label="HELO" value={origin.helo || '—'} />
            <IntelChip label="Received by" value={origin.by_host || '—'} />
            <IntelChip label="Timestamp" value={origin.timestamp_utc ? origin.timestamp_utc.replace('T', ' ').slice(0, 19) : '—'} />
          </div>
        ) : (
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            No external origin hop found in the Received chain.
          </p>
        )}
      </div>

      {/* Geo / reputation intel */}
      {intel && (
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, padding: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Globe size={16} style={{ color: 'var(--primary)' }} />
              <p style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                Geo &amp; Reputation
              </p>
            </div>
            <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace' }}>
              {intel.source ? `source: ${intel.source}` : ''}
              {intel.fetched_at ? ` · ${intel.fetched_at.slice(0, 19).replace('T', ' ')} UTC` : ''}
            </span>
          </div>

          <div style={{ display: 'flex', gap: 6, marginBottom: 14, flexWrap: 'wrap' }}>
            <Flag label="VPN" active={intel.is_vpn} tone="warning" />
            <Flag label="TOR" active={intel.is_tor} tone="danger" />
            <Flag label="PROXY" active={intel.is_proxy} tone="warning" />
            <Flag label="HOSTING" active={intel.is_hosting} tone="warning" />
            <Flag label="DNSBL LISTED" active={intel.is_dnsbl_listed} tone="danger" />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 10 }}>
            <IntelChip label="Country" value={[intel.country, intel.country_code ? `(${intel.country_code})` : ''].filter(Boolean).join(' ') || '—'} />
            <IntelChip label="Region / City" value={[intel.region, intel.city].filter(Boolean).join(' / ') || '—'} />
            <IntelChip label="ASN" value={intel.asn ? `AS${intel.asn}` : '—'} />
            <IntelChip label="ASN Org" value={intel.asn_org || '—'} />
            <IntelChip label="ISP" value={intel.isp || '—'} />
            <IntelChip label="PTR" value={intel.ptr_host || '—'} />
          </div>
        </div>
      )}

      {!intel && origin && (
        <div style={{ background: 'var(--bg-card)', border: '1px dashed var(--border-default)', borderRadius: 8, padding: 16, fontSize: '0.8rem', color: 'var(--text-muted)' }}>
          {trace.enriching ? (
            <>
              Looking up <span className="font-mono">{origin.ip}</span> and{' '}
              {trace.enriching - 1 > 0 ? `${trace.enriching - 1} relay hop${trace.enriching - 1 !== 1 ? 's' : ''} ` : ''}
              in the background — geo/ASN details appear automatically in a few seconds.
            </>
          ) : (
            <>
              No cached IP intelligence for <span className="font-mono">{origin.ip}</span>.
              Use <strong>Refresh Intel</strong> to query the configured provider (graceful when offline).
            </>
          )}
        </div>
      )}

      {/* Map */}
      <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, overflow: 'hidden' }}>
        <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', alignItems: 'center', gap: 8 }}>
          <MapPin size={16} style={{ color: showRoute ? 'var(--primary)' : 'var(--danger)' }} />
          <p style={{ fontSize: '0.875rem', fontWeight: 700, color: 'var(--text-primary)' }}>
            {showRoute ? 'Route — source → relays → origin' : 'Origin Location'}
          </p>
          {showRoute && hopsWithoutGeo > 0 && (
            <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>
              +{hopsWithoutGeo} hop{hopsWithoutGeo !== 1 ? 's' : ''} without cached coordinates
            </span>
          )}
        </div>
        {showRoute || (hasCoords && origin) ? (
          <MapContainer
            center={centerPos}
            zoom={zoom}
            style={{ height: 320, width: '100%' }}
            scrollWheelZoom={false}
          >
            <TileLayer
              attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
              url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
            />
            {showRoute && (
              <>
                <Polyline
                  positions={route}
                  pathOptions={{ color: '#3b82f6', weight: 3, opacity: 0.85, dashArray: '8 10' }}
                />
                {hopCoords.map((p) => (
                  <Marker key={p.idx} position={[p.lat, p.lon]} icon={hopIcon}>
                    <Popup>
                      <strong>hop #{p.idx}</strong>
                      {p.host ? <><br />{p.host}</> : null}
                      {p.ip ? <><br />{p.ip}</> : null}
                      {p.country ? <><br />{p.country}</> : null}
                    </Popup>
                  </Marker>
                ))}
              </>
            )}
            {hasCoords && origin && (
              <Marker position={[intel!.lat!, intel!.lon!]} icon={originIcon}>
                <Popup>
                  <strong>origin: {origin.ip}</strong>
                  <br />
                  {[intel!.city, intel!.country].filter(Boolean).join(', ') || 'coordinates only'}
                </Popup>
              </Marker>
            )}
          </MapContainer>
        ) : (
          <div style={{ height: 320, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 8, background: 'var(--bg-input)' }}>
            <MapPin size={28} style={{ color: 'var(--text-muted)' }} />
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', textAlign: 'center', padding: '0 20px' }}>
              {hops.length > 0
                ? 'No cached hop coordinates yet — visit other traces or run Refresh Intel to populate the geo cache.'
                : 'Geolocation coordinates unavailable — run Refresh Intel to populate the map.'}
            </p>
          </div>
        )}
      </div>

      {/* Received chain */}
      <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, overflow: 'hidden' }}>
        <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', alignItems: 'center', gap: 8 }}>
          <Server size={16} style={{ color: 'var(--primary)' }} />
          <p style={{ fontSize: '0.875rem', fontWeight: 700, color: 'var(--text-primary)' }}>Received Chain</p>
          <span className="font-mono" style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginLeft: 4 }}>
            {hops.length} hop{hops.length !== 1 ? 's' : ''}
          </span>
        </div>
        <HopTable hops={hops} />
      </div>

      {!trace.hops.some((h) => !h.is_internal) && trace.hops.length > 0 && (
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', padding: '10px 14px', background: 'var(--warning-subtle)', border: '1px solid var(--warning)', borderRadius: 6 }}>
          <ShieldAlert size={14} style={{ color: 'var(--warning)' }} />
          <span style={{ fontSize: '0.78rem', color: 'var(--text-warning)' }}>
            All hops are internal — origin is this mail server itself (loopback or local relay).
          </span>
        </div>
      )}
    </div>
  );
}
