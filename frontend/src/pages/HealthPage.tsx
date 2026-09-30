import { useCallback, useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { Activity, Database, Server, RefreshCw, CheckCircle, AlertTriangle, AlertCircle, Globe2 } from 'lucide-react';
import { LineChart, Line, ResponsiveContainer } from 'recharts';
import { useSystemHealth } from '../hooks/useSystemHealth';

interface HealthSnapshot {
  time: number;
  latency: number;
  status: boolean;
}

interface ServiceCardProps {
  name: string;
  icon: React.ReactNode;
  status: string;
  detail?: string;
  variant?: 'healthy' | 'error' | 'warning' | 'unknown';
}

function ServiceCard({ name, icon, status, detail, variant = 'unknown' }: ServiceCardProps) {
  const colors = {
    healthy: { text: '#6EE7B7', bg: 'rgba(16,185,129,0.1)', border: 'rgba(16,185,129,0.25)' },
    error:   { text: '#FCA5A5', bg: 'rgba(239,68,68,0.1)',   border: 'rgba(239,68,68,0.25)' },
    warning: { text: '#FCD34D', bg: 'rgba(245,158,11,0.1)',  border: 'rgba(245,158,11,0.25)' },
    unknown: { text: '#94A3B8', bg: 'rgba(100,116,139,0.1)', border: 'rgba(100,116,139,0.25)' },
  };
  const c = colors[variant];

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      style={{
        background: 'var(--bg-card)',
        border: `1px solid var(--border-default)`,
        borderRadius: 8,
        padding: '20px',
        display: 'flex',
        flexDirection: 'column',
        gap: 12,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ color: 'var(--text-muted)' }}>{icon}</div>
          <span style={{ fontSize: '0.875rem', fontWeight: 700, color: 'var(--text-primary)' }}>{name}</span>
        </div>
        <span style={{
          fontSize: '0.7rem',
          fontWeight: 700,
          textTransform: 'uppercase' as const,
          letterSpacing: '0.06em',
          color: c.text,
          background: c.bg,
          border: `1px solid ${c.border}`,
          padding: '3px 10px',
          borderRadius: 4,
        }}>
          {status}
        </span>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        {variant === 'healthy'
          ? <CheckCircle size={14} style={{ color: '#10B981' }} />
          : variant === 'error'
          ? <AlertCircle size={14} style={{ color: '#EF4444' }} />
          : <AlertCircle size={14} style={{ color: '#94A3B8' }} />
        }
        <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
          {detail ?? 'No detail available'}
        </span>
      </div>
    </motion.div>
  );
}

export function HealthPage() {
  const { health, loading: hookLoading, refresh } = useSystemHealth();
  const [history, setHistory] = useState<HealthSnapshot[]>([]);
  const [latency, setLatency] = useState(0);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [manualLoading, setManualLoading] = useState(false);

  const fetchAndTrack = useCallback(async () => {
    const t0 = performance.now();
    await refresh();
    const ms = Math.round(performance.now() - t0);
    setLatency(ms);
    setHistory((prev) => [...prev.slice(-19), { time: Date.now(), latency: ms, status: true }]);
    setLastUpdated(new Date());
  }, [refresh]);

  useEffect(() => {
    if (!health) return;
    queueMicrotask(() => {
      setLatency(health.response_time_ms);
      setLastUpdated(new Date());
      setHistory((prev) => [...prev.slice(-19), {
        time: Date.now(), latency: health.response_time_ms, status: true,
      }]);
    });
  }, [health]);

  const handleRefresh = async () => {
    setManualLoading(true);
    await fetchAndTrack();
    setManualLoading(false);
  };

  const allOk = health?.status === 'ok';
  const dbStatus = health?.components?.database?.status;
  const mlStatus = health?.components?.ml_model?.status;
  const dynamicStatus = health?.components?.dynamic_url?.status;

  // Determine failing components for degraded banner
  const failingComponents: string[] = [];
  if (health?.status === 'degraded') {
    if (dbStatus === 'error') failingComponents.push('Database');
    if (mlStatus === 'not_loaded') failingComponents.push('ML Model');
  }

  return (
    <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* Main Status Banner */}
      <motion.div
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        style={{
          background: allOk ? 'rgba(16,185,129,0.08)' : health ? 'rgba(245,158,11,0.08)' : 'rgba(239,68,68,0.08)',
          border: `1px solid ${allOk ? '#10B981' : health ? '#F59E0B' : '#EF4444'}`,
          borderRadius: 8,
          padding: '28px 32px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          {allOk
            ? <CheckCircle size={36} style={{ color: '#10B981' }} />
            : <AlertTriangle size={36} style={{ color: health ? '#F59E0B' : '#EF4444' }} />
          }
          <div>
            <p style={{
              fontSize: '1.5rem',
              fontWeight: 900,
              color: allOk ? '#10B981' : health ? '#F59E0B' : '#EF4444',
              textTransform: 'uppercase' as const,
              letterSpacing: '-0.01em',
            }}>
              {hookLoading ? 'Checking...' : allOk ? 'All Systems Operational' : health ? 'System Degraded' : 'Backend Offline'}
            </p>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: 4 }}>
              Last checked: {lastUpdated ? lastUpdated.toLocaleTimeString() : '—'} · Auto-refreshes every 30s
            </p>
            {failingComponents.length > 0 && (
              <p style={{ fontSize: '0.8rem', color: '#FCD34D', marginTop: 6 }}>
                Failing: {failingComponents.join(', ')}
              </p>
            )}
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ textAlign: 'right' }}>
            <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' as const, letterSpacing: '0.08em' }}>
              Response Time
            </p>
            <p className="font-mono" style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--text-primary)' }}>
              {health?.response_time_ms ?? latency}ms
            </p>
          </div>
          <button className="btn-ghost" onClick={handleRefresh} style={{ padding: '8px 12px' }}>
            <RefreshCw size={14} style={{ animation: manualLoading ? 'spin 1s linear infinite' : 'none' }} />
          </button>
        </div>
      </motion.div>

      {/* Service cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16 }}>
        <ServiceCard
          name="API"
          icon={<Server size={16} />}
          status={health ? (allOk ? 'HEALTHY' : 'DEGRADED') : 'OFFLINE'}
          detail={health ? `${health.response_time_ms}ms response` : 'Cannot reach backend'}
          variant={health ? (allOk ? 'healthy' : 'warning') : 'error'}
        />
        <ServiceCard
          name="Dynamic URL"
          icon={<Globe2 size={16} />}
          status={!health ? 'UNKNOWN' : dynamicStatus === 'enabled' ? 'ENABLED' : 'DISABLED'}
          detail={health?.components?.dynamic_url?.detail ?? 'No data'}
          variant={!health ? 'unknown' : dynamicStatus === 'enabled' ? 'healthy' : 'warning'}
        />
        <ServiceCard
          name="Database"
          icon={<Database size={16} />}
          status={
            !health ? 'UNKNOWN' :
            dbStatus === 'connected' ? 'HEALTHY' : 'ERROR'
          }
          detail={health?.components?.database?.detail ?? 'No data'}
          variant={
            !health ? 'unknown' :
            dbStatus === 'connected' ? 'healthy' : 'error'
          }
        />
        <ServiceCard
          name="ML Model"
          icon={<Activity size={16} />}
          status={
            !health ? 'UNKNOWN' :
            mlStatus === 'loaded' ? 'LOADED' : 'NOT LOADED'
          }
          detail={health?.components?.ml_model?.detail ?? 'No data'}
          variant={
            !health ? 'unknown' :
            mlStatus === 'loaded' ? 'healthy' : 'warning'
          }
        />
      </div>

      {/* Sparkline History */}
      {history.length > 1 && (
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, padding: '16px 20px' }}>
          <p style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: 12, textTransform: 'uppercase' as const, letterSpacing: '0.06em' }}>
            Response Time History (last {history.length} checks)
          </p>
          <div style={{ height: 80 }}>
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={history}>
                <Line
                  type="monotone"
                  dataKey="latency"
                  stroke="var(--primary)"
                  strokeWidth={2}
                  dot={false}
                  isAnimationActive={false}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 8 }}>
            <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Oldest</span>
            <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Latest: {latency}ms</span>
          </div>
        </div>
      )}

      {/* Version Info */}
      {health?.version && (
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, padding: '14px 20px' }}>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Backend version: <span className="font-mono" style={{ color: 'var(--text-primary)' }}>{health.version}</span>
          </p>
        </div>
      )}
    </div>
  );
}
