import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import { motion } from 'framer-motion';
import { format, subDays } from 'date-fns';
import type { Scan } from '../../types';

interface ThreatTimelineProps {
  scans: Scan[];
}

function buildChartData(scans: Scan[]) {
  const days = Array.from({ length: 7 }, (_, i) => {
    const date = subDays(new Date(), 6 - i);
    return { date: format(date, 'MMM d'), dangerous: 0, suspicious: 0, safe: 0 };
  });

  scans.forEach((scan) => {
    if (scan.status !== 'complete' || !scan.verdict) return;
    const dateStr = scan.completed_at
      ? format(new Date(scan.completed_at), 'MMM d')
      : null;
    if (!dateStr) return;
    const day = days.find((d) => d.date === dateStr);
    if (!day) return;
    const cls = scan.verdict.classification;
    if (cls === 'dangerous') day.dangerous++;
    else if (cls === 'suspicious') day.suspicious++;
    else day.safe++;
  });

  return days;
}

interface TimelineTooltipProps {
  active?: boolean;
  label?: string;
  payload?: Array<{ dataKey?: string; stroke?: string; value?: number }>;
}

const CustomTooltip = ({ active, payload, label }: TimelineTooltipProps) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{
      background: 'var(--bg-card)',
      border: '1px solid var(--border-default)',
      borderRadius: 8,
      padding: '10px 14px',
      boxShadow: '0 8px 32px rgba(0,0,0,0.5)',
    }}>
      <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: 6 }}>{label}</p>
      {(payload ?? []).map((p) => (
        <div key={p.dataKey} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 3 }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: p.stroke, display: 'inline-block' }} />
          <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', textTransform: 'capitalize' }}>
            {p.dataKey}:
          </span>
          <span style={{ fontSize: '0.8rem', fontWeight: 700, color: p.stroke, fontFamily: 'JetBrains Mono, monospace' }}>
            {p.value}
          </span>
        </div>
      ))}
    </div>
  );
};

export function ThreatTimeline({ scans }: ThreatTimelineProps) {
  const data = buildChartData(scans);

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, ease: 'easeOut' }}
      style={{ width: '100%', height: '100%' }}
    >
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 10, right: 4, left: -20, bottom: 0 }}>
          <defs>
            <linearGradient id="dangerGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#EF4444" stopOpacity={0.3} />
              <stop offset="95%" stopColor="#EF4444" stopOpacity={0.02} />
            </linearGradient>
            <linearGradient id="warnGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#F59E0B" stopOpacity={0.25} />
              <stop offset="95%" stopColor="#F59E0B" stopOpacity={0.02} />
            </linearGradient>
            <linearGradient id="safeGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#10B981" stopOpacity={0.25} />
              <stop offset="95%" stopColor="#10B981" stopOpacity={0.02} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" vertical={false} />
          <XAxis
            dataKey="date"
            tick={{ fill: 'var(--text-muted)', fontSize: 11 }}
            axisLine={{ stroke: 'var(--border-subtle)' }}
            tickLine={false}
          />
          <YAxis
            tick={{ fill: 'var(--text-muted)', fontSize: 11 }}
            axisLine={false}
            tickLine={false}
            allowDecimals={false}
          />
          <Tooltip content={<CustomTooltip />} />
          <Area type="monotone" dataKey="dangerous" stroke="#EF4444" strokeWidth={2} fill="url(#dangerGrad)" />
          <Area type="monotone" dataKey="suspicious" stroke="#F59E0B" strokeWidth={2} fill="url(#warnGrad)" />
          <Area type="monotone" dataKey="safe" stroke="#10B981" strokeWidth={2} fill="url(#safeGrad)" />
        </AreaChart>
      </ResponsiveContainer>
    </motion.div>
  );
}
