import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts';
import { motion } from 'framer-motion';
import type { Scan } from '../../types';

interface ClassificationDonutProps {
  scans: Scan[];
}

const SEGMENTS = [
  { key: 'dangerous', label: 'Dangerous', color: '#EF4444' },
  { key: 'suspicious', label: 'Suspicious', color: '#F59E0B' },
  { key: 'safe', label: 'Safe', color: '#10B981' },
];

interface DonutTooltipProps {
  active?: boolean;
  payload?: Array<{ name?: string; value?: number | string }>;
}

const CustomTooltip = ({ active, payload }: DonutTooltipProps) => {
  if (!active || !payload?.length) return null;
  const { name, value } = payload[0];
  return (
    <div style={{
      background: 'var(--bg-card)',
      border: '1px solid var(--border-default)',
      borderRadius: 8,
      padding: '8px 12px',
    }}>
      <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{name}: </span>
      <span style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-primary)', fontFamily: 'JetBrains Mono, monospace' }}>
        {value}
      </span>
    </div>
  );
};

export function ClassificationDonut({ scans }: ClassificationDonutProps) {
  const completedScans = scans.filter((s) => s.status === 'complete' && s.verdict);
  const total = completedScans.length;

  const counts = {
    dangerous: completedScans.filter((s) => s.verdict?.classification === 'dangerous').length,
    suspicious: completedScans.filter((s) => s.verdict?.classification === 'suspicious').length,
    safe: completedScans.filter((s) => s.verdict?.classification === 'safe').length,
  };

  const data = SEGMENTS.map((s) => ({
    name: s.label,
    value: counts[s.key as keyof typeof counts],
    color: s.color,
  })).filter((d) => d.value > 0);

  if (data.length === 0) {
    data.push({ name: 'No Data', value: 1, color: 'var(--bg-input)' });
  }

  return (
    <motion.div
      initial={{ opacity: 0, rotate: -10, scale: 0.9 }}
      animate={{ opacity: 1, rotate: 0, scale: 1 }}
      transition={{ duration: 0.5, ease: 'easeOut' }}
      style={{ width: '100%', height: '100%', display: 'flex', flexDirection: 'column' }}
    >
      <div style={{ flex: 1, position: 'relative' }}>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius="55%"
              outerRadius="80%"
              paddingAngle={3}
              dataKey="value"
              startAngle={90}
              endAngle={-270}
            >
              {data.map((entry, i) => (
                <Cell
                  key={i}
                  fill={entry.color}
                  stroke="transparent"
                  style={{ filter: `drop-shadow(0 0 6px ${entry.color}60)` }}
                />
              ))}
            </Pie>
            <Tooltip content={<CustomTooltip />} />
          </PieChart>
        </ResponsiveContainer>

        {/* Center label */}
        <div style={{
          position: 'absolute',
          inset: 0,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          pointerEvents: 'none',
        }}>
          <span className="font-mono" style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--text-primary)' }}>
            {total}
          </span>
          <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            total scans
          </span>
        </div>
      </div>

      {/* Legend */}
      <div style={{ display: 'flex', justifyContent: 'center', gap: 20, paddingTop: 8 }}>
        {SEGMENTS.map((s) => (
          <div key={s.key} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: s.color, display: 'inline-block', boxShadow: `0 0 6px ${s.color}` }} />
            <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>{s.label}</span>
            <span className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-primary)', fontWeight: 600 }}>
              {counts[s.key as keyof typeof counts]}
            </span>
          </div>
        ))}
      </div>
    </motion.div>
  );
}
