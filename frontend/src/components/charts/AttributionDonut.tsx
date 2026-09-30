import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts';
import type { AttributionStats } from '../../api/forensics';

interface AttributionDonutProps {
  stats: AttributionStats | null;
}

/** kind → label + color for the dashboard attribution split (FE-C5). */
const KIND_SEGMENTS: Record<string, { label: string; color: string }> = {
  spoofed_domain: { label: 'Spoofed domain', color: '#EF4444' },
  compromised_account: { label: 'Compromised account', color: '#F59E0B' },
  anonymized_infrastructure: { label: 'Anonymized infra', color: '#A78BFA' },
  direct_actor: { label: 'Direct actor', color: '#EC4899' },
  unknown: { label: 'Unknown', color: '#64748B' },
};

export function AttributionDonut({ stats }: AttributionDonutProps) {
  const kinds = (stats?.kinds ?? []).filter((k) => k.count > 0);
  const total = stats?.total ?? 0;

  if (!stats || total === 0 || kinds.length === 0) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
        <p style={{ fontSize: '0.62rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
          Attribution split
        </p>
        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          no classified verdicts yet
        </span>
      </div>
    );
  }

  const data = kinds.map((k) => ({
    name: KIND_SEGMENTS[k.kind]?.label ?? k.kind,
    value: k.count,
    color: KIND_SEGMENTS[k.kind]?.color ?? '#64748B',
    kind: k.kind,
  }));

  return (
    <div style={{ minWidth: 0 }}>
      <p style={{ fontSize: '0.62rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 4 }}>
        Attribution split
      </p>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <div style={{ width: 86, height: 86, position: 'relative', flexShrink: 0 }}>
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={data}
                cx="50%"
                cy="50%"
                innerRadius="58%"
                outerRadius="90%"
                paddingAngle={3}
                dataKey="value"
                startAngle={90}
                endAngle={-270}
                isAnimationActive={false}
              >
                {data.map((entry, i) => (
                  <Cell key={i} fill={entry.color} stroke="transparent" />
                ))}
              </Pie>
            </PieChart>
          </ResponsiveContainer>
          <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', pointerEvents: 'none' }}>
            <span className="font-mono" style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)' }}>
              {total}
            </span>
            <span style={{ fontSize: '0.55rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>verdicts</span>
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 3, minWidth: 0 }}>
          {data.map((entry) => (
            <div key={entry.kind} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: entry.color, flexShrink: 0 }} />
              <span style={{ fontSize: '0.68rem', color: 'var(--text-secondary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                {entry.name}
              </span>
              <span className="font-mono" style={{ fontSize: '0.68rem', color: 'var(--text-primary)', fontWeight: 600 }}>
                {entry.value}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
