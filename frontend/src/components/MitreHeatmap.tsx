import type { MitreCoverage, MitreTechniqueCount } from '../types';

interface MitreHeatmapProps {
  data: MitreCoverage | null | undefined;
}

// Key MITRE tactics ordered as in the ATT&CK matrix
const TACTIC_ORDER = [
  { id: 'TA0043', name: 'Reconnaissance' },
  { id: 'TA0042', name: 'Resource Development' },
  { id: 'TA0001', name: 'Initial Access' },
  { id: 'TA0002', name: 'Execution' },
  { id: 'TA0003', name: 'Persistence' },
  { id: 'TA0004', name: 'Privilege Escalation' },
  { id: 'TA0005', name: 'Defense Evasion' },
  { id: 'TA0006', name: 'Credential Access' },
  { id: 'TA0007', name: 'Discovery' },
  { id: 'TA0008', name: 'Lateral Movement' },
  { id: 'TA0009', name: 'Collection' },
  { id: 'TA0011', name: 'Command & Control' },
  { id: 'TA0010', name: 'Exfiltration' },
  { id: 'TA0040', name: 'Impact' },
];

function getHeatLevel(count: number): string {
  if (count === 0) return 'inactive';
  if (count < 5)   return 'low';
  if (count < 20)  return 'medium';
  if (count < 50)  return 'high';
  return 'critical';
}

export default function MitreHeatmap({ data }: MitreHeatmapProps) {
  if (!data || !data.techniques) {
    return (
      <div className="empty-state">
        <div className="empty-state-sub">Run detections to populate ATT&CK coverage</div>
      </div>
    );
  }

  // Build lookup by tactic_id
  const byTactic: Record<string, MitreTechniqueCount[]> = {};
  data.techniques.forEach(t => {
    const key = t.tactic_id || 'unknown';
    if (!byTactic[key]) byTactic[key] = [];
    byTactic[key].push(t);
  });

  // Only show tactics that have at least one technique in our rules
  const activeTactics = TACTIC_ORDER.filter(t => byTactic[t.id]);

  if (activeTactics.length === 0) {
    return (
      <div className="empty-state">
        <div className="empty-state-sub">
          No technique hits yet — upload logs and run detections
        </div>
      </div>
    );
  }

  return (
    <div className="mitre-grid">
      {activeTactics.map(tactic => {
        const techniques = byTactic[tactic.id] || [];
        return (
          <div key={tactic.id} className="mitre-tactic">
            <div className="mitre-tactic-header">
              <span style={{ color: 'var(--text-muted)', marginRight: 6 }}>{tactic.id}</span>
              {tactic.name}
            </div>
            <div className="mitre-techniques-row">
              {techniques.map(tech => (
                <div
                  key={tech.technique_id}
                  className={`mitre-cell ${getHeatLevel(tech.count)}`}
                  title={`${tech.technique_id} — ${tech.technique_name}\n${tech.count} alert(s)`}
                >
                  <span className="mitre-cell-id">{tech.technique_id}</span>
                  <span className="mitre-cell-name">{tech.technique_name || '—'}</span>
                  {tech.count > 0 && (
                    <span className="mitre-cell-count">{tech.count} alert{tech.count !== 1 ? 's' : ''}</span>
                  )}
                </div>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}
