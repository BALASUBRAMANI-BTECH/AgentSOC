import React from 'react';
import { Incident } from '../types/soc';
import { Shield, CheckCircle, AlertTriangle, ExternalLink } from 'lucide-react';

interface MitreViewProps {
  incidents: Incident[];
  onSelectIncident: (id: string) => void;
}

export const MitreView: React.FC<MitreViewProps> = ({ incidents, onSelectIncident }) => {
  const activeTechniques = new Set(
    incidents.map((i) => i.mitre_mapping?.technique_id || 'T1110')
  );

  const tactics = [
    {
      name: 'Initial Access',
      techniques: [
        { id: 'T1190', name: 'Exploit Public-Facing App', desc: 'Exploiting internet-accessible services' },
        { id: 'T1078', name: 'Valid Accounts', desc: 'Obtaining and abusing credentials of existing accounts' },
      ],
    },
    {
      name: 'Credential Access',
      techniques: [
        { id: 'T1110', name: 'Brute Force', desc: 'Systematic guessing or high-velocity credential spraying', highlighted: true },
        { id: 'T1110.001', name: 'Password Guessing', desc: 'Attempting common or default passwords against accounts' },
        { id: 'T1003', name: 'OS Credential Dumping', desc: 'Attempting to extract passwords from memory/registry' },
      ],
    },
    {
      name: 'Discovery',
      techniques: [
        { id: 'T1046', name: 'Network Service Discovery', desc: 'Port scanning and enumerating open services' },
        { id: 'T1087', name: 'Account Discovery', desc: 'Listing domain/local users on targeted host' },
      ],
    },
    {
      name: 'Defense Evasion',
      techniques: [
        { id: 'T1070', name: 'Indicator Removal', desc: 'Deleting event logs or altering audit trails' },
        { id: 'T1562', name: 'Impair Defenses', desc: 'Disabling firewall rules or endpoint agents' },
      ],
    },
  ];

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div>
        <h2 className="text-xl font-mono font-black uppercase text-white tracking-wider flex items-center space-x-2">
          <Shield className="w-5 h-5 text-cyan-400" />
          <span>MITRE ATT&CK Matrix Navigator (Enterprise v14)</span>
        </h2>
        <p className="text-xs font-mono text-slate-400 mt-1">
          Real-time technique correlation matching observed adversary telemetry to standardized TTPs
        </p>
      </div>

      {/* Matrix Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {tactics.map((tactic) => (
          <div
            key={tactic.name}
            className="bg-slate-950 border border-slate-800 rounded-xl p-4 flex flex-col space-y-3"
          >
            <div className="border-b border-slate-800 pb-2 flex items-center justify-between">
              <h3 className="font-mono text-xs font-bold uppercase text-slate-200 tracking-wider">
                {tactic.name}
              </h3>
              <span className="text-[10px] font-mono text-slate-500">
                {tactic.techniques.length} Techniques
              </span>
            </div>

            <div className="space-y-2.5 flex-1">
              {tactic.techniques.map((tech) => {
                const isActive = activeTechniques.has(tech.id) || tech.highlighted;
                return (
                  <div
                    key={tech.id}
                    className={`p-3 rounded-lg border font-mono transition-all ${
                      isActive
                        ? 'bg-red-950/30 border-red-500/50 shadow-[0_0_12px_rgba(239,68,68,0.15)]'
                        : 'bg-slate-900/50 border-slate-800/80 text-slate-400'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className={`text-xs font-bold ${isActive ? 'text-red-400' : 'text-slate-300'}`}>
                        {tech.id}
                      </span>
                      {isActive && (
                        <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-red-500/20 text-red-300 border border-red-500/30 animate-pulse">
                          TRIGGERED
                        </span>
                      )}
                    </div>
                    <div className="text-xs font-semibold text-slate-200 mb-1">
                      {tech.name}
                    </div>
                    <p className="text-[11px] text-slate-400 leading-tight">
                      {tech.desc}
                    </p>
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

