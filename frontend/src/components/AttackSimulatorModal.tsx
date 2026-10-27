import React, { useState, useEffect } from 'react';
import { SimulationScenario } from '../types/soc';
import { api } from '../services/api';
import { X, Play, ShieldAlert, Crosshair, Terminal, CheckCircle2, AlertCircle, Loader2 } from 'lucide-react';

interface AttackSimulatorModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSimulationComplete: () => void;
}

export const AttackSimulatorModal: React.FC<AttackSimulatorModalProps> = ({
  isOpen,
  onClose,
  onSimulationComplete,
}) => {
  const [scenarios, setScenarios] = useState<SimulationScenario[]>([]);
  const [selectedScenario, setSelectedScenario] = useState<string>('brute_force');
  const [eventCount, setEventCount] = useState<number>(25);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen) {
      api.getSimulationScenarios()
        .then((data) => {
          if (data && data.length > 0) {
            setScenarios(data);
          }
        })
        .catch(() => {});
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const handleLaunch = async () => {
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await api.triggerSimulation(selectedScenario, eventCount);
      setResult(res);
      onSimulationComplete();
    } catch (err: any) {
      setError(err.message || 'Simulation execution failed');
    } finally {
      setLoading(false);
    }
  };

  const defaultScenarios: SimulationScenario[] = [
    {
      id: 'brute_force',
      name: 'High-Velocity SSH Brute-Force',
      description: 'Adversary repeatedly attempts SSH authentication against admin user from internal pivot IP.',
      mitre_technique: 'T1110',
      attacker_ip: '192.168.1.50',
      target_user: 'admin',
      event_count: 25,
      category: 'Credential Access',
    },
    {
      id: 'port_scan',
      name: 'Internal Network Service Discovery',
      description: 'Host conducts fast TCP SYN discovery sweep across enterprise services and database ports.',
      mitre_technique: 'T1046',
      attacker_ip: '10.0.1.99',
      target_user: 'network_probe',
      event_count: 15,
      category: 'Discovery',
    },
    {
      id: 'credential_stuffing',
      name: 'Distributed Tor Credential Stuffing',
      description: 'State-sponsored actor relays automated password spraying across multiple valid accounts via Tor exit node.',
      mitre_technique: 'T1110.004',
      attacker_ip: '185.220.101.5',
      target_user: 'sarah.connor, john.doe, finance_lead',
      event_count: 20,
      category: 'Initial Access & Credential Access',
    },
    {
      id: 'privilege_abuse',
      name: 'Unauthorized Privilege Escalation',
      description: 'Restricted account attempts unauthorized elevation to domain admin and security context tampering.',
      mitre_technique: 'T1078',
      attacker_ip: '10.0.0.75',
      target_user: 'guest_user',
      event_count: 10,
      category: 'Defense Evasion & Persistence',
    },
    {
      id: 'data_exfiltration',
      name: 'Encrypted Non-C2 Data Exfiltration',
      description: 'Compromised internal endpoint stages and transmits anomalous high-volume outbound data stream.',
      mitre_technique: 'T1048',
      attacker_ip: '10.0.0.120',
      target_user: 'backup_agent',
      event_count: 12,
      category: 'Exfiltration',
    },
  ];

  const displayScenarios = scenarios.length > 0 ? scenarios : defaultScenarios;
  const activeScenarioObj = displayScenarios.find((s) => s.id === selectedScenario) || displayScenarios[0];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md">
      <div className="bg-slate-900 border border-slate-700/80 rounded-2xl w-full max-w-3xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center space-x-3">
            <div className="p-2.5 rounded-xl bg-red-950/40 border border-red-500/30 text-red-400">
              <Crosshair className="w-5 h-5 animate-pulse" />
            </div>
            <div>
              <h3 className="text-base font-mono font-bold uppercase text-white tracking-wider">
                Adversary Attack Simulator Hub
              </h3>
              <p className="text-xs font-mono text-slate-400">
                Inject realistic multi-vector cyber telemetry to stress-test autonomous detection & LangGraph response
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-2 rounded-lg hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1">
          {/* Scenario Grid Selection */}
          <div>
            <label className="text-xs font-mono font-bold uppercase text-slate-300 tracking-wider mb-3 block">
              1. Select Attack Campaign Vector
            </label>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {displayScenarios.map((sc) => {
                const isSelected = selectedScenario === sc.id;
                return (
                  <button
                    key={sc.id}
                    onClick={() => {
                      setSelectedScenario(sc.id);
                      setEventCount(sc.event_count || 20);
                    }}
                    className={`text-left p-4 rounded-xl border transition flex flex-col justify-between ${
                      isSelected
                        ? 'bg-red-950/20 border-red-500/60 shadow-lg shadow-red-950/40'
                        : 'bg-slate-950/40 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs font-mono font-bold text-white tracking-wide">
                          {sc.name}
                        </span>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-400 border border-cyan-500/30">
                          {sc.mitre_technique}
                        </span>
                      </div>
                      <p className="text-xs font-mono text-slate-400 line-clamp-2 mt-1">
                        {sc.description}
                      </p>
                    </div>
                    <div className="flex items-center justify-between mt-3 pt-2 border-t border-slate-800/60 text-[10px] font-mono text-slate-500">
                      <span>IP: {sc.attacker_ip}</span>
                      <span>Target: {sc.target_user}</span>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Volume Config */}
          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <label className="text-xs font-mono font-bold uppercase text-white tracking-wider block">
                2. Telemetry Ingestion Burst Volume
              </label>
              <p className="text-xs font-mono text-slate-400 mt-0.5">
                Number of raw telemetry events to inject in rapid succession
              </p>
            </div>
            <div className="flex items-center space-x-2">
              {[10, 25, 50, 100].map((count) => (
                <button
                  key={count}
                  onClick={() => setEventCount(count)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold border transition ${
                    eventCount === count
                      ? 'bg-red-500 text-white border-red-400'
                      : 'bg-slate-900 text-slate-400 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  {count} Evts
                </button>
              ))}
            </div>
          </div>

          {/* Target Summary Details */}
          {activeScenarioObj && (
            <div className="p-4 rounded-xl bg-slate-900 border border-slate-800/80 font-mono text-xs space-y-2">
              <div className="flex items-center justify-between text-slate-400">
                <span>SIMULATED ADVERSARY:</span>
                <span className="text-red-400 font-bold">{activeScenarioObj.attacker_ip}</span>
              </div>
              <div className="flex items-center justify-between text-slate-400">
                <span>TARGET ENTITY:</span>
                <span className="text-amber-400 font-bold">{activeScenarioObj.target_user}</span>
              </div>
              <div className="flex items-center justify-between text-slate-400">
                <span>MITRE ATT&CK TECHNIQUE:</span>
                <span className="text-cyan-400 font-bold">{activeScenarioObj.mitre_technique}</span>
              </div>
            </div>
          )}

          {/* Error Message */}
          {error && (
            <div className="p-3 rounded-xl bg-red-950/40 border border-red-500/50 flex items-center space-x-2 text-xs font-mono text-red-300">
              <AlertCircle className="w-4 h-4 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {/* Success Banner */}
          {result && (
            <div className="p-4 rounded-xl bg-emerald-950/30 border border-emerald-500/40 font-mono text-xs text-emerald-300 space-y-2">
              <div className="flex items-center space-x-2 font-bold text-emerald-400">
                <CheckCircle2 className="w-4 h-4" />
                <span>Simulation Successful: {result.events_injected} events injected!</span>
              </div>
              <p className="text-slate-300 text-[11px]">
                Events evaluated through rules and ML anomaly engine. Multi-agent investigation completed.
              </p>
              {result.correlated_incident && (
                <div className="p-2.5 rounded-lg bg-slate-950 border border-emerald-500/30 text-[11px] text-slate-300">
                  <span className="text-white font-bold">Correlated Incident:</span>{' '}
                  {result.correlated_incident.incident_id} — {result.correlated_incident.title} (Risk: {result.correlated_incident.risk_score}/100)
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-5 border-t border-slate-800 bg-slate-950/60 flex items-center justify-between">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl bg-slate-800 text-slate-300 hover:bg-slate-700 text-xs font-mono transition"
          >
            Close
          </button>
          <button
            onClick={handleLaunch}
            disabled={loading}
            className="flex items-center space-x-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 text-white font-mono font-bold text-xs uppercase tracking-wider shadow-lg shadow-red-900/30 transition disabled:opacity-50"
          >
            {loading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Injecting Telemetry...</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4 fill-white" />
                <span>Launch Attack Campaign</span>
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};
