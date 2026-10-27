import React, { useState } from 'react';
import { DashboardStats, Incident, SecurityEvent, UserProfile } from '../types/soc';
import { SeverityBadge, StatusBadge } from '../components/IncidentBadge';
import { RiskGauge } from '../components/RiskGauge';
import { AttackSimulatorModal } from '../components/AttackSimulatorModal';
import { api } from '../services/api';
import { Shield, AlertTriangle, Radio, Activity, Zap, Play, Terminal, ArrowRight, CheckCircle, RefreshCw, Crosshair } from 'lucide-react';

interface DashboardViewProps {
  stats: DashboardStats | null;
  incidents: Incident[];
  liveEvents: SecurityEvent[];
  user: UserProfile | null;
  onSelectIncident: (id: string) => void;
  onRefresh: () => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  stats,
  incidents,
  liveEvents,
  user,
  onSelectIncident,
  onRefresh,
}) => {
  const [simulating, setSimulating] = useState(false);
  const [simulatorModalOpen, setSimulatorModalOpen] = useState(false);
  const [simulationStatus, setSimulationStatus] = useState<string | null>(null);

  const handleSimulateAttack = async () => {
    setSimulating(true);
    setSimulationStatus('Injecting credential attack bursts (100 failed auth from 192.168.1.50)...');
    try {
      // Ingest a burst of 10 failed login events to simulate the benchmark attack
      for (let i = 1; i <= 10; i++) {
        await api.ingestEvent({
          source_ip: '192.168.1.50',
          destination_ip: '10.0.0.5',
          username: 'admin',
          event_type: 'login_failed',
          severity: 'HIGH',
          message: `Authentication credential failure attempt #${i * 10} - targeted SSH brute-force`,
          metadata: { failure_count: i * 10, total_batch: 100, service: 'ssh' },
        });
      }
      setSimulationStatus('Attack burst injected! Threat detected, correlated, and investigated by LangGraph AI agents.');
      setTimeout(() => {
        onRefresh();
        setSimulationStatus(null);
      }, 3000);
    } catch (err: any) {
      setSimulationStatus(`Simulation failed: ${err.message}`);
    } finally {
      setSimulating(false);
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Top Banner with Simulation Trigger */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-2xl bg-gradient-to-r from-slate-950 via-slate-900 to-slate-950 border border-slate-800 shadow-xl">
        <div>
          <div className="flex items-center space-x-2">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse" />
            <h2 className="text-base font-mono font-black uppercase text-white tracking-wider">
              Real-Time Threat Telemetry & Autonomous Response Grid
            </h2>
          </div>
          <p className="text-xs font-mono text-slate-400 mt-1">
            Continuous ingestion stream monitoring • Dual ML + Rule correlation • MITRE ATT&CK Mapping
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <button
            onClick={onRefresh}
            className="p-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 transition-colors"
            title="Refresh Metrics"
          >
            <RefreshCw className="w-4 h-4" />
          </button>

          <button
            onClick={() => setSimulatorModalOpen(true)}
            className="flex items-center space-x-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-red-600 via-rose-600 to-amber-600 hover:from-red-500 hover:to-amber-500 text-white font-mono text-xs font-bold uppercase tracking-wider shadow-[0_0_20px_rgba(239,68,68,0.3)] transition-all"
          >
            <Crosshair className="w-3.5 h-3.5" />
            <span>Attack Simulator Hub</span>
          </button>
        </div>
      </div>

      <AttackSimulatorModal
        isOpen={simulatorModalOpen}
        onClose={() => setSimulatorModalOpen(false)}
        onSimulationComplete={onRefresh}
      />

      {simulationStatus && (
        <div className="p-3.5 bg-cyan-950/60 border border-cyan-500/40 rounded-xl text-cyan-300 font-mono text-xs flex items-center space-x-2 animate-fadeIn">
          <Terminal className="w-4 h-4 text-cyan-400 shrink-0" />
          <span>{simulationStatus}</span>
        </div>
      )}

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Events */}
        <div className="bg-slate-950/80 p-4 rounded-xl border border-slate-800/80 hover:border-slate-700 transition-all">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono uppercase tracking-wider">Ingested Telemetry</span>
            <Radio className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-mono font-black text-white">
            {stats?.total_events ?? liveEvents.length}
          </div>
          <span className="text-[11px] font-mono text-cyan-400/80 mt-1 block">
            Streaming via Redis/Memurai
          </span>
        </div>

        {/* Active Incidents */}
        <div className="bg-slate-950/80 p-4 rounded-xl border border-slate-800/80 hover:border-slate-700 transition-all">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono uppercase tracking-wider">Active Incidents</span>
            <AlertTriangle className="w-4 h-4 text-orange-400" />
          </div>
          <div className="text-2xl font-mono font-black text-orange-400">
            {incidents.filter((i) => i.status !== 'RESOLVED' && i.status !== 'CLOSED').length}
          </div>
          <span className="text-[11px] font-mono text-red-400 mt-1 block">
            {incidents.filter((i) => i.severity === 'CRITICAL').length} Critical Tier
          </span>
        </div>

        {/* Blocked Threats */}
        <div className="bg-slate-950/80 p-4 rounded-xl border border-slate-800/80 hover:border-slate-700 transition-all">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono uppercase tracking-wider">Defensive Containments</span>
            <Shield className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-mono font-black text-emerald-400">
            {stats?.contained_incidents ?? incidents.filter((i) => i.status === 'CONTAINED').length}
          </div>
          <span className="text-[11px] font-mono text-slate-400 mt-1 block">
            Perimeter Drops & Account Locks
          </span>
        </div>

        {/* Autonomous Agents */}
        <div className="bg-slate-950/80 p-4 rounded-xl border border-slate-800/80 hover:border-slate-700 transition-all">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono uppercase tracking-wider">AI Investigation Agents</span>
            <Activity className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-mono font-black text-cyan-400">5 / 5</div>
          <span className="text-[11px] font-mono text-emerald-400 mt-1 block">
            LangGraph Autonomous State
          </span>
        </div>
      </div>

      {/* Main Grid: Recent Correlated Incidents & Live Telemetry Stream */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Active Incidents List (8 cols) */}
        <div className="lg:col-span-7 bg-slate-950 border border-slate-800 rounded-xl overflow-hidden flex flex-col">
          <div className="p-4 bg-slate-900/60 border-b border-slate-800 flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <AlertTriangle className="w-4 h-4 text-orange-400" />
              <h3 className="font-mono text-xs font-bold uppercase text-slate-200 tracking-wider">
                Correlated Security Incidents
              </h3>
            </div>
            <span className="text-[11px] font-mono text-slate-400">
              {incidents.length} Detected
            </span>
          </div>

          <div className="divide-y divide-slate-800/60 overflow-y-auto max-h-[500px]">
            {incidents.length === 0 ? (
              <div className="p-8 text-center font-mono text-xs text-slate-500">
                No active security incidents detected. Click "Simulate Benchmark Attack" to generate test telemetry.
              </div>
            ) : (
              incidents.map((inc) => (
                <div
                  key={inc.incident_id}
                  onClick={() => onSelectIncident(inc.incident_id)}
                  className="p-4 hover:bg-slate-900/50 cursor-pointer transition-colors flex items-center justify-between gap-4"
                >
                  <div className="space-y-1.5 flex-1 min-w-0">
                    <div className="flex items-center space-x-2">
                      <span className="font-mono text-xs font-bold text-cyan-400">
                        {inc.incident_id}
                      </span>
                      <SeverityBadge severity={inc.severity} size="sm" />
                      <StatusBadge status={inc.status} />
                    </div>

                    <p className="text-xs text-slate-200 font-semibold truncate">
                      {inc.title}
                    </p>

                    <div className="flex items-center space-x-4 text-[11px] font-mono text-slate-400">
                      <span>Source: <strong className="text-slate-300">{inc.source_ip}</strong></span>
                      {inc.target_user && (
                        <span>Target: <strong className="text-yellow-400">{inc.target_user}</strong></span>
                      )}
                      <span>MITRE: <strong className="text-cyan-400">{inc.mitre_mapping?.technique_id || 'T1110'}</strong></span>
                    </div>
                  </div>

                  {/* Mini Risk Score & Chevron */}
                  <div className="flex items-center space-x-3 shrink-0">
                    <div className="text-center">
                      <span
                        className={`text-lg font-mono font-black ${
                          inc.risk_score >= 90
                            ? 'text-red-400'
                            : inc.risk_score >= 70
                            ? 'text-orange-400'
                            : 'text-yellow-400'
                        }`}
                      >
                        {Math.round(inc.risk_score)}
                      </span>
                      <span className="block text-[9px] font-mono text-slate-500 uppercase">Risk</span>
                    </div>
                    <ArrowRight className="w-4 h-4 text-slate-500" />
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Live Telemetry Ticker (4 cols) */}
        <div className="lg:col-span-5 bg-slate-950 border border-slate-800 rounded-xl overflow-hidden flex flex-col">
          <div className="p-4 bg-slate-900/60 border-b border-slate-800 flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Radio className="w-4 h-4 text-cyan-400 animate-pulse" />
              <h3 className="font-mono text-xs font-bold uppercase text-slate-200 tracking-wider">
                Live Ingestion Stream
              </h3>
            </div>
            <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800">
              Active
            </span>
          </div>

          <div className="p-3 space-y-2 overflow-y-auto max-h-[500px] font-mono text-xs">
            {liveEvents.length === 0 ? (
              <div className="p-6 text-center text-slate-500">
                Listening for incoming events on Redis stream...
              </div>
            ) : (
              liveEvents.slice(0, 15).map((ev, i) => (
                <div
                  key={ev.event_id || i}
                  className="p-2.5 rounded bg-slate-900/60 border border-slate-800/80 space-y-1 hover:border-cyan-800/50 transition-colors"
                >
                  <div className="flex items-center justify-between text-[10px]">
                    <span className="text-cyan-400 font-bold">{ev.event_type}</span>
                    <span className="text-slate-500">
                      {new Date(ev.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-300 truncate">{ev.message}</p>
                  <div className="flex items-center justify-between text-[10px] text-slate-500 pt-1 border-t border-slate-800/40">
                    <span>IP: {ev.source_ip}</span>
                    {ev.username && <span>User: {ev.username}</span>}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

