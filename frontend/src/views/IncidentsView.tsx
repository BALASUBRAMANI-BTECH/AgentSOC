import React, { useState, useMemo } from 'react';
import { Incident, IncidentSeverity, IncidentStatus, UserProfile } from '../types/soc';
import { SeverityBadge, StatusBadge } from '../components/IncidentBadge';
import { Search, Filter, AlertTriangle, ArrowRight, ShieldCheck, ShieldAlert } from 'lucide-react';

interface IncidentsViewProps {
  incidents: Incident[];
  user: UserProfile | null;
  onSelectIncident: (incidentId: string) => void;
}

export const IncidentsView: React.FC<IncidentsViewProps> = ({
  incidents,
  user,
  onSelectIncident,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');

  const filteredIncidents = useMemo(() => {
    return incidents.filter((inc) => {
      const matchesSearch =
        searchTerm === '' ||
        inc.incident_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
        inc.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
        inc.source_ip.includes(searchTerm) ||
        (inc.target_user && inc.target_user.toLowerCase().includes(searchTerm.toLowerCase()));

      const matchesSeverity = severityFilter === 'ALL' || inc.severity === severityFilter;
      const matchesStatus = statusFilter === 'ALL' || inc.status === statusFilter;

      return matchesSearch && matchesSeverity && matchesStatus;
    });
  }, [incidents, searchTerm, severityFilter, statusFilter]);

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-mono font-black uppercase text-white tracking-wider flex items-center space-x-2">
            <AlertTriangle className="w-5 h-5 text-orange-400" />
            <span>Correlated Security Incidents</span>
          </h2>
          <p className="text-xs font-mono text-slate-400 mt-1">
            Triaged, correlated, and investigated by autonomous AI multi-agent graph
          </p>
        </div>
        <div className="text-xs font-mono text-slate-400">
          Total Incidents: <span className="text-cyan-400 font-bold">{incidents.length}</span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl flex flex-wrap items-center gap-3">
        {/* Search */}
        <div className="relative flex-1 min-w-[240px]">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search by ID, IP (e.g. 192.168.1.50), user, or attack vector..."
            className="w-full bg-slate-900 border border-slate-700/80 rounded-lg pl-9 pr-3 py-2 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>

        {/* Severity filter */}
        <div className="flex items-center space-x-2 text-xs font-mono">
          <span className="text-slate-400">Severity:</span>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-slate-900 border border-slate-700/80 rounded-lg px-2.5 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>

        {/* Status filter */}
        <div className="flex items-center space-x-2 text-xs font-mono">
          <span className="text-slate-400">Status:</span>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-slate-900 border border-slate-700/80 rounded-lg px-2.5 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Statuses</option>
            <option value="OPEN">Open</option>
            <option value="INVESTIGATING">Investigating</option>
            <option value="CONTAINED">Contained</option>
            <option value="RESOLVED">Resolved</option>
          </select>
        </div>
      </div>

      {/* Incidents Table */}
      <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs border-collapse">
            <thead>
              <tr className="bg-slate-900/80 text-slate-400 border-b border-slate-800 uppercase text-[10px] tracking-wider">
                <th className="p-3.5">Incident ID</th>
                <th className="p-3.5">Threat Title</th>
                <th className="p-3.5">Source IP</th>
                <th className="p-3.5">Target</th>
                <th className="p-3.5">Severity</th>
                <th className="p-3.5">Risk Score</th>
                <th className="p-3.5">MITRE Technique</th>
                <th className="p-3.5">Status</th>
                <th className="p-3.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredIncidents.length === 0 ? (
                <tr>
                  <td colSpan={9} className="p-8 text-center text-slate-500 font-mono text-xs">
                    No incidents matching current criteria.
                  </td>
                </tr>
              ) : (
                filteredIncidents.map((inc) => (
                  <tr
                    key={inc.incident_id}
                    onClick={() => onSelectIncident(inc.incident_id)}
                    className="hover:bg-slate-900/50 cursor-pointer transition-colors"
                  >
                    <td className="p-3.5 font-bold text-cyan-400">
                      {inc.incident_id}
                    </td>
                    <td className="p-3.5 text-slate-200 font-medium">
                      {inc.title}
                    </td>
                    <td className="p-3.5 text-slate-300">
                      <span className="bg-slate-900 px-2 py-0.5 rounded border border-slate-800 text-slate-200">
                        {inc.source_ip}
                      </span>
                    </td>
                    <td className="p-3.5 text-yellow-400">
                      {inc.target_user || '—'}
                    </td>
                    <td className="p-3.5">
                      <SeverityBadge severity={inc.severity} size="sm" />
                    </td>
                    <td className="p-3.5 font-black text-sm">
                      <span
                        className={
                          inc.risk_score >= 90
                            ? 'text-red-400'
                            : inc.risk_score >= 70
                            ? 'text-orange-400'
                            : 'text-yellow-400'
                        }
                      >
                        {Math.round(inc.risk_score)}
                      </span>
                      <span className="text-[10px] text-slate-500 font-normal"> /100</span>
                    </td>
                    <td className="p-3.5">
                      <span className="bg-cyan-950/60 text-cyan-300 px-2 py-0.5 rounded border border-cyan-800/40 text-[10px]">
                        {inc.mitre_mapping?.technique_id || 'T1110'}
                      </span>
                    </td>
                    <td className="p-3.5">
                      <StatusBadge status={inc.status} />
                    </td>
                    <td className="p-3.5 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectIncident(inc.incident_id);
                        }}
                        className="p-1.5 rounded bg-cyan-950/50 hover:bg-cyan-900/50 text-cyan-400 border border-cyan-800/40 transition-colors inline-flex items-center space-x-1"
                      >
                        <span>Investigate</span>
                        <ArrowRight className="w-3 h-3" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

