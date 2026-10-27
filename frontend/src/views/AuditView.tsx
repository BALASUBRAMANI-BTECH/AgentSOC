import React, { useEffect, useState } from 'react';
import { ResponseAuditRecord } from '../types/soc';
import { api } from '../services/api';
import { History, Shield, CheckCircle, RefreshCw, Lock } from 'lucide-react';

export const AuditView: React.FC = () => {
  const [auditLogs, setAuditLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);

  const fetchAuditLogs = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${window.location.origin}/audit`);
      if (res.ok) {
        const data = await res.json();
        setAuditLogs(data);
      } else {
        // Fallback to /responses
        const fallbackRes = await fetch(`${window.location.origin}/responses`);
        if (fallbackRes.ok) {
          const fallbackData = await fallbackRes.json();
          setAuditLogs(fallbackData);
        }
      }
    } catch (e) {
      console.error('Failed to fetch audit records', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAuditLogs();
  }, []);

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-mono font-black uppercase text-white tracking-wider flex items-center space-x-2">
            <History className="w-5 h-5 text-cyan-400" />
            <span>Defensive Response & Containment Audit Trail</span>
          </h2>
          <p className="text-xs font-mono text-slate-400 mt-1">
            Immutable log of automated and operator-approved mitigation actions
          </p>
        </div>

        <button
          onClick={fetchAuditLogs}
          className="p-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 transition-colors"
          title="Refresh Audit Trail"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* Table */}
      <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs border-collapse">
            <thead>
              <tr className="bg-slate-900/80 text-slate-400 border-b border-slate-800 uppercase text-[10px] tracking-wider">
                <th className="p-3.5">Timestamp</th>
                <th className="p-3.5">Incident Ref</th>
                <th className="p-3.5">Action Executed</th>
                <th className="p-3.5">Target</th>
                <th className="p-3.5">Operator Clearance</th>
                <th className="p-3.5">Mode</th>
                <th className="p-3.5">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {auditLogs.length === 0 ? (
                <tr>
                  <td colSpan={7} className="p-8 text-center text-slate-500 font-mono text-xs">
                    No defensive containment actions recorded yet. Containment actions executed by SOC Administrators will be permanently logged here.
                  </td>
                </tr>
              ) : (
                auditLogs.map((log, idx) => (
                  <tr key={log.action_id || idx} className="hover:bg-slate-900/40 transition-colors">
                    <td className="p-3.5 text-slate-400 whitespace-nowrap">
                      {new Date(log.timestamp || log.executed_at).toLocaleString()}
                    </td>
                    <td className="p-3.5 font-bold text-cyan-400 whitespace-nowrap">
                      {log.incident_id}
                    </td>
                    <td className="p-3.5 font-bold text-red-400 whitespace-nowrap">
                      {log.action_type || log.action}
                    </td>
                    <td className="p-3.5 text-slate-200 whitespace-nowrap">
                      <span className="bg-slate-900 px-2 py-0.5 rounded border border-slate-800 text-yellow-400">
                        {log.target}
                      </span>
                    </td>
                    <td className="p-3.5 text-slate-300 whitespace-nowrap">
                      <span className="text-[11px] px-2 py-0.5 rounded bg-cyan-950/60 text-cyan-300 border border-cyan-800/40">
                        {log.operator || 'SOC_ADMIN'}
                      </span>
                    </td>
                    <td className="p-3.5 text-slate-400 whitespace-nowrap">
                      {log.simulated !== false ? (
                        <span className="text-cyan-400">Simulated</span>
                      ) : (
                        <span className="text-emerald-400 font-bold">Live</span>
                      )}
                    </td>
                    <td className="p-3.5 whitespace-nowrap">
                      <span className="inline-flex items-center space-x-1 text-emerald-400 text-[11px]">
                        <CheckCircle className="w-3.5 h-3.5" />
                        <span>SUCCESS</span>
                      </span>
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

