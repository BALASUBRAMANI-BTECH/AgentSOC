import React, { useState } from 'react';
import { SecurityEvent, UserProfile } from '../types/soc';
import { SeverityBadge } from '../components/IncidentBadge';
import { api } from '../services/api';
import { Radio, Search, Plus, Terminal, RefreshCw } from 'lucide-react';

interface EventsViewProps {
  events: SecurityEvent[];
  user: UserProfile | null;
  onRefresh: () => void;
}

export const EventsView: React.FC<EventsViewProps> = ({ events, user, onRefresh }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [showInjectModal, setShowInjectModal] = useState(false);
  const [injectIp, setInjectIp] = useState('192.168.1.50');
  const [injectUser, setInjectUser] = useState('admin');
  const [injectType, setInjectType] = useState('login_failed');
  const [injectMsg, setInjectMsg] = useState('Multiple incorrect credentials provided over SSH');
  const [loading, setLoading] = useState(false);

  const filteredEvents = events.filter((ev) => {
    return (
      searchTerm === '' ||
      ev.source_ip.includes(searchTerm) ||
      ev.event_type.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (ev.username && ev.username.toLowerCase().includes(searchTerm.toLowerCase())) ||
      ev.message.toLowerCase().includes(searchTerm.toLowerCase())
    );
  });

  const handleInject = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      await api.ingestEvent({
        source_ip: injectIp,
        destination_ip: '10.0.0.5',
        username: injectUser,
        event_type: injectType,
        severity: 'HIGH',
        message: injectMsg,
        metadata: { manual_test: true },
      });
      setShowInjectModal(false);
      onRefresh();
    } catch (err) {
      console.error('Failed to ingest event', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-mono font-black uppercase text-white tracking-wider flex items-center space-x-2">
            <Radio className="w-5 h-5 text-cyan-400 animate-pulse" />
            <span>Real-Time Security Event Telemetry</span>
          </h2>
          <p className="text-xs font-mono text-slate-400 mt-1">
            Raw event stream ingested via Redis/Memurai sliding window buffers
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={onRefresh}
            className="p-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
          <button
            onClick={() => setShowInjectModal(true)}
            className="flex items-center space-x-1.5 px-3 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-mono text-xs font-bold uppercase tracking-wider transition-all"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Ingest Test Event</span>
          </button>
        </div>
      </div>

      {/* Search Bar */}
      <div className="relative">
        <Search className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
        <input
          type="text"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          placeholder="Filter raw events by source IP, user, type, message..."
          className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-9 pr-4 py-2.5 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
        />
      </div>

      {/* Table */}
      <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs border-collapse">
            <thead>
              <tr className="bg-slate-900/80 text-slate-400 border-b border-slate-800 uppercase text-[10px] tracking-wider">
                <th className="p-3">Timestamp</th>
                <th className="p-3">Event Type</th>
                <th className="p-3">Source IP</th>
                <th className="p-3">Target User</th>
                <th className="p-3">Severity</th>
                <th className="p-3">Message</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={6} className="p-8 text-center text-slate-500 font-mono text-xs">
                    No telemetry events received yet. Click "Ingest Test Event" or trigger a simulation.
                  </td>
                </tr>
              ) : (
                filteredEvents.map((ev, idx) => (
                  <tr key={ev.event_id || idx} className="hover:bg-slate-900/40 transition-colors">
                    <td className="p-3 text-slate-400 text-[11px] whitespace-nowrap">
                      {new Date(ev.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="p-3 font-bold text-cyan-400 whitespace-nowrap">
                      {ev.event_type}
                    </td>
                    <td className="p-3 text-slate-300 whitespace-nowrap">
                      <span className="bg-slate-900 px-2 py-0.5 rounded border border-slate-800 text-red-400 font-bold">
                        {ev.source_ip}
                      </span>
                    </td>
                    <td className="p-3 text-yellow-400 whitespace-nowrap">
                      {ev.username || '—'}
                    </td>
                    <td className="p-3 whitespace-nowrap">
                      <SeverityBadge severity={ev.severity} size="sm" />
                    </td>
                    <td className="p-3 text-slate-300 max-w-md truncate">
                      {ev.message}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Test Event Modal */}
      {showInjectModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-xl p-6 max-w-md w-full font-mono text-xs space-y-4">
            <h3 className="text-sm font-bold uppercase text-white flex items-center space-x-2">
              <Terminal className="w-4 h-4 text-cyan-400" />
              <span>Ingest Security Event</span>
            </h3>

            <form onSubmit={handleInject} className="space-y-3">
              <div>
                <label className="text-slate-400 block mb-1">Source IP</label>
                <input
                  type="text"
                  value={injectIp}
                  onChange={(e) => setInjectIp(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Target Username</label>
                <input
                  type="text"
                  value={injectUser}
                  onChange={(e) => setInjectUser(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Event Type</label>
                <input
                  type="text"
                  value={injectType}
                  onChange={(e) => setInjectType(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Message</label>
                <textarea
                  value={injectMsg}
                  onChange={(e) => setInjectMsg(e.target.value)}
                  rows={2}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200"
                />
              </div>

              <div className="flex justify-end space-x-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowInjectModal(false)}
                  className="px-3 py-1.5 rounded border border-slate-700 text-slate-400"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="px-4 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-bold"
                >
                  {loading ? 'Ingesting...' : 'Ingest Event'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

