import React, { useState } from 'react';
import { Incident, ResponseActionType, UserProfile } from '../types/soc';
import { api } from '../services/api';
import { ShieldAlert, Lock, CheckCircle, X, AlertTriangle, Play } from 'lucide-react';

interface MitigationModalProps {
  incident: Incident;
  user: UserProfile | null;
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

export const MitigationModal: React.FC<MitigationModalProps> = ({
  incident,
  user,
  isOpen,
  onClose,
  onSuccess,
}) => {
  const [selectedAction, setSelectedAction] = useState<ResponseActionType>('BLOCK_IP');
  const [simulated, setSimulated] = useState<boolean>(true);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  if (!isOpen) return null;

  const isAdmin = user?.role === 'SOC_ADMIN';

  const handleExecute = async () => {
    if (!isAdmin) {
      setError('Forbidden: Analyst role has read-only access. Only SOC Administrators can authorize containment.');
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const target = selectedAction === 'LOCK_ACCOUNT' ? incident.target_user || 'admin' : incident.source_ip;
      await api.executeResponse(incident.incident_id, selectedAction, target, simulated);
      setSuccessMsg(`Action ${selectedAction} successfully triggered against ${target}`);
      setTimeout(() => {
        onSuccess();
        onClose();
      }, 1500);
    } catch (err: any) {
      setError(err.message || 'Failed to execute response');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
      <div className="bg-slate-900 border border-slate-700 rounded-xl shadow-2xl max-w-lg w-full overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between p-4 bg-slate-950 border-b border-slate-800">
          <div className="flex items-center space-x-2">
            <ShieldAlert className="w-5 h-5 text-red-400" />
            <h3 className="font-mono font-bold text-slate-100 uppercase tracking-wider">
              Execute Defensive Containment
            </h3>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 space-y-4">
          {/* Target details */}
          <div className="bg-slate-950/80 p-3 rounded-lg border border-slate-800 font-mono text-xs space-y-1">
            <div className="flex justify-between">
              <span className="text-slate-400">Incident Target:</span>
              <span className="text-cyan-400 font-bold">{incident.incident_id}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Threat Vector:</span>
              <span className="text-orange-400">{incident.attack_type}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Source IP:</span>
              <span className="text-red-400">{incident.source_ip}</span>
            </div>
            {incident.target_user && (
              <div className="flex justify-between">
                <span className="text-slate-400">Targeted Account:</span>
                <span className="text-yellow-400 font-bold">{incident.target_user}</span>
              </div>
            )}
          </div>

          {/* Action selection */}
          <div className="space-y-2">
            <label className="block text-xs font-mono text-slate-300 uppercase">
              Select Containment Action:
            </label>
            <div className="grid grid-cols-3 gap-2">
              {[
                { id: 'BLOCK_IP', label: 'Block IP', target: incident.source_ip },
                { id: 'LOCK_ACCOUNT', label: 'Lock Account', target: incident.target_user || 'admin' },
                { id: 'ISOLATE_HOST', label: 'Isolate Host', target: incident.source_ip },
              ].map((act) => (
                <button
                  key={act.id}
                  type="button"
                  onClick={() => setSelectedAction(act.id as ResponseActionType)}
                  className={`p-2.5 rounded text-xs font-mono border text-center transition-all ${
                    selectedAction === act.id
                      ? 'border-red-500 bg-red-500/20 text-red-200 font-bold shadow-[0_0_10px_rgba(239,68,68,0.2)]'
                      : 'border-slate-800 bg-slate-950 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  {act.label}
                </button>
              ))}
            </div>
          </div>

          {/* Simulation Mode Toggle */}
          <div className="flex items-center justify-between p-3 rounded bg-slate-950/60 border border-slate-800 text-xs font-mono">
            <div>
              <span className="text-slate-200 font-semibold block">Simulated Execution</span>
              <span className="text-slate-500 text-[11px]">Audit and log containment safely</span>
            </div>
            <input
              type="checkbox"
              checked={simulated}
              onChange={(e) => setSimulated(e.target.checked)}
              className="h-4 w-4 rounded bg-slate-900 border-slate-700 text-cyan-500 focus:ring-cyan-400"
            />
          </div>

          {/* RBAC Warning Banner for Analysts */}
          {!isAdmin && (
            <div className="p-3 bg-amber-500/10 border border-amber-500/30 rounded-lg flex items-start space-x-3 text-amber-300 text-xs">
              <Lock className="w-5 h-5 shrink-0 text-amber-400 mt-0.5" />
              <div>
                <span className="font-bold block uppercase font-mono tracking-wider">
                  Analyst Role: Read-Only Access
                </span>
                <p className="mt-0.5 text-slate-400">
                  Containment execution is restricted to <span className="text-amber-300 font-bold">SOC Administrators</span>.
                  Login with master credentials (<code className="text-cyan-400">24282428</code>) to authorize response playbooks.
                </p>
              </div>
            </div>
          )}

          {error && (
            <div className="p-3 bg-red-500/10 border border-red-500/30 rounded text-red-400 text-xs font-mono flex items-center space-x-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {successMsg && (
            <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded text-emerald-400 text-xs font-mono flex items-center space-x-2">
              <CheckCircle className="w-4 h-4 shrink-0" />
              <span>{successMsg}</span>
            </div>
          )}
        </div>

        {/* Footer actions */}
        <div className="p-4 bg-slate-950 border-t border-slate-800 flex justify-end space-x-3">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 text-xs font-mono text-slate-400 hover:text-white rounded border border-slate-800 hover:bg-slate-900"
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={!isAdmin || loading}
            onClick={handleExecute}
            className={`px-4 py-2 text-xs font-mono font-bold rounded flex items-center space-x-2 uppercase tracking-wider transition-all ${
              isAdmin
                ? 'bg-red-600 hover:bg-red-500 text-white shadow-[0_0_15px_rgba(239,68,68,0.4)]'
                : 'bg-slate-800 text-slate-600 cursor-not-allowed border border-slate-700'
            }`}
          >
            <Play className="w-3.5 h-3.5" />
            <span>{loading ? 'Executing...' : 'Authorize Containment'}</span>
          </button>
        </div>
      </div>
    </div>
  );
};

