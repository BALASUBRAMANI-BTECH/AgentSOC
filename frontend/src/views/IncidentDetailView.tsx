import React, { useState } from 'react';
import { Incident, IncidentStatus, UserProfile, ResponseActionType } from '../types/soc';
import { SeverityBadge, StatusBadge } from '../components/IncidentBadge';
import { RiskGauge } from '../components/RiskGauge';
import { AgentStepper } from '../components/AgentStepper';
import { MitigationModal } from '../components/MitigationModal';
import { api } from '../services/api';
import {
  ArrowLeft,
  Shield,
  AlertTriangle,
  Clock,
  User,
  Radio,
  Lock,
  CheckCircle,
  ExternalLink,
  Zap,
  Terminal,
  FileText,
  Activity,
  ChevronRight,
  Download,
} from 'lucide-react';

interface IncidentDetailViewProps {
  incident: Incident;
  user: UserProfile | null;
  onBack: () => void;
  onRefresh: () => void;
  onOpenCopilot: () => void;
}

export const IncidentDetailView: React.FC<IncidentDetailViewProps> = ({
  incident,
  user,
  onBack,
  onRefresh,
  onOpenCopilot,
}) => {
  const [modalOpen, setModalOpen] = useState(false);
  const [statusUpdating, setStatusUpdating] = useState(false);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const [investigating, setInvestigating] = useState(false);

  const isAdmin = user?.role === 'SOC_ADMIN';

  const handleTriggerInvestigation = async () => {
    if (!isAdmin) {
      setStatusError('Forbidden: Analyst role is restricted from triggering new AI investigations.');
      return;
    }
    setInvestigating(true);
    setStatusError(null);
    try {
      await api.triggerInvestigation(incident.incident_id);
      onRefresh();
    } catch (err: any) {
      setStatusError(err.message || 'Failed to execute AI investigation');
    } finally {
      setInvestigating(false);
    }
  };

  const handleExportReport = async () => {
    setExporting(true);
    try {
      const markdown = await api.downloadForensicReport(incident.incident_id);
      const blob = new Blob([markdown], { type: 'text/markdown;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `forensic-dossier-${incident.incident_id}.md`);
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    } catch (err: any) {
      alert(`Export failed: ${err.message}`);
    } finally {
      setExporting(false);
    }
  };

  const handleStatusChange = async (newStatus: IncidentStatus) => {
    if (!isAdmin) {
      setStatusError('Forbidden: Analyst role is restricted from changing incident status.');
      return;
    }
    setStatusUpdating(true);
    setStatusError(null);
    try {
      await api.updateIncidentStatus(incident.incident_id, newStatus);
      onRefresh();
    } catch (err: any) {
      setStatusError(err.message || 'Failed to update status');
    } finally {
      setStatusUpdating(false);
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Back Button & Header Breadcrumb */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <button
          onClick={onBack}
          className="inline-flex items-center space-x-2 text-xs font-mono text-cyan-400 hover:text-cyan-300 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to All Incidents</span>
        </button>

        <div className="flex flex-wrap items-center gap-2.5">
          <button
            onClick={handleTriggerInvestigation}
            disabled={investigating}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-sky-950/50 hover:bg-sky-900/60 border border-sky-700/60 text-sky-300 text-xs font-mono transition-all disabled:opacity-50"
            title="Execute LangGraph 5-Agent Pipeline"
          >
            <Activity className={`w-3.5 h-3.5 text-sky-400 ${investigating ? 'animate-spin' : ''}`} />
            <span>{investigating ? 'Investigating...' : 'Run AI Investigation'}</span>
          </button>

          <button
            onClick={handleExportReport}
            disabled={exporting}
            className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-mono transition-all disabled:opacity-50"
            title="Download complete Markdown forensic report"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>{exporting ? 'Exporting...' : 'Export Dossier'}</span>
          </button>

          <button
            onClick={onOpenCopilot}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-cyan-950/40 hover:bg-cyan-900/60 border border-cyan-800 text-cyan-300 text-xs font-mono transition-all"
          >
            <Zap className="w-3.5 h-3.5 text-cyan-400" />
            <span>Ask Copilot</span>
          </button>

          <button
            onClick={() => setModalOpen(true)}
            className="flex items-center space-x-1.5 px-4 py-1.5 rounded-lg bg-red-600 hover:bg-red-500 text-white font-mono text-xs font-bold uppercase tracking-wider shadow-[0_0_15px_rgba(239,68,68,0.3)] transition-all"
          >
            <Shield className="w-3.5 h-3.5" />
            <span>Containment Actions</span>
          </button>
        </div>
      </div>

      {/* Main Incident Banner */}
      <div className="p-6 bg-slate-950 border border-slate-800 rounded-2xl shadow-xl space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center space-x-3">
              <span className="text-sm font-mono font-bold text-cyan-400 bg-cyan-950/80 px-2 py-0.5 rounded border border-cyan-800/60">
                {incident.incident_id}
              </span>
              <SeverityBadge severity={incident.severity} size="lg" />
              <StatusBadge status={incident.status} />
            </div>
            <h1 className="text-xl font-mono font-black text-white mt-1">
              {incident.title}
            </h1>
            <p className="text-xs font-mono text-slate-400">
              {incident.description}
            </p>
          </div>

          {/* Status Changer & RBAC indicator */}
          <div className="flex flex-col items-end space-y-1">
            <div className="flex items-center space-x-2 text-xs font-mono">
              <span className="text-slate-400">Lifecycle Status:</span>
              <select
                disabled={!isAdmin || statusUpdating}
                value={incident.status}
                onChange={(e) => handleStatusChange(e.target.value as IncidentStatus)}
                className={`bg-slate-900 border rounded-lg px-2.5 py-1.5 text-xs font-mono font-bold ${
                  isAdmin
                    ? 'border-cyan-700 text-cyan-300 focus:outline-none'
                    : 'border-slate-800 text-slate-500 cursor-not-allowed'
                }`}
              >
                <option value="OPEN">OPEN</option>
                <option value="INVESTIGATING">INVESTIGATING</option>
                <option value="CONTAINED">CONTAINED</option>
                <option value="RESOLVED">RESOLVED</option>
                <option value="CLOSED">CLOSED</option>
              </select>
            </div>
            {!isAdmin && (
              <span className="text-[10px] font-mono text-amber-400/80 flex items-center space-x-1">
                <Lock className="w-3 h-3" />
                <span>Status lock: Admin clearance required</span>
              </span>
            )}
            {statusError && (
              <span className="text-[10px] font-mono text-red-400">{statusError}</span>
            )}
          </div>
        </div>

        {/* Forensic Metadata Badges */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-3 border-t border-slate-800/80 text-xs font-mono">
          <div className="bg-slate-900/60 p-2.5 rounded-lg border border-slate-800">
            <span className="text-slate-500 block text-[10px] uppercase">Adversary Source IP</span>
            <span className="text-red-400 font-bold">{incident.source_ip || 'N/A'}</span>
          </div>

          <div className="bg-slate-900/60 p-2.5 rounded-lg border border-slate-800">
            <span className="text-slate-500 block text-[10px] uppercase">Targeted User</span>
            <span className="text-yellow-400 font-bold">{incident.target_user || (incident as any).username || 'root/admin'}</span>
          </div>

          <div className="bg-slate-900/60 p-2.5 rounded-lg border border-slate-800">
            <span className="text-slate-500 block text-[10px] uppercase">Correlated Events</span>
            <span className="text-cyan-400 font-bold">
              {(incident as any).related_event_ids?.length || incident.event_ids?.length || (incident as any).event_count || 1} Events
            </span>
          </div>

          <div className="bg-slate-900/60 p-2.5 rounded-lg border border-slate-800">
            <span className="text-slate-500 block text-[10px] uppercase">Detected At</span>
            <span className="text-slate-300">
              {incident.created_at ? new Date(incident.created_at).toLocaleTimeString() : new Date().toLocaleTimeString()}
            </span>
          </div>
        </div>
      </div>

      {/* Middle Row: Explainable Risk Score & MITRE ATT&CK Mapping */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
        {/* Risk Score Card (5 cols) */}
        <div className="md:col-span-5 bg-slate-950 border border-slate-800 rounded-xl p-5 shadow-lg flex flex-col justify-between">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
            <div className="flex items-center space-x-2">
              <Activity className="w-4 h-4 text-orange-400" />
              <h3 className="font-mono text-xs font-bold uppercase text-slate-200 tracking-wider">
                0–100 Explainable Risk Score
              </h3>
            </div>
            <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800">
              Calibrated
            </span>
          </div>

          <RiskGauge score={incident.risk_score ?? 0} showBreakdown={true} />

          <p className="mt-4 text-[11px] font-mono text-slate-400 text-center leading-relaxed">
            Composite risk formula weights velocity (&gt;2.5 req/s), target account privilege (admin tier), and threat intelligence abuse history.
          </p>
        </div>

        {/* MITRE ATT&CK Matrix Card (7 cols) */}
        <div className="md:col-span-7 bg-slate-950 border border-slate-800 rounded-xl p-5 shadow-lg flex flex-col justify-between">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
            <div className="flex items-center space-x-2">
              <Shield className="w-4 h-4 text-cyan-400" />
              <h3 className="font-mono text-xs font-bold uppercase text-slate-200 tracking-wider">
                MITRE ATT&CK Framework Mapping
              </h3>
            </div>
            <span className="text-[10px] font-mono text-cyan-300 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800">
              v14 Enterprise
            </span>
          </div>

          <div className="space-y-4">
            <div className="bg-slate-900/80 p-4 rounded-xl border border-cyan-900/40 space-y-2 font-mono">
              <div className="flex items-center justify-between">
                <span className="text-lg font-black text-cyan-400">
                  {incident.mitre_mapping?.technique_id || (incident as any).mitre_technique || 'T1110'}
                </span>
                <span className="text-xs px-2 py-0.5 rounded bg-orange-500/10 text-orange-400 border border-orange-500/30">
                  {incident.mitre_mapping?.tactic || 'Credential Access'}
                </span>
              </div>
              <h4 className="text-sm font-bold text-slate-200">
                {incident.mitre_mapping?.technique_name || (incident as any).mitre_name || 'Brute Force'}
              </h4>
              <p className="text-xs text-slate-400 leading-relaxed">
                {incident.mitre_mapping?.description ||
                  'Adversaries may use brute force techniques to attempt authentication by guessing or systematically attempting passwords.'}
              </p>
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs font-mono">
              <div className="p-3 bg-slate-900/50 rounded-lg border border-slate-800">
                <span className="text-slate-500 block text-[10px] uppercase">Confidence</span>
                <span className="text-emerald-400 font-bold">
                  {Math.round(((incident.mitre_mapping?.confidence ?? (incident.mitre_mapping as any)?.mapping_confidence ?? 0.95)) * 100)}% Match
                </span>
              </div>
              <div className="p-3 bg-slate-900/50 rounded-lg border border-slate-800">
                <span className="text-slate-500 block text-[10px] uppercase">Attack Surface</span>
                <span className="text-slate-200">Perimeter Ingress (SSH/API)</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Autonomous AI Multi-Agent Stepper */}
      <div className="bg-slate-950 border border-slate-800 rounded-xl p-5 shadow-xl">
        <AgentStepper report={incident.investigation_report} />
      </div>

      {/* Forensic Event Timeline */}
      <div className="bg-slate-950 border border-slate-800 rounded-xl p-5 shadow-xl space-y-4">
        <div className="flex items-center space-x-2 border-b border-slate-800 pb-3">
          <Clock className="w-4 h-4 text-cyan-400" />
          <h3 className="font-mono text-xs font-bold uppercase text-slate-200 tracking-wider">
            Chronological Forensic Timeline
          </h3>
        </div>

        <div className="space-y-3 font-mono text-xs">
          {Array.isArray(incident.timeline) && incident.timeline.length > 0 ? (
            incident.timeline.map((entry, idx) => (
              <div
                key={idx}
                className="flex items-start space-x-3 p-3 rounded-lg bg-slate-900/50 border border-slate-800/80"
              >
                <div className="p-1 rounded bg-cyan-950/80 border border-cyan-800/50 text-cyan-400 mt-0.5">
                  <ChevronRight className="w-3.5 h-3.5" />
                </div>
                <div className="flex-1 space-y-1">
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="text-cyan-400 font-bold uppercase">
                      {entry.stage || (entry as any).event_type || 'DETECTION'}
                    </span>
                    <span className="text-slate-500">
                      {entry.timestamp ? new Date(entry.timestamp).toLocaleTimeString() : 'N/A'}
                    </span>
                  </div>
                  <p className="text-slate-300 text-xs">{entry.description}</p>
                  <span className="text-[10px] text-slate-500 block">
                    Source / Actor: {entry.actor || (entry as any).source_ip || 'System Ingress'}
                  </span>
                </div>
              </div>
            ))
          ) : (
            <div className="text-slate-500 p-4 text-center">
              Initial threat detection event recorded.
            </div>
          )}
        </div>
      </div>

      {/* Mitigation Action Modal */}
      <MitigationModal
        incident={incident}
        user={user}
        isOpen={modalOpen}
        onClose={() => setModalOpen(false)}
        onSuccess={onRefresh}
      />
    </div>
  );
};

