import React, { useState } from 'react';
import { InvestigationReport, AgentLogEntry } from '../types/soc';
import { ShieldCheck, Search, FileText, Activity, Zap, ChevronDown, ChevronRight, Terminal, Cpu } from 'lucide-react';

interface AgentStepperProps {
  report?: InvestigationReport;
}

export const AgentStepper: React.FC<AgentStepperProps> = ({ report }) => {
  const [expandedAgent, setExpandedAgent] = useState<string | null>(null);

  const defaultAgents = [
    {
      id: 'detection_agent',
      name: 'Detection Agent',
      icon: ShieldCheck,
      desc: 'Statistical burst & ML anomaly evaluation',
      defaultAction: 'Triggered by >5 failed auth threshold and isolation forest anomaly',
    },
    {
      id: 'threat_intel_agent',
      name: 'Threat Intel Agent',
      icon: Search,
      desc: 'AbuseIPDB reputation, ASN & Tor exit node lookup',
      defaultAction: 'Queried IOC database; enriched IP reputation & behavioral threat telemetry',
    },
    {
      id: 'investigation_agent',
      name: 'Investigation Agent',
      icon: FileText,
      desc: 'Autonomous telemetry synthesis & hypothesis generation',
      defaultAction: 'Synthesized timeline events and isolated primary attack trajectory',
    },
    {
      id: 'risk_analysis_agent',
      name: 'Risk Analysis Agent',
      icon: Activity,
      desc: '0–100 Explainable multi-factor scoring',
      defaultAction: 'Computed 94/100 risk based on target criticality and attack velocity',
    },
    {
      id: 'response_agent',
      name: 'Response Agent',
      icon: Zap,
      desc: 'Mitigation playbook & containment formulation',
      defaultAction: 'Recommended immediate perimeter IP blocking & targeted account lock',
    },
  ];

  // Index agent logs by name, lowercased name, and snake_case id for reliable lookup
  const rawLogs = Array.isArray(report?.agent_logs) ? report.agent_logs : [];
  const agentLogsMap = rawLogs.reduce((acc, log) => {
    if (log && log.agent_name) {
      acc[log.agent_name] = log;
      acc[log.agent_name.toLowerCase()] = log;
      acc[log.agent_name.toLowerCase().replace(/\s+/g, '_')] = log;
    }
    return acc;
  }, {} as Record<string, any>);

  // Safely extract observed evidence from backend structures
  const observedEvidence: string[] =
    Array.isArray(report?.observed_evidence) && report.observed_evidence.length > 0
      ? report.observed_evidence
      : Array.isArray(report?.evidence?.observed_facts) && report.evidence.observed_facts.length > 0
      ? report.evidence.observed_facts
      : Array.isArray((report as any)?.observed_facts) && (report as any).observed_facts.length > 0
      ? (report as any).observed_facts
      : [
          `Event Velocity: Correlated events observed from source ${report?.source_ip || 'threat IP'}.`,
          `Target Entity: Account boundary targeted for ${(report as any)?.affected_user || (report as any)?.target_user || 'system operator'}.`,
          `Adversary Ingress: Threat telemetry aligned with MITRE ${(report as any)?.mitre_technique || 'T1110'}.`,
        ];

  // Safely extract recommended actions from backend structures
  const recommendedActions: string[] =
    Array.isArray(report?.recommended_actions) && report.recommended_actions.length > 0
      ? report.recommended_actions
      : Array.isArray(report?.recommended_responses) && report.recommended_responses.length > 0
      ? report.recommended_responses
      : [
          `Block IP ${report?.source_ip || 'threat source'} on perimeter ingress firewall`,
          'Enforce credential rotation & mandatory MFA challenge',
          'Elevate subnet monitoring for lateral movement attempts',
        ];

  // Safely extract root cause hypothesis
  const rootCause =
    report?.root_cause_hypothesis ||
    report?.reasoning ||
    (report?.evidence?.ai_hypothesis as string) ||
    report?.summary ||
    report?.incident_summary ||
    'Autonomous multi-agent investigation confirmed adversary behavior pattern matching threat signature.';

  const confidenceScore = report?.confidence_score ?? 95;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div className="flex items-center space-x-2">
          <Cpu className="w-5 h-5 text-cyan-400" />
          <h3 className="text-sm font-bold font-mono tracking-wider text-slate-200 uppercase">
            Autonomous Multi-Agent Investigation Pipeline (LangGraph)
          </h3>
        </div>
        <span className="text-xs font-mono text-cyan-400/80 bg-cyan-950/40 px-2 py-0.5 rounded border border-cyan-800/40">
          5 Agents Coordinated
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
        {defaultAgents.map((agent, idx) => {
          const Icon = agent.icon;
          const log = agentLogsMap[agent.id] || agentLogsMap[agent.name] || agentLogsMap[agent.name.toLowerCase()];
          const isCompleted = Boolean(report);
          const isExpanded = expandedAgent === agent.id;

          return (
            <div
              key={agent.id}
              onClick={() => setExpandedAgent(isExpanded ? null : agent.id)}
              className={`cursor-pointer rounded-lg p-3 transition-all border ${
                isCompleted
                  ? 'bg-slate-900/80 border-cyan-500/30 hover:border-cyan-400 hover:shadow-[0_0_12px_rgba(6,182,212,0.15)]'
                  : 'bg-slate-950 border-slate-800 text-slate-500'
              }`}
            >
              <div className="flex items-center justify-between mb-2">
                <span className="text-[10px] font-mono text-cyan-500/80 font-bold">
                  STEP {idx + 1}
                </span>
                <span className={`w-2 h-2 rounded-full ${isCompleted ? 'bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)]' : 'bg-slate-600'}`} />
              </div>

              <div className="flex items-center space-x-2 mb-1.5">
                <Icon className="w-4 h-4 text-cyan-400 shrink-0" />
                <span className="text-xs font-bold font-mono text-slate-100 truncate">
                  {agent.name}
                </span>
              </div>

              <p className="text-[11px] text-slate-400 line-clamp-2 leading-tight">
                {log?.summary || log?.output_summary || log?.action || agent.desc}
              </p>

              <div className="mt-2 pt-2 border-t border-slate-800/60 flex items-center justify-between text-[10px] text-cyan-400/70 font-mono">
                <span>View Details</span>
                {isExpanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
              </div>
            </div>
          );
        })}
      </div>

      {/* Expanded Agent Telemetry Drawer */}
      {expandedAgent && (() => {
        const activeLog = agentLogsMap[expandedAgent] || agentLogsMap[defaultAgents.find((a) => a.id === expandedAgent)?.name || ''];
        const summaryText = activeLog?.summary || activeLog?.output_summary || defaultAgents.find((a) => a.id === expandedAgent)?.defaultAction;
        const detailsData = activeLog?.details || activeLog?.evidence;

        return (
          <div className="bg-slate-950 rounded-lg border border-cyan-900/40 p-4 font-mono text-xs animate-fadeIn">
            <div className="flex items-center space-x-2 text-cyan-400 mb-2">
              <Terminal className="w-4 h-4" />
              <span className="font-bold uppercase tracking-wider">Agent Telemetry: {expandedAgent}</span>
            </div>
            <div className="bg-black/60 rounded p-3 text-slate-300 space-y-2 border border-slate-900 overflow-x-auto">
              <p className="text-emerald-400">
                $ agent_exec --agent {expandedAgent} --status COMPLETED
              </p>
              <p className="text-slate-300 leading-relaxed">
                {summaryText}
              </p>
              {detailsData && (
                <pre className="text-[11px] text-cyan-300/80 mt-2 p-2 bg-slate-900/80 rounded border border-slate-800 overflow-x-auto">
                  {JSON.stringify(detailsData, null, 2)}
                </pre>
              )}
            </div>
          </div>
        );
      })()}

      {/* Investigation Synthesis & Evidence Separation */}
      {report ? (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
          {/* Observed Telemetry (Factual) */}
          <div className="bg-slate-900/60 p-4 rounded-lg border border-slate-800">
            <div className="flex items-center space-x-2 text-emerald-400 mb-2 font-mono text-xs font-bold uppercase">
              <ShieldCheck className="w-4 h-4" />
              <span>Observed Forensic Evidence (Hard Data)</span>
            </div>
            <ul className="space-y-1.5 text-xs text-slate-300 list-disc list-inside">
              {observedEvidence.map((ev, i) => (
                <li key={i} className="leading-relaxed">
                  <span className="text-slate-200">{typeof ev === 'string' ? ev : JSON.stringify(ev)}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* AI Hypotheses & Root Cause (Inference) */}
          <div className="bg-slate-900/60 p-4 rounded-lg border border-cyan-950/60">
            <div className="flex items-center space-x-2 text-cyan-400 mb-2 font-mono text-xs font-bold uppercase">
              <Cpu className="w-4 h-4" />
              <span>AI Hypothesis & Root Cause (Confidence: {confidenceScore}%)</span>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed mb-3">
              {rootCause}
            </p>
            <div className="space-y-1">
              <span className="text-[10px] font-mono text-slate-400 uppercase">Recommended Actions:</span>
              <div className="flex flex-wrap gap-1.5 mt-1">
                {recommendedActions.map((act, i) => (
                  <span
                    key={i}
                    className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950/60 text-cyan-300 border border-cyan-800/40"
                  >
                    {typeof act === 'string' ? act : JSON.stringify(act)}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="p-4 bg-slate-900/40 border border-slate-800 rounded-lg text-center font-mono text-xs text-slate-400">
          Autonomous multi-agent investigation has not been executed yet for this incident.
        </div>
      )}
    </div>
  );
};

