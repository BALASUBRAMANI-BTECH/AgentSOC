import React from 'react';
import { IncidentSeverity, IncidentStatus } from '../types/soc';

interface SeverityBadgeProps {
  severity: IncidentSeverity;
  size?: 'sm' | 'md' | 'lg';
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, size = 'md' }) => {
  const sizeClasses = {
    sm: 'text-xs px-2 py-0.5',
    md: 'text-xs px-2.5 py-1',
    lg: 'text-sm px-3 py-1.5 font-bold',
  };

  const styleMap: Record<IncidentSeverity, string> = {
    CRITICAL: 'bg-red-500/10 text-red-400 border border-red-500/30 shadow-[0_0_10px_rgba(239,68,68,0.2)]',
    HIGH: 'bg-orange-500/10 text-orange-400 border border-orange-500/30 shadow-[0_0_10px_rgba(249,115,22,0.15)]',
    MEDIUM: 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/30',
    LOW: 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30',
  };

  return (
    <span className={`inline-flex items-center font-mono uppercase tracking-wider rounded-md font-semibold ${styleMap[severity]} ${sizeClasses[size]}`}>
      <span className="w-1.5 h-1.5 rounded-full mr-1.5 bg-current animate-pulse" />
      {severity}
    </span>
  );
};

interface StatusBadgeProps {
  status: IncidentStatus;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status }) => {
  const styleMap: Record<IncidentStatus, string> = {
    OPEN: 'bg-rose-950/40 text-rose-300 border border-rose-800/40',
    INVESTIGATING: 'bg-sky-950/40 text-sky-300 border border-sky-800/40 animate-pulse',
    CONTAINED: 'bg-emerald-950/40 text-emerald-300 border border-emerald-800/40',
    RESOLVED: 'bg-slate-800 text-slate-300 border border-slate-700',
    CLOSED: 'bg-slate-900 text-slate-500 border border-slate-800',
  };

  return (
    <span className={`inline-flex items-center text-xs font-mono px-2 py-0.5 rounded border font-medium ${styleMap[status] || 'bg-slate-800 text-slate-300'}`}>
      {status}
    </span>
  );
};

