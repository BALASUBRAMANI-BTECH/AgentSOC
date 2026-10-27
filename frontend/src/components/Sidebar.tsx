import React from 'react';
import { LayoutDashboard, AlertTriangle, Radio, Shield, History, Activity, Cpu, Globe } from 'lucide-react';

export type NavTab = 'dashboard' | 'incidents' | 'events' | 'mitre' | 'threat_intel' | 'audit';

interface SidebarProps {
  currentTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  incidentCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onSelectTab,
  incidentCount,
}) => {
  const menuItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'incidents', label: 'Incidents', icon: AlertTriangle, badge: incidentCount },
    { id: 'events', label: 'Live Telemetry', icon: Radio },
    { id: 'mitre', label: 'MITRE ATT&CK', icon: Shield },
    { id: 'threat_intel', label: 'Threat Intel', icon: Globe },
    { id: 'audit', label: 'Audit Trail', icon: History },
  ];

  return (
    <aside className="w-64 bg-slate-950 border-r border-slate-800 flex flex-col justify-between shrink-0">
      <div className="p-4 space-y-6">
        {/* Navigation Section */}
        <div className="space-y-1">
          <div className="px-3 text-[10px] font-mono font-bold uppercase text-slate-500 tracking-wider mb-2">
            Operations Center
          </div>
          {menuItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onSelectTab(item.id as NavTab)}
                className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-mono transition-all ${
                  isActive
                    ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 shadow-[0_0_10px_rgba(6,182,212,0.15)] font-bold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent'
                }`}
              >
                <div className="flex items-center space-x-2.5">
                  <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                  <span>{item.label}</span>
                </div>
                {item.badge !== undefined && item.badge > 0 && (
                  <span className="text-[10px] px-2 py-0.5 rounded-full bg-red-500/20 text-red-400 border border-red-500/30 font-bold">
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* Engine Telemetry Bottom Status */}
      <div className="p-4 border-t border-slate-900 bg-slate-950/40 text-xs font-mono space-y-2.5">
        <div className="text-[10px] uppercase font-bold text-slate-500 tracking-wider flex items-center space-x-1.5">
          <Activity className="w-3.5 h-3.5 text-cyan-500" />
          <span>SOC Engine Status</span>
        </div>

        <div className="space-y-1.5 text-[11px] text-slate-400">
          <div className="flex justify-between items-center">
            <span>Stream Pipeline:</span>
            <span className="text-emerald-400 font-semibold flex items-center">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 mr-1 animate-pulse" />
              Active
            </span>
          </div>

          <div className="flex justify-between items-center">
            <span>Detection Layer:</span>
            <span className="text-cyan-400 font-semibold">Rules + ML</span>
          </div>

          <div className="flex justify-between items-center">
            <span>AI Orchestration:</span>
            <span className="text-indigo-400 font-semibold">LangGraph 5-Agent</span>
          </div>

          <div className="flex justify-between items-center">
            <span>Scoring Engine:</span>
            <span className="text-slate-300 font-semibold">0–100 Multi-Factor</span>
          </div>
        </div>
      </div>
    </aside>
  );
};

