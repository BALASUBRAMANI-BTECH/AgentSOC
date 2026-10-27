import React from 'react';
import { UserProfile } from '../types/soc';
import { ConnectionStatus } from '../hooks/useSocRealtime';
import { Shield, Radio, Lock, LogOut, Bot, Key, Eye } from 'lucide-react';

interface NavbarProps {
  user: UserProfile | null;
  wsStatus: ConnectionStatus;
  onLogout: () => void;
  onToggleCopilot: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  user,
  wsStatus,
  onLogout,
  onToggleCopilot,
}) => {
  const isAdmin = user?.role === 'SOC_ADMIN';

  return (
    <header className="h-16 bg-slate-950 border-b border-slate-800 px-6 flex items-center justify-between sticky top-0 z-40">
      {/* Brand & Subtitle */}
      <div className="flex items-center space-x-3">
        <div className="p-2 rounded-xl bg-cyan-950/80 border border-cyan-500/40 text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.25)]">
          <Shield className="w-5 h-5" />
        </div>
        <div>
          <div className="flex items-center space-x-2">
            <span className="font-mono font-black text-lg text-white tracking-wider">
              Agent<span className="text-cyan-400">SOC</span>
            </span>
            <span className="text-[10px] font-mono font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 px-1.5 py-0.5 rounded">
              v2.0 AUTONOMOUS
            </span>
          </div>
          <p className="text-[11px] font-mono text-slate-400">
            Autonomous AI-Powered Security Operations Center
          </p>
        </div>
      </div>

      {/* Center Status: Live WebSocket & Master Lock Indicator */}
      <div className="hidden md:flex items-center space-x-4">
        {/* WS Indicator */}
        <div className="flex items-center space-x-2 px-3 py-1 rounded-full bg-slate-900 border border-slate-800 text-xs font-mono">
          <span
            className={`w-2 h-2 rounded-full ${
              wsStatus === 'connected'
                ? 'bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)] animate-pulse'
                : wsStatus === 'connecting'
                ? 'bg-yellow-400 animate-pulse'
                : 'bg-red-500'
            }`}
          />
          <span className="text-slate-300 uppercase tracking-wider">
            {wsStatus === 'connected' ? 'STREAM: LIVE' : `STREAM: ${wsStatus}`}
          </span>
        </div>

        {/* Admin Password Status Indicator */}
        <div className="flex items-center space-x-1.5 px-3 py-1 rounded-full bg-slate-900 border border-slate-800 text-xs font-mono text-slate-400">
          <Key className="w-3.5 h-3.5 text-cyan-400" />
          <span>Admin Master Key:</span>
          <span className="text-cyan-300 font-bold tracking-wider">24282428</span>
          <span className="text-[10px] text-emerald-400 font-bold bg-emerald-950/60 px-1 rounded border border-emerald-800">
            LOCKED
          </span>
        </div>
      </div>

      {/* User info, AI Copilot toggle & Logout */}
      <div className="flex items-center space-x-3">
        <button
          onClick={onToggleCopilot}
          className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-cyan-950/50 hover:bg-cyan-900/50 border border-cyan-800/60 text-cyan-300 text-xs font-mono transition-all hover:shadow-[0_0_12px_rgba(6,182,212,0.2)]"
        >
          <Bot className="w-4 h-4 text-cyan-400" />
          <span>AI Copilot</span>
        </button>

        {user && (
          <div className="flex items-center space-x-3 pl-2 border-l border-slate-800">
            <div className="flex flex-col text-right">
              <span className="text-xs font-mono font-bold text-slate-200">
                {user.display_name || user.username}
              </span>
              <span
                className={`text-[10px] font-mono uppercase font-bold tracking-wider px-1.5 py-0.5 rounded border inline-block ${
                  isAdmin
                    ? 'text-cyan-300 bg-cyan-950/80 border-cyan-700/60'
                    : 'text-amber-300 bg-amber-950/80 border-amber-700/60'
                }`}
              >
                {isAdmin ? 'SOC_ADMIN (Full Control)' : 'SOC_ANALYST (View-Only)'}
              </span>
            </div>

            <button
              onClick={onLogout}
              title="Sign Out"
              className="p-2 text-slate-400 hover:text-red-400 rounded-lg hover:bg-slate-900 border border-transparent hover:border-slate-800 transition-colors"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        )}
      </div>
    </header>
  );
};

