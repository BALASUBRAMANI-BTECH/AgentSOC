import React, { useState } from 'react';
import { api } from '../services/api';
import { UserProfile } from '../types/soc';
import { Shield, Lock, Key, AlertTriangle, ArrowRight, Check, Eye } from 'lucide-react';

interface LoginViewProps {
  onLoginSuccess: (user: UserProfile) => void;
}

export const LoginView: React.FC<LoginViewProps> = ({ onLoginSuccess }) => {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!password.trim()) {
      setError('Please enter a password');
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const data = await api.login(password, username);
      onLoginSuccess(data.user);
    } catch (err: any) {
      setError(err.message || 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  const fillCredentials = (type: 'admin' | 'analyst') => {
    if (type === 'admin') {
      setUsername('admin');
      setPassword('24282428');
    } else {
      setUsername('analyst');
      setPassword('analyst_pass');
    }
    setError(null);
  };

  return (
    <div className="min-h-screen bg-[#080c14] flex flex-col items-center justify-center p-4 relative overflow-hidden font-sans">
      {/* Background cyber grid & glow */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#1e293b15_1px,transparent_1px),linear-gradient(to_bottom,#1e293b15_1px,transparent_1px)] bg-[size:32px_32px] pointer-events-none" />
      <div className="absolute -top-32 -left-32 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute -bottom-32 -right-32 w-96 h-96 bg-blue-600/10 rounded-full blur-3xl pointer-events-none" />

      {/* Login Card */}
      <div className="relative z-10 w-full max-w-md bg-slate-950 border border-slate-800 rounded-2xl shadow-2xl p-8 backdrop-blur-xl">
        {/* Header */}
        <div className="flex flex-col items-center text-center mb-8">
          <div className="w-16 h-16 rounded-2xl bg-cyan-950/80 border border-cyan-500/30 flex items-center justify-center text-cyan-400 mb-4 shadow-[0_0_20px_rgba(6,182,212,0.3)] animate-pulse">
            <Shield className="w-8 h-8" />
          </div>
          <h1 className="text-2xl font-mono font-black tracking-wider text-white">
            Agent<span className="text-cyan-400">SOC</span>
          </h1>
          <p className="text-xs font-mono text-slate-400 mt-1">
            Autonomous AI-Powered Security Operations Center
          </p>
        </div>

        {/* Credentials Policy Notice */}
        <div className="mb-6 p-3.5 bg-slate-900/90 rounded-xl border border-slate-800 text-xs font-mono space-y-2">
          <div className="flex items-center space-x-2 text-cyan-400 font-bold uppercase tracking-wider">
            <Key className="w-4 h-4" />
            <span>Role-Based Access Policy</span>
          </div>
          <div className="space-y-1 text-slate-300 text-[11px] leading-relaxed">
            <p>
              • <strong className="text-cyan-300">Admin Master Password:</strong> <code className="bg-slate-950 px-1 py-0.5 rounded text-cyan-400 border border-slate-700">24282428</code> (Full Control, Containment Authorization)
            </p>
            <p>
              • <strong className="text-amber-300">Analyst Password:</strong> Any other password (Read-only forensics & monitoring)
            </p>
          </div>

          {/* Quick Fill Buttons */}
          <div className="pt-2 border-t border-slate-800 flex gap-2">
            <button
              type="button"
              onClick={() => fillCredentials('admin')}
              className="flex-1 py-1.5 px-2 bg-cyan-950/60 hover:bg-cyan-900/80 border border-cyan-800 text-cyan-300 rounded text-[11px] font-mono font-semibold transition-colors"
            >
              Fill Admin (24282428)
            </button>
            <button
              type="button"
              onClick={() => fillCredentials('analyst')}
              className="flex-1 py-1.5 px-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 rounded text-[11px] font-mono font-semibold transition-colors"
            >
              Fill Analyst
            </button>
          </div>
        </div>

        {/* Error Alert */}
        {error && (
          <div className="mb-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-xs font-mono flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-mono text-slate-400 uppercase tracking-wider mb-1">
              Operator Username (Optional)
            </label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="e.g. admin or analyst"
              className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3.5 py-2.5 text-slate-200 text-xs font-mono focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-colors"
            />
          </div>

          <div>
            <label className="block text-xs font-mono text-slate-400 uppercase tracking-wider mb-1">
              Security Clearance Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter password (24282428 for Admin)"
              className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3.5 py-2.5 text-slate-200 text-xs font-mono focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-colors"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full mt-2 py-3 px-4 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-mono font-bold text-xs uppercase tracking-wider transition-all shadow-[0_0_20px_rgba(6,182,212,0.3)] hover:shadow-[0_0_25px_rgba(6,182,212,0.5)] flex items-center justify-center space-x-2 disabled:opacity-50"
          >
            <span>{loading ? 'Authenticating Clearance...' : 'Authenticate & Enter SOC'}</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </form>

        {/* Footer info */}
        <div className="mt-8 pt-4 border-t border-slate-900 text-center">
          <p className="text-[10px] font-mono text-slate-500">
            AgentSOC Autonomous Defense Architecture • 256-bit PBKDF2 Authenticated
          </p>
        </div>
      </div>
    </div>
  );
};

