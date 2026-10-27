import React, { useState, useEffect } from 'react';
import { ThreatIntelItem } from '../types/soc';
import { api } from '../services/api';
import {
  Globe,
  Search,
  ShieldAlert,
  Server,
  Terminal,
  Activity,
  AlertTriangle,
  CheckCircle2,
  Copy,
  ExternalLink,
  Loader2,
  Radio
} from 'lucide-react';

export const ThreatIntelView: React.FC = () => {
  const [searchQuery, setSearchQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [intelResult, setIntelResult] = useState<ThreatIntelItem | null>(null);
  const [feed, setFeed] = useState<ThreatIntelItem[]>([]);
  const [copiedIoc, setCopiedIoc] = useState<string | null>(null);

  useEffect(() => {
    // Load initial curated threat feed
    api.getThreatFeed().then((data) => {
      if (data && data.length > 0) {
        setFeed(data);
      }
    }).catch(() => {});
  }, []);

  const handleSearch = async (iocToSearch?: string) => {
    const target = iocToSearch || searchQuery;
    if (!target.trim()) return;

    setLoading(true);
    try {
      const data = await api.lookupIoc(target.trim());
      setIntelResult(data);
      if (iocToSearch) {
        setSearchQuery(iocToSearch);
      }
    } catch (err) {
      console.error('Threat intel lookup failed', err);
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedIoc(text);
    setTimeout(() => setCopiedIoc(null), 2000);
  };

  const sampleIocs = [
    { label: 'APT-29 Tor Node', ioc: '185.220.101.5' },
    { label: 'Internal Pivot Rig', ioc: '192.168.1.50' },
    { label: 'Cobalt Strike C2', ioc: 'c2-stealth-beacon.xyz' },
    { label: 'BlackCat Exfil Drop', ioc: 'darkweb-exfil-portal.cc' },
    { label: 'Mimikatz Binary', ioc: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
  ];

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-2xl bg-gradient-to-r from-slate-950 via-slate-900 to-slate-950 border border-slate-800 shadow-xl">
        <div>
          <div className="flex items-center space-x-2">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-pulse" />
            <h2 className="text-base font-mono font-black uppercase text-white tracking-wider">
              Global Threat Intelligence & IOC Scanner
            </h2>
          </div>
          <p className="text-xs font-mono text-slate-400 mt-1">
            Real-time reputation analysis, AbuseIPDB scoring, Tor exit nodes, threat actors & ASN routing
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <span className="px-3 py-1 rounded-lg bg-slate-800 border border-slate-700 text-xs font-mono text-cyan-400">
            Feed Status: SYNCHRONIZED
          </span>
        </div>
      </div>

      {/* Search Console */}
      <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-4">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSearch();
          }}
          className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3"
        >
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-4 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Query any IPv4, Domain, or SHA256 file hash..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-11 pr-4 py-3 text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/40 transition"
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="px-6 py-3 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-mono font-bold text-xs uppercase tracking-wider transition flex items-center justify-center space-x-2 shadow-lg shadow-cyan-500/20 disabled:opacity-50"
          >
            {loading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Scanning...</span>
              </>
            ) : (
              <>
                <Radio className="w-4 h-4" />
                <span>Enrich IOC</span>
              </>
            )}
          </button>
        </form>

        {/* Quick Sample IOC Pills */}
        <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-slate-800/80">
          <span className="text-[11px] font-mono text-slate-500 mr-1">Quick Scans:</span>
          {sampleIocs.map((item) => (
            <button
              key={item.ioc}
              onClick={() => handleSearch(item.ioc)}
              className="text-[11px] font-mono px-2.5 py-1 rounded-lg bg-slate-950 border border-slate-800 hover:border-cyan-500/40 text-slate-400 hover:text-cyan-300 transition"
            >
              {item.label}
            </button>
          ))}
        </div>
      </div>

      {/* Lookup Dossier Card (if searched) */}
      {intelResult && (
        <div className="p-6 rounded-2xl bg-slate-900 border border-cyan-500/40 shadow-2xl shadow-cyan-950/20 space-y-5 animate-in fade-in duration-200">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-4 border-b border-slate-800">
            <div className="space-y-1">
              <div className="flex items-center space-x-2">
                <span className="text-xs font-mono px-2 py-0.5 rounded uppercase bg-cyan-950/80 text-cyan-400 border border-cyan-500/30">
                  {intelResult.type}
                </span>
                <span className="text-base font-mono font-black text-white">{intelResult.ioc}</span>
                <button
                  onClick={() => copyToClipboard(intelResult.ioc)}
                  className="text-slate-500 hover:text-white transition p-1"
                  title="Copy IOC"
                >
                  <Copy className="w-3.5 h-3.5" />
                </button>
                {copiedIoc === intelResult.ioc && (
                  <span className="text-[10px] font-mono text-emerald-400">Copied!</span>
                )}
              </div>
              <p className="text-xs font-mono text-slate-400">{intelResult.category}</p>
            </div>

            <div className="flex items-center space-x-3">
              <div className="text-right">
                <div className="text-[10px] font-mono text-slate-500 uppercase">Abuse Score</div>
                <div className={`text-xl font-mono font-black ${
                  intelResult.abuse_score >= 80 ? 'text-red-400' :
                  intelResult.abuse_score >= 50 ? 'text-amber-400' : 'text-emerald-400'
                }`}>
                  {intelResult.abuse_score} / 100
                </div>
              </div>
              <div className={`px-3 py-1.5 rounded-xl border font-mono text-xs font-bold uppercase tracking-wider ${
                intelResult.reputation.includes('MALICIOUS')
                  ? 'bg-red-950/40 border-red-500/50 text-red-400'
                  : intelResult.reputation.includes('SUSPICIOUS')
                  ? 'bg-amber-950/40 border-amber-500/50 text-amber-400'
                  : 'bg-emerald-950/40 border-emerald-500/50 text-emerald-400'
              }`}>
                {intelResult.reputation}
              </div>
            </div>
          </div>

          {/* Dossier Grid Details */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
            <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-1">
              <span className="text-slate-500 text-[10px] uppercase">Threat Actor Attribution</span>
              <p className="text-white font-bold">{intelResult.threat_actor || 'Unattributed / Independent'}</p>
            </div>
            <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-1">
              <span className="text-slate-500 text-[10px] uppercase">Geolocation & ASN</span>
              <p className="text-white font-bold">
                {intelResult.country} {intelResult.city ? `(${intelResult.city})` : ''} • {intelResult.asn || 'N/A'}
              </p>
            </div>
            <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-1">
              <span className="text-slate-500 text-[10px] uppercase">Tor Exit Relay</span>
              <p className={`font-bold ${intelResult.is_tor_exit_node ? 'text-red-400' : 'text-slate-400'}`}>
                {intelResult.is_tor_exit_node ? 'VERIFIED TOR EXIT NODE' : 'Direct / Non-Tor Node'}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Global Threat Feed Table */}
      <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <ShieldAlert className="w-4 h-4 text-rose-400" />
            <h3 className="text-sm font-mono font-bold uppercase text-white tracking-wider">
              Active Enterprise Threat Intelligence Feed
            </h3>
          </div>
          <span className="text-xs font-mono text-slate-500">
            {feed.length} Active Indicators Profiled
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                <th className="py-3 px-3">Type</th>
                <th className="py-3 px-3">Indicator of Compromise (IOC)</th>
                <th className="py-3 px-3">Attributed Threat Actor</th>
                <th className="py-3 px-3">Abuse Score</th>
                <th className="py-3 px-3">Origin</th>
                <th className="py-3 px-3">Tactic</th>
                <th className="py-3 px-3 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {feed.map((item, idx) => (
                <tr key={idx} className="hover:bg-slate-800/40 transition">
                  <td className="py-3 px-3">
                    <span className="px-2 py-0.5 rounded text-[10px] uppercase bg-slate-800 text-slate-300 border border-slate-700">
                      {item.type}
                    </span>
                  </td>
                  <td className="py-3 px-3 font-bold text-white max-w-[200px] truncate">
                    {item.ioc}
                  </td>
                  <td className="py-3 px-3 text-slate-300">
                    {item.threat_actor}
                  </td>
                  <td className="py-3 px-3">
                    <span className={`font-bold ${
                      item.abuse_score >= 90 ? 'text-red-400' :
                      item.abuse_score >= 70 ? 'text-amber-400' : 'text-emerald-400'
                    }`}>
                      {item.abuse_score}/100
                    </span>
                  </td>
                  <td className="py-3 px-3 text-slate-400">
                    {item.country}
                  </td>
                  <td className="py-3 px-3 text-cyan-400 text-[11px]">
                    {item.mitre_tactic || 'TA0001'}
                  </td>
                  <td className="py-3 px-3 text-right">
                    <button
                      onClick={() => handleSearch(item.ioc)}
                      className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-cyan-500 hover:text-slate-950 text-slate-300 text-[11px] transition"
                    >
                      Enrich
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
