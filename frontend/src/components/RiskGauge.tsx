import React from 'react';

interface RiskGaugeProps {
  score: number;
  showBreakdown?: boolean;
}

export const RiskGauge: React.FC<RiskGaugeProps> = ({ score, showBreakdown = false }) => {
  // Score styling
  const getColor = (val: number) => {
    if (val >= 90) return { text: 'text-red-400', stroke: '#ef4444', glow: 'rgba(239, 68, 68, 0.4)', label: 'CRITICAL HAZARD' };
    if (val >= 70) return { text: 'text-orange-400', stroke: '#f97316', glow: 'rgba(249, 115, 22, 0.3)', label: 'HIGH THREAT' };
    if (val >= 40) return { text: 'text-yellow-400', stroke: '#eab308', glow: 'rgba(234, 179, 8, 0.2)', label: 'ELEVATED' };
    return { text: 'text-emerald-400', stroke: '#10b981', glow: 'rgba(16, 185, 129, 0.2)', label: 'LOW RISK' };
  };

  const theme = getColor(score);
  const circumference = 2 * Math.PI * 36;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className="flex flex-col items-center">
      <div className="relative w-28 h-28 flex items-center justify-center">
        <svg className="w-28 h-28 transform -rotate-90">
          <circle
            cx="56"
            cy="56"
            r="36"
            stroke="#1e293b"
            strokeWidth="8"
            fill="transparent"
          />
          <circle
            cx="56"
            cy="56"
            r="36"
            stroke={theme.stroke}
            strokeWidth="8"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            fill="transparent"
            style={{
              transition: 'stroke-dashoffset 0.8s ease-in-out',
              filter: `drop-shadow(0 0 6px ${theme.glow})`,
            }}
          />
        </svg>
        <div className="absolute flex flex-col items-center justify-center text-center">
          <span className={`text-2xl font-black font-mono tracking-tighter ${theme.text}`}>
            {Math.round(score)}
          </span>
          <span className="text-[10px] text-slate-500 font-mono uppercase">/ 100</span>
        </div>
      </div>
      <span className={`mt-2 text-xs font-mono font-bold tracking-widest uppercase ${theme.text}`}>
        {theme.label}
      </span>

      {showBreakdown && (
        <div className="w-full mt-4 space-y-2 text-xs font-mono bg-slate-900/60 p-3 rounded-lg border border-slate-800">
          <div className="flex justify-between items-center text-slate-400">
            <span>Attack Velocity Factor:</span>
            <span className="text-slate-200">High (&gt;2.5 req/s)</span>
          </div>
          <div className="flex justify-between items-center text-slate-400">
            <span>Target Asset Criticality:</span>
            <span className="text-red-400 font-bold">Tier-1 Admin Account</span>
          </div>
          <div className="flex justify-between items-center text-slate-400">
            <span>Threat Intel Abuse Score:</span>
            <span className="text-orange-400">85% Confidence</span>
          </div>
        </div>
      )}
    </div>
  );
};

