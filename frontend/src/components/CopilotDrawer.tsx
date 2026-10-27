import React, { useState, useEffect, useRef } from 'react';
import { api } from '../services/api';
import { Bot, X, Send, Sparkles, Terminal, Shield, RefreshCw } from 'lucide-react';

interface CopilotDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  activeIncidentId?: string;
}

interface ChatMessage {
  sender: 'user' | 'copilot';
  text: string;
  time: string;
}

export const CopilotDrawer: React.FC<CopilotDrawerProps> = ({
  isOpen,
  onClose,
  activeIncidentId,
}) => {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      sender: 'copilot',
      text: 'AgentSOC AI Copilot active. I can assist with incident triage, MITRE ATT&CK mapping, and containment playbooks.',
      time: new Date().toLocaleTimeString(),
    },
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [suggestions, setSuggestions] = useState<string[]>([
    'Explain the 100 failed logins incident',
    'What is MITRE T1110 technique?',
    'Recommend containment steps for 192.168.1.50',
    'Calculate risk factors for targeted admin account',
  ]);
  const chatEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (isOpen) {
      chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages, isOpen]);

  const handleSend = async (messageText?: string) => {
    const textToSend = messageText || input;
    if (!textToSend.trim() || loading) return;

    const userMsg: ChatMessage = {
      sender: 'user',
      text: textToSend,
      time: new Date().toLocaleTimeString(),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInput('');
    setLoading(true);

    try {
      const response = await api.askCopilot(textToSend, activeIncidentId);
      const copilotMsg: ChatMessage = {
        sender: 'copilot',
        text: response.reply,
        time: new Date().toLocaleTimeString(),
      };
      setMessages((prev) => [...prev, copilotMsg]);
      if (response.suggestions && response.suggestions.length > 0) {
        setSuggestions(response.suggestions);
      }
    } catch (err: any) {
      const errorMsg: ChatMessage = {
        sender: 'copilot',
        text: `Error connecting to AI Copilot: ${err.message || 'Unknown error'}`,
        time: new Date().toLocaleTimeString(),
      };
      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-y-0 right-0 z-50 w-full max-w-md bg-slate-950 border-l border-cyan-900/40 shadow-2xl flex flex-col">
      {/* Drawer Header */}
      <div className="p-4 bg-slate-900 border-b border-slate-800 flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <div className="p-1.5 rounded-lg bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">
            <Bot className="w-5 h-5" />
          </div>
          <div>
            <h3 className="font-mono text-sm font-bold text-slate-100 flex items-center space-x-1.5">
              <span>AgentSOC AI Copilot</span>
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            </h3>
            <p className="text-[10px] font-mono text-slate-400">
              {activeIncidentId ? `Context: Incident #${activeIncidentId}` : 'Global Threat Triage Assistant'}
            </p>
          </div>
        </div>
        <button
          onClick={onClose}
          className="text-slate-400 hover:text-white p-1 rounded hover:bg-slate-800"
        >
          <X className="w-5 h-5" />
        </button>
      </div>

      {/* Chat Messages */}
      <div className="flex-1 overflow-y-auto p-4 space-y-3 font-mono text-xs">
        {messages.map((m, idx) => (
          <div
            key={idx}
            className={`flex flex-col ${
              m.sender === 'user' ? 'items-end' : 'items-start'
            }`}
          >
            <div className="flex items-center space-x-1.5 text-[10px] text-slate-500 mb-1">
              <span>{m.sender === 'user' ? 'Operator' : 'AgentSOC Copilot'}</span>
              <span>•</span>
              <span>{m.time}</span>
            </div>
            <div
              className={`p-3 rounded-lg max-w-[88%] leading-relaxed ${
                m.sender === 'user'
                  ? 'bg-cyan-600 text-white rounded-br-none shadow-[0_0_10px_rgba(6,182,212,0.2)]'
                  : 'bg-slate-900 text-slate-200 border border-slate-800 rounded-bl-none'
              }`}
            >
              <p className="whitespace-pre-wrap">{m.text}</p>
            </div>
          </div>
        ))}

        {loading && (
          <div className="flex items-center space-x-2 text-cyan-400 text-xs font-mono p-2">
            <RefreshCw className="w-4 h-4 animate-spin" />
            <span>AI Copilot synthesizing threat telemetry...</span>
          </div>
        )}
        <div ref={chatEndRef} />
      </div>

      {/* Suggested Prompts */}
      <div className="p-3 bg-slate-900/60 border-t border-slate-800 space-y-1.5">
        <div className="flex items-center space-x-1 text-[11px] text-slate-400 font-mono">
          <Sparkles className="w-3 h-3 text-cyan-400" />
          <span>Suggested Queries:</span>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {suggestions.slice(0, 3).map((sug, i) => (
            <button
              key={i}
              onClick={() => handleSend(sug)}
              className="text-[10px] font-mono px-2 py-1 rounded bg-slate-800/80 hover:bg-cyan-950/80 text-cyan-300/80 hover:text-cyan-200 border border-slate-700 hover:border-cyan-700 text-left transition-all"
            >
              {sug}
            </button>
          ))}
        </div>
      </div>

      {/* Input Box */}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          handleSend();
        }}
        className="p-3 bg-slate-950 border-t border-slate-800 flex items-center space-x-2"
      >
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Ask Copilot about threats, playbooks, MITRE..."
          className="flex-1 bg-slate-900 text-slate-200 placeholder-slate-500 text-xs font-mono rounded-lg px-3 py-2 border border-slate-700 focus:outline-none focus:border-cyan-500"
        />
        <button
          type="submit"
          disabled={!input.trim() || loading}
          className="p-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 text-white rounded-lg transition-all"
        >
          <Send className="w-4 h-4" />
        </button>
      </form>
    </div>
  );
};

