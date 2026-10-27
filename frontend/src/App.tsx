import React, { useState, useEffect, useCallback } from 'react';
import { UserProfile, Incident, SecurityEvent, DashboardStats } from './types/soc';
import { api } from './services/api';
import { useSocRealtime } from './hooks/useSocRealtime';
import { Navbar } from './components/Navbar';
import { Sidebar, NavTab } from './components/Sidebar';
import { CopilotDrawer } from './components/CopilotDrawer';
import { LoginView } from './views/LoginView';
import { DashboardView } from './views/DashboardView';
import { IncidentsView } from './views/IncidentsView';
import { IncidentDetailView } from './views/IncidentDetailView';
import { EventsView } from './views/EventsView';
import { MitreView } from './views/MitreView';
import { ThreatIntelView } from './views/ThreatIntelView';
import { AuditView } from './views/AuditView';
import { ErrorBoundary } from './components/ErrorBoundary';
import { AlertTriangle, RefreshCw } from 'lucide-react';

export const App: React.FC = () => {
  const [user, setUser] = useState<UserProfile | null>(null);
  const [loadingUser, setLoadingUser] = useState<boolean>(true);
  const [currentTab, setCurrentTab] = useState<NavTab>('dashboard');
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [copilotOpen, setCopilotOpen] = useState<boolean>(false);

  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [stats, setStats] = useState<DashboardStats | null>(null);

  const { status: wsStatus, liveEvents, lastIncident, lastResponse } = useSocRealtime();

  // Load user session
  const checkSession = useCallback(async () => {
    try {
      const u = await api.getCurrentUser();
      setUser(u);
    } catch {
      setUser(null);
    } finally {
      setLoadingUser(false);
    }
  }, []);

  useEffect(() => {
    checkSession();
  }, [checkSession]);

  // Load data
  const fetchData = useCallback(async () => {
    if (!user) return;
    try {
      const [incList, evList, s] = await Promise.all([
        api.getIncidents(),
        api.getEvents(100),
        api.getDashboardStats(),
      ]);
      setIncidents(incList);
      setEvents(evList);
      setStats(s);
    } catch (e) {
      console.error('Failed to load SOC telemetry', e);
    }
  }, [user]);

  useEffect(() => {
    if (user) {
      fetchData();
      const interval = setInterval(fetchData, 8000);
      return () => clearInterval(interval);
    }
  }, [user, fetchData]);

  // Handle live incident notification
  useEffect(() => {
    if (lastIncident) {
      setIncidents((prev) => {
        const idx = prev.findIndex((i) => i.incident_id === lastIncident.incident_id);
        if (idx >= 0) {
          const updated = [...prev];
          updated[idx] = lastIncident;
          return updated;
        }
        return [lastIncident, ...prev];
      });
    }
  }, [lastIncident]);

  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [incidentLoading, setIncidentLoading] = useState<boolean>(false);
  const [incidentError, setIncidentError] = useState<string | null>(null);

  // Synchronize browser history and deep-linking via ?incident= URL query param
  const handleSelectIncident = useCallback((id: string) => {
    setSelectedIncidentId(id);
    setIncidentLoading(true);
    setIncidentError(null);
    const cached = incidents.find((i) => i.incident_id === id);
    if (cached) {
      setSelectedIncident(cached);
    } else {
      setSelectedIncident(null);
    }
    try {
      const url = new URL(window.location.href);
      url.searchParams.set('incident', id);
      window.history.pushState({ incidentId: id }, '', url.toString());
    } catch {
      // Ignore if history state update is unavailable
    }
  }, [incidents]);

  const handleBackToDashboard = useCallback(() => {
    setSelectedIncidentId(null);
    setSelectedIncident(null);
    setIncidentError(null);
    setIncidentLoading(false);
    try {
      const url = new URL(window.location.href);
      url.searchParams.delete('incident');
      window.history.pushState({}, '', url.toString());
    } catch {
      // Ignore
    }
  }, []);

  // Listen to popstate (browser back/forward buttons) and initialize from URL query param
  useEffect(() => {
    const handlePopState = () => {
      try {
        const params = new URLSearchParams(window.location.search);
        const incParam = params.get('incident');
        if (incParam) {
          setSelectedIncidentId(incParam);
        } else {
          setSelectedIncidentId(null);
          setSelectedIncident(null);
          setIncidentError(null);
          setIncidentLoading(false);
        }
      } catch {
        // Ignore
      }
    };
    window.addEventListener('popstate', handlePopState);
    try {
      const initialParams = new URLSearchParams(window.location.search);
      const initialInc = initialParams.get('incident');
      if (initialInc) {
        setSelectedIncidentId(initialInc);
      }
    } catch {
      // Ignore
    }
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  // Load full incident details from API whenever selectedIncidentId changes
  const loadIncidentDetail = useCallback(async (id: string) => {
    setIncidentLoading(true);
    setIncidentError(null);
    try {
      const fullIncident = await api.getIncident(id);
      setSelectedIncident(fullIncident);
    } catch (err: any) {
      console.warn(`Failed to fetch incident ${id} from API`, err);
      setSelectedIncident((prev) => {
        if (!prev || prev.incident_id !== id) {
          setIncidentError(err.message || `Incident '${id}' could not be loaded.`);
          return null;
        }
        return prev;
      });
    } finally {
      setIncidentLoading(false);
    }
  }, []);

  useEffect(() => {
    if (selectedIncidentId) {
      loadIncidentDetail(selectedIncidentId);
    } else {
      setSelectedIncident(null);
      setIncidentError(null);
      setIncidentLoading(false);
    }
  }, [selectedIncidentId, loadIncidentDetail]);

  const handleLogout = () => {
    api.setToken(null);
    setUser(null);
    handleBackToDashboard();
  };

  if (loadingUser) {
    return (
      <div className="min-h-screen bg-[#080c14] flex items-center justify-center font-mono text-cyan-400 text-sm">
        <div className="flex items-center space-x-3">
          <div className="w-4 h-4 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
          <span>INITIALIZING AGENTSOC ENVIRONMENT...</span>
        </div>
      </div>
    );
  }

  if (!user) {
    return <LoginView onLoginSuccess={(u) => setUser(u)} />;
  }

  return (
    <div className="min-h-screen bg-[#080c14] text-slate-100 flex flex-col font-sans">
      {/* Top Navbar */}
      <Navbar
        user={user}
        wsStatus={wsStatus}
        onLogout={handleLogout}
        onToggleCopilot={() => setCopilotOpen(!copilotOpen)}
      />

      {/* Main Workspace Body */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left Sidebar */}
        <Sidebar
          currentTab={currentTab}
          onSelectTab={(tab) => {
            setCurrentTab(tab);
            handleBackToDashboard();
          }}
          incidentCount={incidents.filter((i) => i.status !== 'RESOLVED' && i.status !== 'CLOSED').length}
        />

        {/* Dynamic Center Stage Content */}
        <main className="flex-1 overflow-y-auto bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-slate-900/30 via-[#080c14] to-[#080c14]">
          <ErrorBoundary
            fallbackTitle="Investigation View Exception"
            onReset={handleBackToDashboard}
          >
            {selectedIncidentId ? (
              incidentError && !selectedIncident ? (
                <div className="p-8 max-w-xl mx-auto my-12 bg-slate-950 border border-red-500/40 rounded-2xl shadow-2xl font-mono text-center space-y-4">
                  <div className="w-12 h-12 mx-auto rounded-full bg-red-500/10 border border-red-500/30 flex items-center justify-center text-red-400">
                    <AlertTriangle className="w-6 h-6" />
                  </div>
                  <h3 className="text-base font-bold text-white uppercase tracking-wider">
                    Incident Not Available
                  </h3>
                  <p className="text-xs text-red-300/90 leading-relaxed">
                    {incidentError}
                  </p>
                  <div className="flex items-center justify-center space-x-3 pt-2">
                    <button
                      onClick={() => loadIncidentDetail(selectedIncidentId)}
                      className="flex items-center space-x-1.5 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold uppercase transition-colors"
                    >
                      <RefreshCw className="w-3.5 h-3.5" />
                      <span>Retry</span>
                    </button>
                    <button
                      onClick={handleBackToDashboard}
                      className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs uppercase transition-colors"
                    >
                      Return to Dashboard
                    </button>
                  </div>
                </div>
              ) : selectedIncident ? (
                <IncidentDetailView
                  incident={selectedIncident}
                  user={user}
                  onBack={handleBackToDashboard}
                  onRefresh={() => {
                    fetchData();
                    if (selectedIncidentId) loadIncidentDetail(selectedIncidentId);
                  }}
                  onOpenCopilot={() => setCopilotOpen(true)}
                />
              ) : (
                <div className="p-16 flex flex-col items-center justify-center space-y-4 font-mono text-cyan-400">
                  <div className="w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
                  <span className="text-sm tracking-wider">RETRIEVING FORENSIC TELEMETRY ({selectedIncidentId})...</span>
                </div>
              )
            ) : (
              <>
                {currentTab === 'dashboard' && (
                  <DashboardView
                    stats={stats}
                    incidents={incidents}
                    liveEvents={liveEvents.length > 0 ? liveEvents : events}
                    user={user}
                    onSelectIncident={handleSelectIncident}
                    onRefresh={fetchData}
                  />
                )}

                {currentTab === 'incidents' && (
                  <IncidentsView
                    incidents={incidents}
                    user={user}
                    onSelectIncident={handleSelectIncident}
                  />
                )}

                {currentTab === 'events' && (
                  <EventsView
                    events={liveEvents.length > 0 ? liveEvents : events}
                    user={user}
                    onRefresh={fetchData}
                  />
                )}

                {currentTab === 'mitre' && (
                  <MitreView
                    incidents={incidents}
                    onSelectIncident={handleSelectIncident}
                  />
                )}

                {currentTab === 'threat_intel' && <ThreatIntelView />}

                {currentTab === 'audit' && <AuditView />}
              </>
            )}
          </ErrorBoundary>
        </main>
      </div>

      {/* AI Copilot Drawer */}
      <CopilotDrawer
        isOpen={copilotOpen}
        onClose={() => setCopilotOpen(false)}
        activeIncidentId={selectedIncidentId || undefined}
      />
    </div>
  );
};

