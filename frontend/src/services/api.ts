import { DashboardStats, Incident, IncidentStatus, ResponseActionType, ResponseAuditRecord, SecurityEvent, UserProfile } from '../types/soc';

const API_BASE = window.location.origin;

class ApiService {
  private token: string | null = localStorage.getItem('agentsoc_token');

  setToken(token: string | null) {
    this.token = token;
    if (token) {
      localStorage.setItem('agentsoc_token', token);
    } else {
      localStorage.removeItem('agentsoc_token');
    }
  }

  getToken(): string | null {
    return this.token;
  }

  private getHeaders(): HeadersInit {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }
    return headers;
  }

  async login(password: string, username?: string): Promise<{ access_token: string; user: UserProfile }> {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password, username: username || undefined }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Authentication failed' }));
      throw new Error(err.detail || 'Authentication failed');
    }
    const data = await res.json();
    this.setToken(data.access_token);
    return data;
  }

  async getCurrentUser(): Promise<UserProfile> {
    const res = await fetch(`${API_BASE}/auth/me`, {
      headers: this.getHeaders(),
    });
    if (!res.ok) {
      throw new Error('Session invalid');
    }
    return res.json();
  }

  async getDashboardStats(): Promise<DashboardStats> {
    const res = await fetch(`${API_BASE}/dashboard/stats`, {
      headers: this.getHeaders(),
    });
    if (!res.ok) throw new Error('Failed to fetch dashboard stats');
    return res.json();
  }

  async getIncidents(): Promise<Incident[]> {
    const res = await fetch(`${API_BASE}/incidents`, {
      headers: this.getHeaders(),
    });
    if (!res.ok) throw new Error('Failed to fetch incidents');
    return res.json();
  }

  async getIncident(incidentId: string): Promise<Incident> {
    const res = await fetch(`${API_BASE}/incidents/${encodeURIComponent(incidentId)}`, {
      headers: this.getHeaders(),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: `Failed to fetch incident ${incidentId}` }));
      throw new Error(err.detail || `Failed to fetch incident ${incidentId}`);
    }
    return res.json();
  }

  async triggerInvestigation(incidentId: string): Promise<any> {
    const res = await fetch(`${API_BASE}/investigations/${encodeURIComponent(incidentId)}`, {
      method: 'POST',
      headers: this.getHeaders(),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to execute AI investigation' }));
      throw new Error(err.detail || 'Failed to execute AI investigation');
    }
    return res.json();
  }

  async updateIncidentStatus(incidentId: string, status: IncidentStatus): Promise<Incident> {
    const res = await fetch(`${API_BASE}/incidents/${incidentId}/status`, {
      method: 'PATCH',
      headers: this.getHeaders(),
      body: JSON.stringify({ status }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Update failed' }));
      throw new Error(err.detail || 'Failed to update status');
    }
    return res.json();
  }

  async getEvents(limit: number = 50): Promise<SecurityEvent[]> {
    const res = await fetch(`${API_BASE}/events?limit=${limit}`, {
      headers: this.getHeaders(),
    });
    if (!res.ok) throw new Error('Failed to fetch events');
    return res.json();
  }

  async ingestEvent(event: Partial<SecurityEvent>): Promise<any> {
    const res = await fetch(`${API_BASE}/events`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify(event),
    });
    if (!res.ok) throw new Error('Failed to ingest event');
    return res.json();
  }

  async executeResponse(
    incidentId: string,
    actionType: ResponseActionType,
    target?: string,
    simulated: boolean = true
  ): Promise<ResponseAuditRecord> {
    const res = await fetch(`${API_BASE}/incidents/${incidentId}/response`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify({
        action_type: actionType,
        target,
        simulated,
      }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Response execution failed' }));
      throw new Error(err.detail || 'Execution failed');
    }
    return res.json();
  }

  async askCopilot(message: string, incidentId?: string): Promise<{ reply: string; suggestions: string[] }> {
    const res = await fetch(`${API_BASE}/assistant/chat`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify({ message, incident_id: incidentId }),
    });
    if (!res.ok) throw new Error('AI Copilot request failed');
    return res.json();
  }

  async getAuditLog(): Promise<ResponseAuditRecord[]> {
    const res = await fetch(`${API_BASE}/audit`, {
      headers: this.getHeaders(),
    });
    if (!res.ok) {
      return [];
    }
    return res.json();
  }

  async lookupIoc(ioc: string): Promise<any> {
    const res = await fetch(`${API_BASE}/threat-intel/lookup/${encodeURIComponent(ioc)}`, {
      headers: this.getHeaders(),
    });
    if (!res.ok) throw new Error('Threat intelligence lookup failed');
    return res.json();
  }

  async getThreatFeed(): Promise<any[]> {
    const res = await fetch(`${API_BASE}/threat-intel/feed`, {
      headers: this.getHeaders(),
    });
    if (!res.ok) return [];
    return res.json();
  }

  async getSimulationScenarios(): Promise<any[]> {
    const res = await fetch(`${API_BASE}/simulation/scenarios`, {
      headers: this.getHeaders(),
    });
    if (!res.ok) return [];
    return res.json();
  }

  async triggerSimulation(scenario: string, count?: number): Promise<any> {
    const res = await fetch(`${API_BASE}/simulation/trigger`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify({ scenario, count }),
    });
    if (!res.ok) throw new Error('Simulation failed to start');
    return res.json();
  }

  async downloadForensicReport(incidentId: string): Promise<string> {
    const res = await fetch(`${API_BASE}/incidents/${incidentId}/report/markdown`, {
      headers: this.getHeaders(),
    });
    if (!res.ok) throw new Error('Failed to generate forensic report');
    return res.text();
  }
}

export const api = new ApiService();

