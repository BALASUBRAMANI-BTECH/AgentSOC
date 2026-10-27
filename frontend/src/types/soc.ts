export type IncidentSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type IncidentStatus = "OPEN" | "INVESTIGATING" | "CONTAINED" | "RESOLVED" | "CLOSED";
export type ResponseActionType = "BLOCK_IP" | "LOCK_ACCOUNT" | "ISOLATE_HOST" | "QUARANTINE_FILE" | "REVOKE_TOKEN";

export interface SecurityEvent {
  event_id: string;
  timestamp: string;
  source_ip: string;
  destination_ip: string;
  username?: string;
  event_type: string;
  severity: IncidentSeverity;
  message: string;
  metadata: Record<string, any>;
}

export interface IncidentTimelineEntry {
  timestamp: string;
  stage: string;
  description: string;
  actor: string;
}

export interface MitreMapping {
  technique_id: string;
  technique_name: string;
  tactic: string;
  description: string;
  subtechnique_id?: string;
  confidence: number;
}

export interface AgentLogEntry {
  agent_name: string;
  timestamp: string;
  action: string;
  summary?: string;
  output_summary?: string;
  details?: Record<string, any>;
  evidence?: Record<string, any>;
}

export interface InvestigationReport {
  investigation_id?: string;
  incident_id: string;
  summary?: string;
  incident_summary?: string;
  root_cause_hypothesis?: string;
  reasoning?: string;
  confidence_score?: number;
  risk_score?: number;
  severity?: string;
  source_ip?: string;
  affected_user?: string;
  attack_type?: string;
  mitre_technique?: string;
  evidence?: Record<string, any>;
  observed_evidence?: string[];
  agent_logs?: AgentLogEntry[];
  recommended_actions?: string[];
  recommended_responses?: string[];
  created_at?: string;
  investigated_at?: string;
  status?: string;
  llm_provider?: string;
}

export interface Incident {
  incident_id: string;
  title: string;
  description: string;
  severity: IncidentSeverity;
  status: IncidentStatus;
  attack_type: string;
  source_ip: string;
  target_user?: string;
  event_ids: string[];
  risk_score: number;
  mitre_mapping?: MitreMapping;
  investigation_report?: InvestigationReport;
  timeline: IncidentTimelineEntry[];
  created_at: string;
  updated_at: string;
}

export interface UserProfile {
  username: string;
  display_name: string;
  role: "SOC_ADMIN" | "SOC_ANALYST";
  email: string;
  permissions: string[];
}

export interface DashboardStats {
  total_events: number;
  total_incidents: number;
  open_incidents: number;
  contained_incidents: number;
  critical_incidents: number;
  blocked_ips_count: number;
  ai_agents_active: number;
  average_risk_score: number;
}

export interface ResponseAuditRecord {
  action_id: string;
  incident_id: string;
  action_type: ResponseActionType;
  target: string;
  executed_by: string;
  timestamp: string;
  simulated: boolean;
  status: string;
  details: string;
}

export interface ThreatIntelItem {
  ioc: string;
  type: "ipv4" | "domain" | "sha256" | "generic";
  reputation: string;
  abuse_score: number;
  threat_actor: string;
  category: string;
  country: string;
  city?: string;
  asn?: string;
  is_tor_exit_node?: boolean;
  mitre_tactic?: string;
  last_seen: string;
}

export interface SimulationScenario {
  id: string;
  name: string;
  description: string;
  mitre_technique: string;
  attacker_ip: string;
  target_user: string;
  event_count: number;
  category: string;
}


