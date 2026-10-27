export interface PaginatedMeta {
  total: number;
  page: number;
  page_size: number;
}

export interface NormalizedEvent {
  id: string;
  timestamp?: string;
  platform: string;
  hostname?: string;
  source_type?: string;
  event_id?: string;
  event_type?: string;
  username?: string;
  source_ip?: string;
  severity?: string;
  authentication_result?: string;
  message?: string;
  raw_event?: string;
  process_name?: string;
  process_id?: number;
  extra?: Record<string, unknown>;
}

export interface DetectionAlert {
  id: string;
  rule_id: string;
  title: string;
  description: string;
  severity: string;
  confidence: number;
  created_at: string;
  explanation: string;
  mitre_attack: string[];
  false_positive_notes: string[];
  recommendations: string[];
  event_ids: string[];
  hosts: string[];
  users: string[];
  source_ips: string[];
  status: string;
}

export interface StatisticsOverview {
  total_events: number;
  windows_events: number;
  linux_events: number;
  active_alerts: number;
  high_critical_alerts: number;
}
