// ─── Forensics / Intel / Report / Alerts API ────────────────────────────────
//
// Client for the Week 2–3 endpoints: header forensics, origin trace,
// attribution graph, campaigns, forensic reports and the alert feed.

import { apiClient } from './client';
import type { Classification } from '../types';

// ─── Header forensics ────────────────────────────────────────────────────────

export interface Hop {
  hop_index: number;
  from_host: string | null;
  from_ip: string | null;
  helo: string | null;
  by_host: string | null;
  via: string | null;
  protocol: string | null;
  timestamp: string | null;
  is_internal: boolean;
  raw: string | null;
  /** Cached per-hop geo (null when the IP has no cached row) — FE-C6 */
  geo?: {
    lat: number;
    lon: number;
    country: string | null;
    country_code: string | null;
  } | null;
}

export interface AuthResults {
  spf_result: string | null;
  spf_domain: string | null;
  dkim_result: string | null;
  dkim_domain: string | null;
  dkim_selector: string | null;
  dmarc_result: string | null;
  dmarc_domain: string | null;
  alignment: string | null;
  source: string | null;
  checked_at: string | null;
}

export interface HeaderEvidence {
  email_id: number;
  present: boolean;
  headers: Record<string, unknown> | null;
  hops: Hop[];
  auth: AuthResults | null;
  raw_path: string | null;
  raw_sha256: string | null;
  size_bytes: number | null;
}

export const getHeaderEvidence = async (emailId: number): Promise<HeaderEvidence> => {
  const { data } = await apiClient.get<HeaderEvidence>(`/emails/${emailId}/headers`);
  return data;
};

// ─── Origin trace ────────────────────────────────────────────────────────────

export interface Origin {
  ip: string;
  hop_index: number;
  from_host: string | null;
  helo: string | null;
  by_host: string | null;
  timestamp_utc: string | null;
  is_internal: boolean;
}

export interface IpIntel {
  ip: string;
  country: string | null;
  country_code: string | null;
  region: string | null;
  city: string | null;
  lat: number | null;
  lon: number | null;
  asn: number | null;
  asn_org: string | null;
  isp: string | null;
  ptr_host: string | null;
  is_vpn: boolean;
  is_tor: boolean;
  is_proxy: boolean;
  is_hosting: boolean;
  is_dnsbl_listed: boolean;
  dnsbl: unknown;
  source: string | null;
  fetched_at: string | null;
  expires_at: string | null;
}

export interface TraceResponse {
  email_id: number;
  origin: Origin | null;
  hops: Hop[];
  intel: IpIntel | null;
  /** IPs queued for background geo enrichment — re-poll while > 0 */
  enriching?: number;
}

export const getTrace = async (emailId: number, refresh = false): Promise<TraceResponse> => {
  const { data } = await apiClient.get<TraceResponse>(`/emails/${emailId}/trace`, {
    params: refresh ? { refresh: true } : {},
  });
  return data;
};

export interface IpStats {
  total_ips: number;
  countries: Array<{ country: string | null; count: number }>;
}

export const getIpStats = async (): Promise<IpStats> => {
  const { data } = await apiClient.get<IpStats>('/ips/stats');
  return data;
};

// ─── Attribution graph ───────────────────────────────────────────────────────

export interface GraphNode {
  id: string;
  type: string;
  label: string;
  risk: number;
}

export interface GraphEdge {
  source: string;
  target: string;
  relation: string;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export const getGraph = async (
  minScore = 0,
  limit = 500,
  campaignId?: number,
  scanId?: number,
): Promise<GraphData> => {
  const { data } = await apiClient.get<GraphData>('/graph', {
    params: {
      min_score: minScore,
      limit,
      ...(campaignId != null ? { campaign_id: campaignId } : {}),
      ...(scanId != null ? { scan_id: scanId } : {}),
    },
  });
  return data;
};

// ─── Attribution stats (dashboard donut, FE-C5) ──────────────────────────────

export interface AttributionStats {
  total: number;
  kinds: Array<{ kind: string; count: number }>;
}

export const getAttributionStats = async (): Promise<AttributionStats> => {
  const { data } = await apiClient.get<AttributionStats>('/attribution/stats');
  return data;
};

// ─── Campaigns ───────────────────────────────────────────────────────────────

export interface Campaign {
  id: number;
  name: string;
  first_seen: string | null;
  last_seen: string | null;
  email_count: number;
  avg_score: number;
  status: string;
  confidence: number;
  notes?: string | null;
  summary: Record<string, unknown> | null;
}

export const CAMPAIGN_STATUSES = ['open', 'new', 'investigating', 'closed'] as const;

export const updateCampaign = async (
  id: number,
  patch: { status?: string; notes?: string },
): Promise<Campaign> => {
  const { data } = await apiClient.patch<{ campaign: Campaign }>(
    `/campaigns/${id}`,
    patch,
  );
  return data.campaign;
};

export interface CampaignMember {
  scan_id: number;
  email_id: number;
  subject: string | null;
  sender: string | null;
  final_score: number;
  classification: Classification | null;
}

export interface CampaignDetail {
  campaign: Campaign;
  scans: CampaignMember[];
}

export const getCampaigns = async (status?: string): Promise<Campaign[]> => {
  const { data } = await apiClient.get<{ count: number; campaigns: Campaign[] }>('/campaigns', {
    params: status ? { status } : {},
  });
  return data.campaigns ?? [];
};

export const getCampaign = async (id: number): Promise<CampaignDetail> => {
  const { data } = await apiClient.get<CampaignDetail>(`/campaigns/${id}`);
  return data;
};

export interface ReclusterResult {
  campaigns: Campaign[];
  scans_clustered: number;
  scans_total: number;
}

export const reclusterCampaigns = async (): Promise<ReclusterResult> => {
  const { data } = await apiClient.post<ReclusterResult>('/campaigns/recluster');
  return data;
};

// ─── Indicators ──────────────────────────────────────────────────────────────

export interface IndicatorRow {
  type: string;
  value: string;
  scan_count: number;
  sighting_count: number;
  first_seen: string | null;
  last_seen: string | null;
}

export const getIndicators = async (q?: string): Promise<IndicatorRow[]> => {
  const { data } = await apiClient.get<{ count: number; indicators: IndicatorRow[] }>(
    '/indicators',
    { params: q ? { q } : {} },
  );
  return data.indicators ?? [];
};

// ─── Forensic report ─────────────────────────────────────────────────────────

export interface EvidenceRow {
  id: number;
  email_id: number | null;
  scan_id: number | null;
  actor: string;
  raw_sha256: string | null;
  report_sha256: string | null;
  prev_hash: string | null;
  row_hash: string | null;
  created_at: string | null;
}

export interface ForensicReport {
  report: {
    scan: { id: number; status: string; started_at: string | null; completed_at: string | null };
    email: {
      message_id: string;
      sender: string | null;
      to: string | null;
      subject: string | null;
      date: string | null;
      fetched_at: string | null;
    };
    verdict: {
      final_score: number;
      classification: Classification;
      scores: { ai: number; url: number; attachment: number; header: number };
      ai_label: string | null;
      flags: string[];
      bec: Record<string, unknown> | null;
      lookalike: Record<string, unknown> | null;
      created_at: string | null;
    } | null;
    header_forensics: Record<string, unknown> | null;
    attribution: Record<string, unknown> | null;
    origin: (Origin & { intel: IpIntel | null }) | null;
    received_chain: Hop[];
    indicators: IndicatorRow[];
    campaign: Campaign | null;
    evidence_chain: EvidenceRow[];
  };
  integrity: {
    report_sha256: string;
    generated_at: string;
    app_version: string;
    disclaimer: string;
  };
}

export const getReport = async (scanId: number, exportEvidence = false): Promise<ForensicReport> => {
  const { data } = await apiClient.get<ForensicReport>(`/scans/${scanId}/report`, {
    params: exportEvidence ? { export: true } : {},
  });
  return data;
};

// ─── Alert feed ──────────────────────────────────────────────────────────────

export interface AlertItem {
  id: number;
  scan_id: number;
  email_id: number | null;
  score: number;
  classification: Classification;
  reasons: string[];
  subject: string | null;
  sender: string | null;
  created_at: string | null;
  read: boolean;
}

export interface AlertsResponse {
  count: number;
  total: number;
  unread: number;
  alerts: AlertItem[];
}

export const getAlerts = async (unreadOnly = false, limit = 50): Promise<AlertsResponse> => {
  const { data } = await apiClient.get<AlertsResponse>('/alerts', {
    params: { ...(unreadOnly ? { unread: true } : {}), limit },
  });
  return data;
};

export const markAlertRead = async (alertId: number): Promise<AlertItem> => {
  const { data } = await apiClient.post<AlertItem>(`/alerts/${alertId}/read`);
  return data;
};

export const markAllAlertsRead = async (): Promise<{ marked: number }> => {
  const { data } = await apiClient.post<{ marked: number }>('/alerts/read-all');
  return data;
};
