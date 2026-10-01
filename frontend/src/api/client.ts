import axios from 'axios';
import type {
  Email,
  EmailDetail,
  Scan,
  HealthStatus,
  FetchEmailsResponse,
  ScanTriggerResponse,
  Classification,
} from '../types';

// ─── Axios Instance ───────────────────────────────────────────────────────────

export const apiClient = axios.create({
  baseURL: '/api',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const resolveApiUrl = (path: string): string =>
  new URL(path, `${apiClient.defaults.baseURL}/`).toString();

export const resolveScreenshotUrl = (
  artifactPath?: string | null,
  storedPath?: string | null,
): string | null => {
  if (artifactPath) return resolveApiUrl(artifactPath);
  if (!storedPath) return null;
  const parts = storedPath.replaceAll('\\', '/').split('/').filter(Boolean);
  if (parts.length < 2) return null;
  const scanId = parts.at(-2);
  const filename = parts.at(-1);
  return resolveApiUrl(`/artifacts/url-screenshots/${scanId}/${filename}`);
};

// Response interceptor for error handling
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.code === 'ECONNREFUSED' || error.code === 'ERR_NETWORK') {
      return Promise.reject(new Error('BACKEND_OFFLINE'));
    }
    // 401 on any protected endpoint → back to the login page.
    // /auth/* 401s are handled by AuthContext / LoginPage themselves.
    if (error.response?.status === 401) {
      const url = String(error.config?.url ?? '');
      if (!url.includes('/auth/') && window.location.pathname !== '/login') {
        window.location.assign('/login');
      }
    }
    return Promise.reject(error);
  }
);

// ─── Health ───────────────────────────────────────────────────────────────────

export const getHealth = async (): Promise<HealthStatus> => {
  const { data } = await apiClient.get<HealthStatus>('/health');
  return data;
};

// ─── Emails ───────────────────────────────────────────────────────────────────

export const getEmails = async (skip = 0, limit = 50): Promise<Email[]> => {
  const { data } = await apiClient.get<{ total: number; emails: Email[] }>('/emails', {
    params: { skip, limit },
  });
  return data.emails ?? [];
};

export const getEmail = async (id: number): Promise<EmailDetail> => {
  const { data } = await apiClient.get<EmailDetail>(`/emails/${id}`);
  return data;
};

export const fetchEmails = async (limit = 20): Promise<FetchEmailsResponse> => {
  const { data } = await apiClient.post<FetchEmailsResponse>(
    `/emails/fetch?limit=${limit}`
  );
  return data;
};

// ─── Scans ────────────────────────────────────────────────────────────────────

export const getScans = async (skip = 0, limit = 50): Promise<Scan[]> => {
  const { data } = await apiClient.get<{ total: number; scans: Scan[] }>('/scans', {
    params: { skip, limit },
  });
  return data.scans ?? [];
};

export const getScan = async (id: number): Promise<Scan> => {
  const { data } = await apiClient.get<Scan>(`/scans/${id}`);
  return data;
};

export const runScan = async (emailId: number): Promise<ScanTriggerResponse> => {
  const { data } = await apiClient.post<ScanTriggerResponse>(`/scans/${emailId}`);
  return data;
};

// ─── Bulk Scan ────────────────────────────────────────────────────────────────

export interface BulkScanResponse {
  status: string;
  total_queued: number;
  scan_ids: number[];
}

export const bulkScan = async (emailIds: number[]): Promise<BulkScanResponse> => {
  const { data } = await apiClient.post<BulkScanResponse>('/emails/bulk-scan', {
    email_ids: emailIds,
  });
  return data;
};

// ─── AI Threat Summary ────────────────────────────────────────────────────────

export interface ThreatSummary {
  scan_id: number;
  classification: string;
  final_score: number;
  summary: string;
  key_findings: string[];
  risk_factors: { engine: string; severity: string; detail: string }[];
}

export const getThreatSummary = async (scanId: number): Promise<ThreatSummary> => {
  const { data } = await apiClient.get<ThreatSummary>(`/scans/${scanId}/summary`);
  return data;
};

// ─── Attachments ──────────────────────────────────────────────────────────────

export interface AttachmentSummary {
  id: number;
  email_id: number;
  filename: string;
  content_type: string | null;
  size_bytes: number;
  sha256_hash: string | null;
  email_subject: string;
  email_sender: string;
  latest_scan_score: number | null;
  latest_classification: Classification | null;
}

export interface AttachmentDetail extends AttachmentSummary {
  storage_path: string | null;
  email_date: string | null;
  scan_results: Array<{
    scan_id: number;
    scan_status: string;
    final_score: number;
    classification: string;
    file_analysis: Record<string, unknown>;
  }>;
}

export const getAttachments = async (skip = 0, limit = 50): Promise<AttachmentSummary[]> => {
  const { data } = await apiClient.get<{ total: number; attachments: AttachmentSummary[] }>('/attachments', {
    params: { skip, limit },
  });
  return data.attachments ?? [];
};

export const getAttachmentDetail = async (id: number): Promise<AttachmentDetail> => {
  const { data } = await apiClient.get<AttachmentDetail>(`/attachments/${id}`);
  return data;
};

// ─── Export ───────────────────────────────────────────────────────────────────

export const exportScansCsv = async (classification?: string): Promise<void> => {
  const params = classification ? { classification } : {};
  const { data } = await apiClient.get('/scans/export/csv', {
    params,
    responseType: 'blob',
  });
  const url = window.URL.createObjectURL(new Blob([data]));
  const link = document.createElement('a');
  link.href = url;
  link.setAttribute('download', 'phishing_guard_scans.csv');
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(url);
};

// ─── Backend status check ─────────────────────────────────────────────────────

export const checkBackendOnline = async (): Promise<boolean> => {
  try {
    await apiClient.get('/health', { timeout: 5000 });
    return true;
  } catch {
    return false;
  }
};
