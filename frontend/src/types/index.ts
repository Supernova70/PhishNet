// ─── Email Types ─────────────────────────────────────────────────────────────

export interface Email {
  id: number;
  message_id: string;
  sender: string;
  subject: string;
  date: string | null;
  to_address: string | null;
  has_html: boolean;
  has_attachments: boolean;
  fetched_at: string;
  attachment_count: number;
  scan_count: number;
}

export interface EmailDetail extends Email {
  body_text: string | null;
  body_html: string | null;
  attachments: Attachment[];
}

export interface Attachment {
  id: number;
  email_id: number;
  filename: string;
  content_type: string | null;
  size_bytes: number;
  sha256_hash: string | null;
}

// ─── Scan Types ───────────────────────────────────────────────────────────────

export type ScanStatus = 'pending' | 'running' | 'complete' | 'error';
export type Classification = 'safe' | 'suspicious' | 'dangerous';

export interface Scan {
  id: number;
  email_id: number;
  status: ScanStatus;
  started_at: string | null;
  completed_at: string | null;
  verdict: Verdict | null;
}

export interface ScanWithEmail extends Scan {
  email?: Email;
}

export interface ScanTriggerResponse {
  status: 'queued';
  scan_id: number;
  email_id: number;
  verdict: null;
}

export interface Verdict {
  id: number;
  scan_id: number;
  final_score: number;
  classification: Classification;
  ai_score: number;
  ai_label: string | null;
  url_score: number;
  attachment_score: number;
  breakdown: ScanBreakdown | null;
  created_at: string;
}

export interface ScanBreakdown {
  ai: {
    score: number;
    label: string;
    is_phishing: boolean;
  };
  url: {
    score: number;
    total_urls: number;
    analyzed_urls: number;
    high_risk_urls: string[];
    per_url: Array<{
      url: string;
      score: number;
      flags?: string[];       // legacy field
      top_flags?: string[];   // current API field
      vt_malicious: number;
      vt_suspicious?: number;
      vt_harmless?: number;
      vt_total?: number;
      vt_error?: string | null;
      heuristic_score?: number;
      vt_score?: number;
      final_score?: number;
      vt_detections?: { malicious: number; suspicious: number; harmless: number; total: number };
      dynamic_score?: number;
      dynamic_status?: string;
      dynamic_flags?: string[];
      dynamic_error?: string | null;
      final_url?: string | null;
      redirect_chain?: string[];
      dom_has_login_form?: boolean;
      ssl_valid?: boolean | null;
      external_form_action?: boolean;
      download_attempted?: boolean;
      popup_attempted?: boolean;
      dynamic_elapsed_ms?: number;
      playwright_screenshot_path?: string | null;
      screenshot_url?: string | null;
    }>;
  };
  attachment: {
    score: number;
    total_files: number;
    analyzed_files: number;
    high_risk_files: string[];
    per_file: Array<{
      filename: string;
      file_type: string;
      risk_score: number;
      mime_mismatch: boolean;
      findings: string[];
      yara_matches: Array<{
        rule: string;
        severity: string;
        tags: string[];
        description: string;
      }>;
      // VirusTotal hash lookup results
      sha256?: string;
      vt_malicious?: number;
      vt_suspicious?: number;
      vt_harmless?: number;
      vt_total?: number;
      vt_error?: string | null;
    }>;
  };
}

// ─── Health Types ────────────────────────────────────────────────────────────

export interface HealthStatus {
  status: 'ok' | 'degraded';
  version: string;
  response_time_ms: number;
  components: {
    database: { status: 'connected' | 'error'; detail: string };
    ml_model: { status: 'loaded' | 'not_loaded'; detail: string };
  };
}

// ─── Fetch Response ───────────────────────────────────────────────────────────

export interface FetchEmailsResponse {
  status: string;
  new_emails: number;
  total_fetched: number;
}

// ─── API Pagination ───────────────────────────────────────────────────────────

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  skip: number;
  limit: number;
}

// ─── UI State Types ───────────────────────────────────────────────────────────

export type ToastType = 'success' | 'error' | 'info' | 'warning';

export interface ToastMessage {
  id: string;
  type: ToastType;
  title: string;
  message?: string;
  duration?: number;
}
