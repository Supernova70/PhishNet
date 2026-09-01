import { useEffect, useRef, useState, useCallback } from 'react';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ScanEvent {
  type: 'connected' | 'progress' | 'complete' | 'error' | 'keepalive';
  scan_id?: number;
  classification?: string;
  final_score?: number;
  ai_score?: number;
  url_score?: number;
  attachment_score?: number;
  message?: string;
}

export interface UseScanSseOptions {
  scanId: number;
  enabled?: boolean;
  onEvent?: (event: ScanEvent) => void;
  onComplete?: (event: ScanEvent) => void;
  onError?: (error: string) => void;
}

export interface UseScanSseReturn {
  connected: boolean;
  lastEvent: ScanEvent | null;
  error: string | null;
  reconnect: () => void;
}

// ─── Hook ────────────────────────────────────────────────────────────────────

export function useScanSse({
  scanId,
  enabled = true,
  onEvent,
  onComplete,
  onError,
}: UseScanSseOptions): UseScanSseReturn {
  const [connected, setConnected] = useState(false);
  const [lastEvent, setLastEvent] = useState<ScanEvent | null>(null);
  const [error, setError] = useState<string | null>(null);
  const eventSourceRef = useRef<EventSource | null>(null);
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const cleanup = useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    setConnected(false);
  }, []);

  const connect = useCallback(() => {
    if (!enabled || !scanId) return;
    cleanup();

    const baseUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8080';
    const es = new EventSource(`${baseUrl}/api/scans/${scanId}/events`);
    eventSourceRef.current = es;

    es.onopen = () => {
      setConnected(true);
      setError(null);
    };

    es.onmessage = (e) => {
      try {
        const event: ScanEvent = JSON.parse(e.data);
        if (event.type === 'keepalive') return;
        setLastEvent(event);
        onEvent?.(event);

        if (event.type === 'complete') {
          onComplete?.(event);
          es.close();
        } else if (event.type === 'error') {
          onError?.(event.message || 'Scan failed');
          es.close();
        }
      } catch {
        // Ignore parse errors
      }
    };

    es.onerror = () => {
      setConnected(false);
      setError('Connection lost');
      es.close();
      // Reconnect after 3 seconds
      reconnectTimeoutRef.current = setTimeout(connect, 3000);
    };
  }, [scanId, enabled, onEvent, onComplete, onError, cleanup]);

  useEffect(() => {
    connect();
    return cleanup;
  }, [connect, cleanup]);

  return {
    connected,
    lastEvent,
    error,
    reconnect: connect,
  };
}

// ─── Global SSE for all active scans ─────────────────────────────────────────

export interface GlobalScanUpdate {
  scan_id: number;
  type: string;
  classification?: string;
  final_score?: number;
}

type GlobalListener = (update: GlobalScanUpdate) => void;

let globalEventSource: EventSource | null = null;
const globalListeners = new Set<GlobalListener>();

export function subscribeToGlobalScans(listener: GlobalListener): () => void {
  globalListeners.add(listener);

  if (!globalEventSource) {
    const baseUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8080';
    globalEventSource = new EventSource(`${baseUrl}/api/scans/events`);
    globalEventSource.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data);
        globalListeners.forEach((l) => l(data));
      } catch {
        // ignore
      }
    };
    globalEventSource.onerror = () => {
      globalEventSource?.close();
      globalEventSource = null;
      // Retry after 5s
      setTimeout(() => {
        if (globalListeners.size > 0) {
          const baseUrl2 = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8080';
          globalEventSource = new EventSource(`${baseUrl2}/api/scans/events`);
        }
      }, 5000);
    };
  }

  return () => {
    globalListeners.delete(listener);
    if (globalListeners.size === 0 && globalEventSource) {
      globalEventSource.close();
      globalEventSource = null;
    }
  };
}
