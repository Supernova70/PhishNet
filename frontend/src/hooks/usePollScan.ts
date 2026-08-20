import { useState, useEffect, useRef, useCallback } from 'react';
import { getScan } from '../api/client';
import type { Scan } from '../types';

const MAX_RETRIES = 90;
const POLL_INTERVAL = 2000;

export function usePollScan() {
  const [scan, setScan] = useState<Scan | null>(null);
  const [polling, setPolling] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const retryCount = useRef(0);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const stopPolling = useCallback(() => {
    setPolling(false);
    if (timerRef.current) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
  }, []);

  const pollOnce = useCallback(async (scanId: number) => {
    try {
      const result = await getScan(scanId);
      setScan(result);

      if (result.status === 'complete' || result.status === 'error') {
        stopPolling();
        return;
      }

      retryCount.current += 1;
      if (retryCount.current >= MAX_RETRIES) {
        setError('Scan status polling timed out after 180 seconds');
        stopPolling();
        return;
      }

      timerRef.current = setTimeout(() => pollOnce(scanId), POLL_INTERVAL);
    } catch (err) {
      setError('Failed to fetch scan status');
      stopPolling();
    }
  }, [stopPolling]);

  const startPolling = useCallback(
    (scanId: number) => {
      retryCount.current = 0;
      setError(null);
      setPolling(true);
      setScan(null);
      pollOnce(scanId);
    },
    [pollOnce]
  );

  useEffect(() => {
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, []);

  return { scan, polling, error, startPolling, stopPolling };
}
