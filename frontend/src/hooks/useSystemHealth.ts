import { createContext, createElement, useCallback, useContext, useEffect, useState, type ReactNode } from 'react';
import { getHealth } from '../api/client';

export interface VtKeyState {
  id: number;
  masked: string;
  state: 'ready' | 'cooldown' | 'invalid';
  cooldown_remaining: number;
  calls: number;
}

export interface VtRotation {
  key_count: number;
  available: number;
  cooling_down: number;
  invalid: number;
  total_calls: number;
  keys?: VtKeyState[];
}

export interface ComponentStatus {
  status: string;
  detail: string;
  rotation?: VtRotation;
}

export interface HealthResponse {
  status: 'ok' | 'degraded';
  version: string;
  response_time_ms: number;
  components: {
    database: ComponentStatus;
    ml_model: ComponentStatus;
    virustotal?: ComponentStatus;
    dynamic_url?: ComponentStatus;
  };
}

interface SystemHealthContextValue {
  health: HealthResponse | null;
  loading: boolean;
  refresh: () => Promise<void>;
}

const SystemHealthContext = createContext<SystemHealthContextValue | null>(null);

export function SystemHealthProvider({ children }: { children: ReactNode }) {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try {
      setHealth(await getHealth() as HealthResponse);
    } catch {
      setHealth(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    const interval = setInterval(refresh, 30000);
    return () => clearInterval(interval);
  }, [refresh]);

  return createElement(
    SystemHealthContext.Provider,
    { value: { health, loading, refresh } },
    children,
  );
}

export const useSystemHealth = () => {
  const context = useContext(SystemHealthContext);
  if (!context) throw new Error('useSystemHealth must be used inside SystemHealthProvider');
  return context;
};
