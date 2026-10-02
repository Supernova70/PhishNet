import { apiClient } from './client';

export interface AuthUser {
  id: number;
  email: string;
  name?: string | null;
  picture?: string | null;
  role: string;
  gmail_connected: boolean;
  needs_gmail: boolean;
  /** Effective RBAC capabilities from /auth/me (absent on older payloads). */
  permissions?: string[];
}

export interface AuthConfig {
  google_client_id: string;
  configured: boolean;
  one_tap: boolean;
}

export const getAuthConfig = async (): Promise<AuthConfig> => {
  const { data } = await apiClient.get<AuthConfig>('/auth/config');
  return data;
};

export const getMe = async (): Promise<AuthUser> => {
  const { data } = await apiClient.get<AuthUser>('/auth/me');
  return data;
};

export const postLogout = async (): Promise<void> => {
  await apiClient.post('/auth/logout');
};

export const postCredential = async (
  credential: string,
  gCsrfToken: string | null
): Promise<AuthUser> => {
  const { data } = await apiClient.post<Partial<AuthUser>>('/auth/credential', {
    credential,
    g_csrf_token: gCsrfToken,
  });
  // /credential returns a subset; hydrate the full shape for the context
  return {
    id: 0,
    email: data.email ?? '',
    role: data.role ?? 'user',
    gmail_connected: data.gmail_connected ?? false,
    needs_gmail: data.needs_gmail ?? true,
    permissions: data.permissions ?? [],
  };
};

/** Begin the combined-consent flow (full-page redirect to Google). */
export const startGoogleSignIn = (): void => {
  window.location.assign('/api/auth/google');
};
