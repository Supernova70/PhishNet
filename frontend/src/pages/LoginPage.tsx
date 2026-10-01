import { useEffect, useState } from 'react';
import { Navigate, useNavigate } from 'react-router-dom';
import { ShieldCheck, Mail, Lock } from 'lucide-react';
import {
  getAuthConfig,
  postCredential,
  startGoogleSignIn,
  type AuthConfig,
} from '../api/auth';
import { useAuth } from '../auth/AuthContext';

interface GisId {
  initialize(opts: {
    client_id: string;
    callback: (resp: { credential: string }) => void;
  }): void;
  prompt(): void;
}

declare global {
  interface Window {
    google?: { accounts?: { id?: GisId } };
  }
}

const GIS_SRC = 'https://accounts.google.com/gsi/client';

const ERROR_MESSAGES: Record<string, string> = {
  invalid_state: 'Your sign-in session expired — please try again.',
  token_exchange_failed: 'Google sign-in failed during token exchange — please try again.',
  missing_id_token: 'Google did not return an identity token — please try again.',
  invalid_id_token: 'Google identity verification failed — please try again.',
  'google:access_denied': 'You declined the Google consent screen.',
};

function friendlyError(code: string | null): string | null {
  if (!code) return null;
  if (ERROR_MESSAGES[code]) return ERROR_MESSAGES[code];
  if (code.startsWith('google:')) return `Google returned an error: ${code.slice(7)}`;
  return 'Sign-in failed — please try again.';
}

function GoogleGIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 48 48" aria-hidden="true">
      <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z" />
      <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z" />
      <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z" />
      <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z" />
    </svg>
  );
}

export function LoginPage() {
  const { user, loading } = useAuth();
  const navigate = useNavigate();
  const [config, setConfig] = useState<AuthConfig | null>(null);
  const [configLoading, setConfigLoading] = useState(true);
  const [signingIn, setSigningIn] = useState(false);
  const [error, setError] = useState<string | null>(
    friendlyError(new URLSearchParams(window.location.search).get('error'))
  );

  useEffect(() => {
    let cancelled = false;
    getAuthConfig()
      .then((c) => {
        if (!cancelled) {
          setConfig(c);
          setConfigLoading(false);
          if (c.configured) initOneTap(c.google_client_id);
        }
      })
      .catch(() => !cancelled && setConfigLoading(false));
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const initOneTap = (clientId: string) => {
    const boot = () => {
      const gis = window.google?.accounts?.id;
      if (!gis) return;
      gis.initialize({
        client_id: clientId,
        callback: async (resp) => {
          try {
            const gCsrf =
              document.cookie
                .split('; ')
                .find((c) => c.startsWith('g_csrf_token='))
                ?.split('=')[1] ?? null;
            await postCredential(resp.credential, gCsrf);
            navigate('/', { replace: true });
          } catch (err) {
            const detail =
              (err as { response?: { data?: { detail?: string } } })?.response
                ?.data?.detail;
            // Unknown accounts fall back to the combined-consent button below.
            if (detail && !detail.includes('Account not found')) {
              setError(detail);
            }
          }
        },
      });
      gis.prompt();
    };
    if (window.google?.accounts?.id) {
      boot();
      return;
    }
    const existing = document.querySelector<HTMLScriptElement>(
      `script[src="${GIS_SRC}"]`
    );
    if (existing) {
      existing.addEventListener('load', boot);
      return;
    }
    const script = document.createElement('script');
    script.src = GIS_SRC;
    script.async = true;
    script.defer = true;
    script.onload = boot;
    document.head.appendChild(script);
  };

  if (!loading && user) return <Navigate to="/" replace />;

  const configured = config?.configured ?? false;

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background:
          'radial-gradient(1200px 600px at 20% -10%, rgba(59,130,246,0.12), transparent), var(--bg-base, #0a0e17)',
        padding: 24,
      }}
    >
      <div
        style={{
          width: '100%',
          maxWidth: 400,
          background: 'var(--bg-card, #111827)',
          border: '1px solid var(--border-default, #1f2937)',
          borderRadius: 12,
          padding: '36px 32px',
          display: 'flex',
          flexDirection: 'column',
          gap: 20,
        }}
      >
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 10 }}>
          <div
            style={{
              width: 52,
              height: 52,
              borderRadius: 12,
              background: 'rgba(59,130,246,0.12)',
              border: '1px solid rgba(59,130,246,0.35)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <ShieldCheck size={26} style={{ color: '#60a5fa' }} />
          </div>
          <h1 style={{ fontSize: '1.35rem', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
            PhishNet
          </h1>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', margin: 0, textAlign: 'center' }}>
            AI-powered phishing detection for your inbox
          </p>
        </div>

        {error && (
          <div
            style={{
              background: 'rgba(239,68,68,0.1)',
              border: '1px solid rgba(239,68,68,0.35)',
              color: '#fca5a5',
              borderRadius: 8,
              padding: '10px 12px',
              fontSize: '0.78rem',
            }}
          >
            {error}
          </div>
        )}

        <button
          onClick={() => {
            if (!configured || signingIn) return;
            setSigningIn(true);
            startGoogleSignIn();
          }}
          disabled={!configured || configLoading || signingIn}
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 10,
            width: '100%',
            padding: '11px 16px',
            borderRadius: 8,
            border: configured ? '1px solid #dadce0' : '1px solid var(--border-default)',
            background: configured ? '#ffffff' : 'var(--bg-panel)',
            color: configured ? '#3c4043' : 'var(--text-muted)',
            fontSize: '0.88rem',
            fontWeight: 600,
            cursor: configured ? 'pointer' : 'not-allowed',
            opacity: signingIn ? 0.7 : 1,
          }}
        >
          <GoogleGIcon />
          {signingIn ? 'Opening Google…' : 'Sign in with Google'}
        </button>

        {!configLoading && !configured && (
          <p style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textAlign: 'center', margin: 0 }}>
            Google sign-in is not configured yet (P0 — Google Cloud Console
            client ID).
          </p>
        )}

        <div style={{ borderTop: '1px solid var(--border-default)', paddingTop: 16, display: 'flex', flexDirection: 'column', gap: 10 }}>
          <PrivacyLine icon={<Lock size={13} />} text="One consent links your Gmail read-only — analysis runs privately per account." />
          <PrivacyLine icon={<Mail size={13} />} text="We only ever read mail to scan it. We never send, delete, or modify it." />
        </div>
      </div>
    </div>
  );
}

function PrivacyLine({ icon, text }: { icon: React.ReactNode; text: string }) {
  return (
    <div style={{ display: 'flex', gap: 8, alignItems: 'flex-start', color: 'var(--text-muted)' }}>
      <span style={{ marginTop: 2, flexShrink: 0 }}>{icon}</span>
      <span style={{ fontSize: '0.72rem', lineHeight: 1.5 }}>{text}</span>
    </div>
  );
}
