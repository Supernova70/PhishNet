import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Layout } from './components/layout/Layout';
import { Dashboard } from './pages/Dashboard';
import { EmailInbox } from './pages/EmailInbox';
import { ScanResults } from './pages/ScanResults';
import { ScanDetail } from './pages/ScanDetail';
import { HealthPage } from './pages/HealthPage';
import { ActiveScans } from './pages/ActiveScans';
import { UrlAnalysis } from './pages/UrlAnalysis';
import { AttachmentsPage } from './pages/AttachmentsPage';
import { SettingsPage } from './pages/SettingsPage';
import { TracePage } from './pages/TracePage';
import { ReportPage } from './pages/ReportPage';
import { GraphPage } from './pages/GraphPage';
import { CampaignsPage } from './pages/CampaignsPage';
import { AlertsPage } from './pages/AlertsPage';
import { LoginPage } from './pages/LoginPage';
import { SystemHealthProvider } from './hooks/useSystemHealth';
import { AuthProvider, useAuth } from './auth/AuthContext';
import { ShieldCheck } from 'lucide-react';

function ProtectedLayout() {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div
        style={{
          minHeight: '100vh',
          display: 'flex',
          flexDirection: 'column',
          gap: 12,
          alignItems: 'center',
          justifyContent: 'center',
          background: 'var(--bg-base, #0a0e17)',
        }}
      >
        <ShieldCheck size={34} style={{ color: '#60a5fa' }} />
        <span style={{ color: 'var(--text-muted)', fontSize: '0.82rem' }}>
          Loading PhishNet…
        </span>
      </div>
    );
  }

  if (!user) return <Navigate to="/login" replace />;
  return <Layout />;
}

export default function App() {
  return (
    <SystemHealthProvider>
      <AuthProvider>
        <BrowserRouter>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route path="/" element={<ProtectedLayout />}>
              <Route index element={<Dashboard />} />
              <Route path="emails" element={<EmailInbox />} />
              <Route path="active-scans" element={<ActiveScans />} />
              <Route path="scans" element={<ScanResults />} />
              <Route path="scans/:id" element={<ScanDetail />} />
              <Route path="scans/:id/report" element={<ReportPage />} />
              <Route path="emails/:id/trace" element={<TracePage />} />
              <Route path="graph" element={<GraphPage />} />
              <Route path="campaigns" element={<CampaignsPage />} />
              <Route path="campaigns/:id" element={<CampaignsPage />} />
              <Route path="alerts" element={<AlertsPage />} />
              <Route path="url-analysis" element={<UrlAnalysis />} />
              <Route path="attachments" element={<AttachmentsPage />} />
              <Route path="system-health" element={<HealthPage />} />
              <Route path="settings" element={<SettingsPage />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Route>
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </SystemHealthProvider>
  );
}
