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
import { SystemHealthProvider } from './hooks/useSystemHealth';

// ─── Placeholder pages for nav items without full pages ──────────────────────
function PlaceholderPage({ title }: { title: string }) {
  return (
    <div style={{ padding: 40, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: 300 }}>
      <p style={{ fontSize: '2rem', color: 'var(--text-muted)', marginBottom: 12 }}>🚧</p>
      <p style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-secondary)' }}>{title}</p>
      <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', marginTop: 6 }}>Coming soon in a future release</p>
    </div>
  );
}

export default function App() {
  return (
    <SystemHealthProvider>
      <BrowserRouter>
        <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Dashboard />} />
          <Route path="emails" element={<EmailInbox />} />
          <Route path="active-scans" element={<ActiveScans />} />
          <Route path="scans" element={<ScanResults />} />
          <Route path="scans/:id" element={<ScanDetail />} />
          <Route path="url-analysis" element={<UrlAnalysis />} />
          <Route path="attachments" element={<AttachmentsPage />} />
          <Route path="health" element={<HealthPage />} />
          <Route path="settings" element={<SettingsPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
        </Routes>
      </BrowserRouter>
    </SystemHealthProvider>
  );
}
