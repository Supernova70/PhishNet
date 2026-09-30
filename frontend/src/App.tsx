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
import { SystemHealthProvider } from './hooks/useSystemHealth';

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
          <Route path="scans/:id/report" element={<ReportPage />} />
          <Route path="emails/:id/trace" element={<TracePage />} />
          <Route path="graph" element={<GraphPage />} />
          <Route path="campaigns" element={<CampaignsPage />} />
          <Route path="campaigns/:id" element={<CampaignsPage />} />
          <Route path="alerts" element={<AlertsPage />} />
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
