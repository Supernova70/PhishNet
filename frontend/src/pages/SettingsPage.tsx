import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import {
  Settings,
  Key,
  Shield,
  Brain,
  Link2,
  RefreshCw,
  AlertCircle,
  CheckCircle2,
  Save,
  Eye,
  EyeOff,
  Sliders,
} from 'lucide-react';
import { apiClient } from '../api/client';

// ── Types ─────────────────────────────────────────────────

interface SystemConfig {
  vt_configured: boolean;
  vt_key_preview: string;
  gs_browsing_configured: boolean;
  dynamic_url_analysis_enabled: boolean;
  auto_scan_enabled: boolean;
  scan_threshold: number;
  max_concurrent_scans: number;
  yara_enabled: boolean;
  ml_model_loaded: boolean;
}

// ── Settings Page ─────────────────────────────────────────

export function SettingsPage() {
  const [config, setConfig] = useState<SystemConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // API Key states
  const [vtKey, setVtKey] = useState('');
  const [showVtKey, setShowVtKey] = useState(false);
  const [savingKey, setSavingKey] = useState(false);

  // Editable settings
  const [autoScan, setAutoScan] = useState(true);
  const [threshold, setThreshold] = useState(40);
  const [maxConcurrent, setMaxConcurrent] = useState(3);
  const [dynamicAnalysis, setDynamicAnalysis] = useState(false);

  useEffect(() => {
    apiClient.get('/settings')
      .then(({ data }) => {
        setConfig(data);
        setAutoScan(data.auto_scan_enabled);
        setThreshold(data.scan_threshold);
        setMaxConcurrent(data.max_concurrent_scans);
        setDynamicAnalysis(data.dynamic_url_analysis_enabled);
      })
      .catch((err) =>
        setError(
          (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
            ?? err.message
        )
      )
      .finally(() => setLoading(false));
  }, []);

  const handleSave = async () => {
    setSaving(true);
    setSuccess(null);
    setError(null);
    try {
      const { data } = await apiClient.put('/settings', {
        auto_scan_enabled: autoScan,
        scan_threshold: threshold,
        max_concurrent_scans: maxConcurrent,
        dynamic_url_analysis_enabled: dynamicAnalysis,
      });
      setConfig(data);
      setSuccess('Settings saved successfully');
      setTimeout(() => setSuccess(null), 3000);
    } catch (err: unknown) {
      setError(
        (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
          ?? (err instanceof Error ? err.message : 'Failed to save')
      );
    } finally {
      setSaving(false);
    }
  };

  const handleSaveApiKey = async (provider: string, key: string) => {
    if (!key.trim()) return;
    setSavingKey(true);
    setSuccess(null);
    try {
      const { data } = await apiClient.post('/settings/api-keys', { provider, api_key: key });
      setSuccess(data.message);
      setVtKey('');
      setShowVtKey(false);
      // Refresh config
      const { data: newConfig } = await apiClient.get('/settings');
      setConfig(newConfig);
      setTimeout(() => setSuccess(null), 3000);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to save key');
    } finally {
      setSavingKey(false);
    }
  };

  if (loading) {
    return (
      <div style={{ padding: 24 }}>
        <div className="skeleton" style={{ height: 32, width: 200, borderRadius: 4, marginBottom: 24 }} />
        <div className="skeleton" style={{ height: 300, borderRadius: 8 }} />
      </div>
    );
  }

  return (
    <div style={{ padding: 24, maxWidth: 900, margin: '0 auto' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 24 }}>
        <Settings size={24} style={{ color: 'var(--primary)' }} />
        <h1 style={{ fontSize: '1.25rem', fontWeight: 800, color: 'var(--text-primary)' }}>System Settings</h1>
      </div>

      {/* Status Messages */}
      {success && (
        <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }}
          style={{ padding: '10px 16px', borderRadius: 6, background: 'var(--safe-subtle)', border: '1px solid var(--safe)', color: 'var(--text-safe)', marginBottom: 16, display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.875rem' }}>
          <CheckCircle2 size={16} /> {success}
        </motion.div>
      )}
      {error && (
        <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }}
          style={{ padding: '10px 16px', borderRadius: 6, background: 'var(--danger-subtle)', border: '1px solid var(--danger)', color: 'var(--text-danger)', marginBottom: 16, display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.875rem' }}>
          <AlertCircle size={16} /> {error}
        </motion.div>
      )}

      <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
        {/* API Keys Section */}
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
          style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, padding: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
            <Key size={18} style={{ color: 'var(--warning)' }} />
            <h2 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)' }}>API Keys</h2>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {/* VirusTotal */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 16px', background: 'var(--bg-input)', borderRadius: 6 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <Shield size={16} style={{ color: config?.vt_configured ? 'var(--safe)' : 'var(--text-muted)' }} />
                <div>
                  <p style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-primary)' }}>VirusTotal</p>
                  <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                    {config?.vt_configured ? `Configured: ${config.vt_key_preview}` : 'Not configured'}
                  </p>
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <div style={{ position: 'relative' }}>
                  <input
                    className="dark-input"
                    type={showVtKey ? 'text' : 'password'}
                    placeholder="Enter API key"
                    value={vtKey}
                    onChange={(e) => setVtKey(e.target.value)}
                    style={{ width: 200, fontSize: '0.8rem', padding: '6px 32px 6px 10px' }}
                  />
                  <button onClick={() => setShowVtKey(!showVtKey)}
                    style={{ position: 'absolute', right: 6, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 2 }}>
                    {showVtKey ? <EyeOff size={14} /> : <Eye size={14} />}
                  </button>
                </div>
                <button className="btn-ghost" onClick={() => handleSaveApiKey('virustotal', vtKey)} disabled={savingKey || !vtKey.trim()}
                  style={{ padding: '6px 12px', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: 4 }}>
                  <Save size={12} /> Save
                </button>
              </div>
            </div>

            {/* Google Safe Browsing */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 16px', background: 'var(--bg-input)', borderRadius: 6 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <Shield size={16} style={{ color: config?.gs_browsing_configured ? 'var(--safe)' : 'var(--text-muted)' }} />
                <div>
                  <p style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-primary)' }}>Google Safe Browsing</p>
                  <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                    {config?.gs_browsing_configured ? 'Configured' : 'Not configured'}
                  </p>
                </div>
              </div>
            </div>
          </div>
        </motion.div>

        {/* Engine Status */}
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
          style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, padding: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
            <Brain size={18} style={{ color: 'var(--primary)' }} />
            <h2 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)' }}>Engine Status</h2>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
            {[
              { label: 'ML Model', loaded: config?.ml_model_loaded ?? false, icon: <Brain size={14} /> },
              { label: 'YARA Rules', loaded: config?.yara_enabled ?? false, icon: <Shield size={14} /> },
              { label: 'Dynamic Analysis', loaded: config?.dynamic_url_analysis_enabled ?? false, icon: <Link2 size={14} /> },
            ].map((eng) => (
              <div key={eng.label} style={{ padding: 12, background: 'var(--bg-input)', borderRadius: 6, display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ color: eng.loaded ? 'var(--safe)' : 'var(--text-muted)' }}>{eng.loaded ? <CheckCircle2 size={14} /> : <AlertCircle size={14} />}</span>
                {eng.icon}
                <div>
                  <p style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)' }}>{eng.label}</p>
                  <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{eng.loaded ? 'Active' : 'Inactive'}</p>
                </div>
              </div>
            ))}
          </div>
        </motion.div>

        {/* Scan Configuration */}
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}
          style={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', borderRadius: 8, padding: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
            <Sliders size={18} style={{ color: 'var(--primary)' }} />
            <h2 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)' }}>Scan Configuration</h2>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {/* Auto-scan toggle */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 16px', background: 'var(--bg-input)', borderRadius: 6 }}>
              <div>
                <p style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-primary)' }}>Auto-scan on Fetch</p>
                <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Automatically scan new emails when fetched</p>
              </div>
              <label style={{ position: 'relative', display: 'inline-block', width: 44, height: 24, cursor: 'pointer' }}>
                <input type="checkbox" checked={autoScan} onChange={(e) => setAutoScan(e.target.checked)} style={{ display: 'none' }} />
                <span style={{
                  position: 'absolute', inset: 0, borderRadius: 12,
                  background: autoScan ? 'var(--primary)' : 'var(--bg-input)',
                  border: `1px solid ${autoScan ? 'var(--primary)' : 'var(--border-default)'}`,
                  transition: 'all 200ms',
                }} />
                <span style={{
                  position: 'absolute', top: 2, left: autoScan ? 22 : 2,
                  width: 20, height: 20, borderRadius: '50%',
                  background: 'white', transition: 'all 200ms',
                  boxShadow: '0 1px 3px rgba(0,0,0,0.2)',
                }} />
              </label>
            </div>

            {/* Risk Threshold */}
            <div style={{ padding: '12px 16px', background: 'var(--bg-input)', borderRadius: 6 }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
                <p style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-primary)' }}>Risk Threshold</p>
                <span className="font-mono" style={{ fontSize: '0.8rem', color: 'var(--primary)', fontWeight: 700 }}>{threshold}</span>
              </div>
              <input type="range" min={10} max={90} value={threshold} onChange={(e) => setThreshold(Number(e.target.value))}
                style={{ width: '100%', accentColor: 'var(--primary)' }} />
              <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 4 }}>
                <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>More sensitive</span>
                <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>Less sensitive</span>
              </div>
            </div>

            {/* Max Concurrent Scans */}
            <div style={{ padding: '12px 16px', background: 'var(--bg-input)', borderRadius: 6 }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
                <p style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-primary)' }}>Max Concurrent Scans</p>
                <span className="font-mono" style={{ fontSize: '0.8rem', color: 'var(--primary)', fontWeight: 700 }}>{maxConcurrent}</span>
              </div>
              <input type="range" min={1} max={10} value={maxConcurrent} onChange={(e) => setMaxConcurrent(Number(e.target.value))}
                style={{ width: '100%', accentColor: 'var(--primary)' }} />
            </div>

            {/* Dynamic URL Analysis toggle */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 16px', background: 'var(--bg-input)', borderRadius: 6 }}>
              <div>
                <p style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-primary)' }}>Dynamic URL Analysis</p>
                <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Open URLs in headless browser (slower, more thorough)</p>
              </div>
              <label style={{ position: 'relative', display: 'inline-block', width: 44, height: 24, cursor: 'pointer' }}>
                <input type="checkbox" checked={dynamicAnalysis} onChange={(e) => setDynamicAnalysis(e.target.checked)} style={{ display: 'none' }} />
                <span style={{
                  position: 'absolute', inset: 0, borderRadius: 12,
                  background: dynamicAnalysis ? 'var(--primary)' : 'var(--bg-input)',
                  border: `1px solid ${dynamicAnalysis ? 'var(--primary)' : 'var(--border-default)'}`,
                  transition: 'all 200ms',
                }} />
                <span style={{
                  position: 'absolute', top: 2, left: dynamicAnalysis ? 22 : 2,
                  width: 20, height: 20, borderRadius: '50%',
                  background: 'white', transition: 'all 200ms',
                  boxShadow: '0 1px 3px rgba(0,0,0,0.2)',
                }} />
              </label>
            </div>
          </div>
        </motion.div>

        {/* Save Button */}
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}>
          <button className="btn-primary" onClick={handleSave} disabled={saving}
            style={{ width: '100%', padding: '12px 24px', fontSize: '0.9rem', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}>
            {saving ? <RefreshCw size={16} className="animate-spin" /> : <Save size={16} />}
            {saving ? 'Saving…' : 'Save All Settings'}
          </button>
        </motion.div>
      </div>
    </div>
  );
}
