import { useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { CheckCircle, XCircle, AlertCircle, Info, X } from 'lucide-react';
import type { ToastMessage } from '../../types';

interface ToastProps {
  toast: ToastMessage;
  onRemove: (id: string) => void;
}

const icons = {
  success: <CheckCircle size={16} style={{ color: 'var(--safe)' }} />,
  error: <XCircle size={16} style={{ color: 'var(--danger)' }} />,
  warning: <AlertCircle size={16} style={{ color: 'var(--warning)' }} />,
  info: <Info size={16} style={{ color: 'var(--primary)' }} />,
};

const borderColors = {
  success: 'var(--safe)',
  error: 'var(--danger)',
  warning: 'var(--warning)',
  info: 'var(--primary)',
};

function ToastItem({ toast, onRemove }: ToastProps) {
  const duration = toast.duration ?? 4000;

  useEffect(() => {
    const timer = setTimeout(() => onRemove(toast.id), duration);
    return () => clearTimeout(timer);
  }, [toast.id, duration, onRemove]);

  return (
    <motion.div
      layout
      initial={{ opacity: 0, x: 80, scale: 0.95 }}
      animate={{ opacity: 1, x: 0, scale: 1 }}
      exit={{ opacity: 0, x: 80, scale: 0.9 }}
      transition={{ duration: 0.25, ease: 'easeOut' }}
      style={{
        background: 'var(--bg-card)',
        border: '1px solid var(--border-default)',
        borderLeft: `3px solid ${borderColors[toast.type]}`,
        borderRadius: 8,
        padding: '12px 16px',
        display: 'flex',
        alignItems: 'flex-start',
        gap: 10,
        minWidth: 300,
        maxWidth: 380,
        boxShadow: '0 8px 32px rgba(0,0,0,0.4)',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      <div style={{ flexShrink: 0, marginTop: 1 }}>{icons[toast.type]}</div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <p style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: toast.message ? 2 : 0 }}>
          {toast.title}
        </p>
        {toast.message && (
          <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{toast.message}</p>
        )}
      </div>
      <button
        onClick={() => onRemove(toast.id)}
        style={{
          background: 'none',
          border: 'none',
          cursor: 'pointer',
          color: 'var(--text-muted)',
          padding: 2,
          flexShrink: 0,
          lineHeight: 1,
        }}
      >
        <X size={14} />
      </button>
      {/* Progress bar */}
      <div
        style={{
          position: 'absolute',
          bottom: 0,
          left: 0,
          height: 2,
          background: borderColors[toast.type],
          opacity: 0.5,
          animation: `progress-bar ${duration}ms linear forwards`,
        }}
      />
    </motion.div>
  );
}

interface ToastContainerProps {
  toasts: ToastMessage[];
  removeToast: (id: string) => void;
}

export function ToastContainer({ toasts, removeToast }: ToastContainerProps) {
  return (
    <div
      className="no-print"
      style={{
        position: 'fixed',
        top: 20,
        right: 20,
        zIndex: 9999,
        display: 'flex',
        flexDirection: 'column',
        gap: 8,
      }}
    >
      <AnimatePresence mode="popLayout">
        {toasts.map((toast) => (
          <ToastItem key={toast.id} toast={toast} onRemove={removeToast} />
        ))}
      </AnimatePresence>
    </div>
  );
}
