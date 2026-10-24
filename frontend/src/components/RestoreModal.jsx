import React, { useState } from 'react';
import { api } from '../api';

export default function RestoreModal({ backup, onClose, onSuccess }) {
  const [targetDbName, setTargetDbName] = useState(`${backup.target_db_name}_restored_${Date.now().toString().slice(-4)}`);
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const res = await api.restoreBackup(backup.id, targetDbName, confirmPassword);
      setResult(res);
      if (onSuccess) onSuccess();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay">
      <div className="modal-card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
          <h3 style={{ fontSize: '1.15rem', color: '#fff', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span>🔄</span> Restore Database from Backup #{backup.id}
          </h3>
          <button onClick={onClose} className="btn btn-secondary btn-sm" disabled={loading}>✕</button>
        </div>

        {result ? (
          <div>
            <div style={{ background: 'rgba(16, 185, 129, 0.1)', border: '1px solid #10b981', padding: '1rem', borderRadius: 8, marginBottom: '1rem' }}>
              <div style={{ color: '#10b981', fontWeight: 700, marginBottom: '0.25rem' }}>✓ Restore Completed Successfully!</div>
              <div style={{ fontSize: '0.85rem' }}>{result.message}</div>
              <div style={{ fontSize: '0.785rem', color: 'var(--text-muted)', marginTop: '0.5rem' }}>
                Duration: {result.duration_seconds}s | Tables: {result.table_count}
              </div>
            </div>
            <button onClick={onClose} className="btn btn-primary" style={{ width: '100%' }}>Done</button>
          </div>
        ) : (
          <form onSubmit={handleSubmit}>
            <div style={{ background: 'rgba(99, 102, 241, 0.1)', border: '1px solid rgba(99, 102, 241, 0.3)', padding: '0.75rem', borderRadius: 6, fontSize: '0.8rem', marginBottom: '1rem', color: '#c7d2fe' }}>
              <strong>Security Protocol Notice:</strong> Overwriting the original database (<code>{backup.target_db_name}</code>) is strictly blocked. You must restore into a new, isolated database. Re-authentication is enforced.
            </div>

            {error && (
              <div style={{ background: 'rgba(239, 68, 68, 0.15)', border: '1px solid #ef4444', color: '#f87171', padding: '0.65rem 0.85rem', borderRadius: 6, fontSize: '0.85rem', marginBottom: '1rem' }}>
                {error}
              </div>
            )}

            <div className="form-group">
              <label className="form-label">New Target Database Name</label>
              <input
                type="text"
                className="form-control"
                value={targetDbName}
                onChange={(e) => setTargetDbName(e.target.value)}
                required
                pattern="^[a-zA-Z0-9_]+$"
                placeholder="e.g., collegedb_recovery_2026"
                disabled={loading}
              />
              <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: 4, display: 'block' }}>
                Alphanumeric characters and underscores only. Must differ from original.
              </span>
            </div>

            <div className="form-group">
              <label className="form-label">Confirm Your Login Password</label>
              <input
                type="password"
                className="form-control"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
                placeholder="Enter password to authorize recovery"
                disabled={loading}
              />
            </div>

            <div style={{ display: 'flex', gap: '0.75rem', marginTop: '1.5rem' }}>
              <button type="button" onClick={onClose} className="btn btn-secondary" style={{ flex: 1 }} disabled={loading}>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" style={{ flex: 2 }} disabled={loading}>
                {loading ? 'Verifying & Restoring...' : 'Confirm & Restore'}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
