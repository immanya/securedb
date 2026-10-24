import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { api } from '../api';
import RestoreModal from './RestoreModal';

export default function BackupsTable({ backups, databases, onRefresh }) {
  const { user } = useAuth();
  const [selectedBackup, setSelectedBackup] = useState(null);
  const [verifyingId, setVerifyingId] = useState(null);
  const [creating, setCreating] = useState(false);
  const [selectedDbId, setSelectedDbId] = useState('');
  const [actionMessage, setActionMessage] = useState(null);

  const canCreate = user?.role === 'admin' || user?.role === 'manager';
  const canVerify = user?.role === 'admin' || user?.role === 'manager';
  const canRestore = user?.role === 'admin' || user?.role === 'manager';
  const canDelete = user?.role === 'admin';

  const handleCreate = async () => {
    if (!selectedDbId && databases.length > 0) {
      setSelectedDbId(databases[0].id);
    }
    const dbId = selectedDbId || databases[0]?.id;
    if (!dbId) {
      alert('Please select or register a target database first');
      return;
    }

    setCreating(true);
    setActionMessage(null);
    try {
      await api.createBackup(Number(dbId));
      setActionMessage({ type: 'success', text: 'Backup encrypted and stored successfully!' });
      onRefresh();
    } catch (err) {
      setActionMessage({ type: 'error', text: err.message });
    } finally {
      setCreating(false);
    }
  };

  const handleVerify = async (backupId, deep = false) => {
    setVerifyingId(backupId);
    setActionMessage(null);
    try {
      const res = await api.verifyBackup(backupId, deep);
      if (res.status === 'SAFE') {
        setActionMessage({
          type: 'success',
          text: `Backup #${backupId} Verified: SAFE! Level 1, 2 (HMAC), and Level 3 (AES-GCM Tags) matched perfectly.`
        });
      } else if (res.status === 'TAMPERED') {
        setActionMessage({
          type: 'error',
          text: `CRITICAL ALERT: Backup #${backupId} is TAMPERED! ${res.details.error_message}`
        });
      } else {
        setActionMessage({
          type: 'warning',
          text: `Backup #${backupId} verification failed: ${res.details.error_message}`
        });
      }
      onRefresh();
    } catch (err) {
      setActionMessage({ type: 'error', text: err.message });
    } finally {
      setVerifyingId(null);
    }
  };

  const handleDelete = async (backupId) => {
    if (!window.confirm(`Are you sure you want to delete encrypted backup #${backupId}?`)) return;
    try {
      await api.deleteBackup(backupId);
      setActionMessage({ type: 'success', text: `Backup #${backupId} deleted.` });
      onRefresh();
    } catch (err) {
      setActionMessage({ type: 'error', text: err.message });
    }
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case 'SAFE':
        return <span className="badge badge-safe">✓ SAFE</span>;
      case 'TAMPERED':
        return <span className="badge badge-tampered">⚠️ TAMPERED</span>;
      case 'FAILED':
        return <span className="badge badge-failed">✕ FAILED</span>;
      default:
        return <span className="badge badge-unverified">● UNVERIFIED</span>;
    }
  };

  return (
    <div className="card" style={{ marginBottom: '2rem' }}>
      <div className="card-header">
        <div>
          <h3 className="card-title">
            <span>📦</span> Encrypted Backups Repository
          </h3>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: 2 }}>
            AES-256-GCM Envelope Encrypted with HMAC-SHA256 Integrity Sealing
          </p>
        </div>

        {canCreate && (
          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
            <select
              className="form-control"
              style={{ width: 'auto', padding: '0.4rem 0.75rem', fontSize: '0.85rem' }}
              value={selectedDbId}
              onChange={(e) => setSelectedDbId(e.target.value)}
            >
              {databases.map((db) => (
                <option key={db.id} value={db.id}>
                  {db.name} ({db.database_name})
                </option>
              ))}
            </select>
            <button 
              onClick={handleCreate} 
              className="btn btn-primary btn-sm"
              disabled={creating || databases.length === 0}
            >
              {creating ? 'Encrypting...' : '+ Run Backup Now'}
            </button>
          </div>
        )}
      </div>

      {actionMessage && (
        <div style={{
          padding: '0.75rem 1rem',
          borderRadius: 6,
          marginBottom: '1rem',
          fontSize: '0.875rem',
          background: actionMessage.type === 'success' ? 'rgba(16, 185, 129, 0.15)' :
                      actionMessage.type === 'error' ? 'rgba(239, 68, 68, 0.15)' : 'rgba(245, 158, 11, 0.15)',
          color: actionMessage.type === 'success' ? '#34d399' :
                 actionMessage.type === 'error' ? '#f87171' : '#fbbf24',
          border: `1px solid ${actionMessage.type === 'success' ? '#10b981' :
                               actionMessage.type === 'error' ? '#ef4444' : '#f59e0b'}`
        }}>
          {actionMessage.text}
        </div>
      )}

      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Target Database</th>
              <th>Encrypted Size</th>
              <th>HMAC-SHA256 Seal</th>
              <th>Integrity Status</th>
              <th>Created At</th>
              <th style={{ textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {backups.length === 0 ? (
              <tr>
                <td colSpan="7" style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-dim)' }}>
                  No backup archives generated yet. Click "Run Backup Now" to create your first encrypted backup.
                </td>
              </tr>
            ) : (
              backups.map((b) => (
                <tr key={b.id}>
                  <td style={{ fontWeight: 700 }}>#{b.id}</td>
                  <td>
                    <span style={{ fontWeight: 600 }}>{b.target_db_name}</span>
                  </td>
                  <td>{(b.file_size_bytes / 1024).toFixed(2)} KB</td>
                  <td>
                    <code style={{ fontSize: '0.75rem', color: '#818cf8' }} title={b.encrypted_file_hmac}>
                      {b.encrypted_file_hmac.slice(0, 10)}...{b.encrypted_file_hmac.slice(-8)}
                    </code>
                  </td>
                  <td>{getStatusBadge(b.integrity_status)}</td>
                  <td style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                    {new Date(b.created_at).toLocaleString()}
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <div style={{ display: 'inline-flex', gap: '0.4rem' }}>
                      {canVerify && (
                        <>
                          <button
                            onClick={() => handleVerify(b.id, false)}
                            className="btn btn-secondary btn-sm"
                            disabled={verifyingId === b.id}
                            title="Verify Level 1 (Existence), Level 2 (HMAC), and Level 3 (GCM Tags)"
                          >
                            {verifyingId === b.id ? 'Checking...' : 'Verify'}
                          </button>
                          <button
                            onClick={() => handleVerify(b.id, true)}
                            className="btn btn-secondary btn-sm"
                            disabled={verifyingId === b.id}
                            title="Verify Level 1-4 (Deep restore into temporary database verify_tmp_<id>)"
                          >
                            Deep
                          </button>
                        </>
                      )}

                      {canRestore && (
                        <button
                          onClick={() => setSelectedBackup(b)}
                          className="btn btn-primary btn-sm"
                          style={{ background: '#3b82f6' }}
                          title="Restore into new isolated database"
                        >
                          Restore
                        </button>
                      )}

                      {canDelete && (
                        <button
                          onClick={() => handleDelete(b.id)}
                          className="btn btn-danger btn-sm"
                          title="Delete encrypted backup"
                        >
                          Delete
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {selectedBackup && (
        <RestoreModal
          backup={selectedBackup}
          onClose={() => setSelectedBackup(null)}
          onSuccess={() => {
            onRefresh();
          }}
        />
      )}
    </div>
  );
}
