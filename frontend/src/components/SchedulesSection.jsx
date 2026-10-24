import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { api } from '../api';

export default function SchedulesSection({ schedules, databases, onRefresh }) {
  const { user } = useAuth();
  const [showModal, setShowModal] = useState(false);
  const [formData, setFormData] = useState({
    target_db_id: databases[0]?.id || '',
    cron_expression: '0 2 * * *',
    retention_count: 5
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const canManage = user?.role === 'admin';

  const handleCreate = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      await api.createSchedule({
        target_db_id: Number(formData.target_db_id || databases[0].id),
        cron_expression: formData.cron_expression,
        retention_count: Number(formData.retention_count)
      });
      setShowModal(false);
      onRefresh();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm(`Delete automated schedule #${id}?`)) return;
    try {
      await api.deleteSchedule(id);
      onRefresh();
    } catch (err) {
      alert(`Delete failed: ${err.message}`);
    }
  };

  return (
    <div className="card" style={{ marginBottom: '2rem' }}>
      <div className="card-header">
        <div>
          <h3 className="card-title">
            <span>⏱️</span> Automated Backup Schedules & Retention
          </h3>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: 2 }}>
            APScheduler cron triggers with automated prune retention policy
          </p>
        </div>

        {canManage && (
          <button onClick={() => setShowModal(true)} className="btn btn-primary btn-sm" disabled={databases.length === 0}>
            + Create Schedule
          </button>
        )}
      </div>

      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Target Database</th>
              <th>Cron Expression</th>
              <th>Retention Count</th>
              <th>Status</th>
              <th>Next Run</th>
              {canManage && <th style={{ textAlign: 'right' }}>Actions</th>}
            </tr>
          </thead>
          <tbody>
            {schedules.length === 0 ? (
              <tr>
                <td colSpan="7" style={{ textAlign: 'center', padding: '1.5rem', color: 'var(--text-dim)' }}>
                  No automated schedules configured.
                </td>
              </tr>
            ) : (
              schedules.map((s) => (
                <tr key={s.id}>
                  <td style={{ fontWeight: 700 }}>#{s.id}</td>
                  <td style={{ fontWeight: 600 }}>{s.target_db_name}</td>
                  <td><code>{s.cron_expression}</code></td>
                  <td>Keep last <strong>{s.retention_count}</strong> backups</td>
                  <td>
                    <span className="badge badge-safe">● RUNNING</span>
                  </td>
                  <td style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                    {s.next_run_at ? new Date(s.next_run_at).toLocaleString() : 'Managed by APScheduler'}
                  </td>
                  {canManage && (
                    <td style={{ textAlign: 'right' }}>
                      <button onClick={() => handleDelete(s.id)} className="btn btn-danger btn-sm">
                        Delete
                      </button>
                    </td>
                  )}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {showModal && (
        <div className="modal-overlay">
          <div className="modal-card">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <h3 style={{ color: '#fff', fontSize: '1.15rem' }}>Create Automated Schedule</h3>
              <button onClick={() => setShowModal(false)} className="btn btn-secondary btn-sm">✕</button>
            </div>

            {error && (
              <div style={{ background: 'rgba(239, 68, 68, 0.15)', border: '1px solid #ef4444', color: '#f87171', padding: '0.65rem', borderRadius: 6, fontSize: '0.85rem', marginBottom: '1rem' }}>
                {error}
              </div>
            )}

            <form onSubmit={handleCreate}>
              <div className="form-group">
                <label className="form-label">Target Database</label>
                <select
                  className="form-control"
                  value={formData.target_db_id}
                  onChange={(e) => setFormData({ ...formData, target_db_id: e.target.value })}
                  required
                >
                  {databases.map((db) => (
                    <option key={db.id} value={db.id}>
                      {db.name} ({db.database_name})
                    </option>
                  ))}
                </select>
              </div>

              <div className="form-group">
                <label className="form-label">Cron Expression</label>
                <input
                  type="text"
                  className="form-control"
                  value={formData.cron_expression}
                  onChange={(e) => setFormData({ ...formData, cron_expression: e.target.value })}
                  required
                  placeholder="0 2 * * * (Daily at 2:00 AM)"
                />
                <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: 4, display: 'block' }}>
                  Standard crontab format: minute hour day-of-month month day-of-week
                </span>
              </div>

              <div className="form-group">
                <label className="form-label">Retention Policy (Keep Last N Backups)</label>
                <input
                  type="number"
                  min="1"
                  max="100"
                  className="form-control"
                  value={formData.retention_count}
                  onChange={(e) => setFormData({ ...formData, retention_count: Number(e.target.value) })}
                  required
                />
                <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: 4, display: 'block' }}>
                  Older backups beyond this limit will be securely erased from storage.
                </span>
              </div>

              <div style={{ display: 'flex', gap: '0.5rem', marginTop: '1.25rem' }}>
                <button type="button" onClick={() => setShowModal(false)} className="btn btn-secondary">
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary" style={{ flex: 1 }} disabled={loading}>
                  {loading ? 'Creating...' : 'Activate Schedule'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
