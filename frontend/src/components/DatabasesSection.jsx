import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { api } from '../api';

export default function DatabasesSection({ databases, onRefresh }) {
  const { user } = useAuth();
  const [showAddModal, setShowAddModal] = useState(false);
  const [formData, setFormData] = useState({
    name: '',
    host: 'localhost',
    port: 5432,
    username: 'postgres',
    password: '',
    database_name: '',
    db_type: 'postgresql'
  });
  const [testResult, setTestResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const canAdd = user?.role === 'admin';
  const canDelete = user?.role === 'admin';

  const handleTestConnection = async () => {
    setLoading(true);
    setTestResult(null);
    setError(null);
    try {
      const res = await api.testConnection(formData);
      setTestResult(res);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleCreate = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      await api.createDatabase(formData);
      setShowAddModal(false);
      setFormData({
        name: '',
        host: 'localhost',
        port: 5432,
        username: 'postgres',
        password: '',
        database_name: '',
        db_type: 'postgresql'
      });
      onRefresh();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (id, name) => {
    if (!window.confirm(`Delete database configuration for '${name}'?`)) return;
    try {
      await api.deleteDatabase(id);
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
            <span>🗄️</span> Target Databases
          </h3>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: 2 }}>
            Connected instances protected by AES-GCM credential envelope encryption
          </p>
        </div>

        {canAdd && (
          <button onClick={() => setShowAddModal(true)} className="btn btn-primary btn-sm">
            + Register Database
          </button>
        )}
      </div>

      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>Display Name</th>
              <th>Host & Port</th>
              <th>Username</th>
              <th>Database Name</th>
              <th>Engine</th>
              <th>Status</th>
              {canDelete && <th style={{ textAlign: 'right' }}>Actions</th>}
            </tr>
          </thead>
          <tbody>
            {databases.map((db) => (
              <tr key={db.id}>
                <td style={{ fontWeight: 600 }}>{db.name}</td>
                <td><code>{db.host}:{db.port}</code></td>
                <td>{db.username}</td>
                <td><code>{db.database_name}</code></td>
                <td>
                  <span style={{ textTransform: 'uppercase', fontSize: '0.75rem', fontWeight: 700, color: '#818cf8' }}>
                    {db.db_type}
                  </span>
                </td>
                <td>
                  <span className="badge badge-safe">● ACTIVE</span>
                </td>
                {canDelete && (
                  <td style={{ textAlign: 'right' }}>
                    <button onClick={() => handleDelete(db.id, db.name)} className="btn btn-danger btn-sm">
                      Delete
                    </button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {showAddModal && (
        <div className="modal-overlay">
          <div className="modal-card">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <h3 style={{ color: '#fff', fontSize: '1.15rem' }}>Register Target Database</h3>
              <button onClick={() => setShowAddModal(false)} className="btn btn-secondary btn-sm">✕</button>
            </div>

            {error && (
              <div style={{ background: 'rgba(239, 68, 68, 0.15)', border: '1px solid #ef4444', color: '#f87171', padding: '0.65rem', borderRadius: 6, fontSize: '0.85rem', marginBottom: '1rem' }}>
                {error}
              </div>
            )}

            {testResult && (
              <div style={{ background: 'rgba(16, 185, 129, 0.15)', border: '1px solid #10b981', color: '#34d399', padding: '0.65rem', borderRadius: 6, fontSize: '0.85rem', marginBottom: '1rem' }}>
                ✓ {testResult.message}
              </div>
            )}

            <form onSubmit={handleCreate}>
              <div className="form-group">
                <label className="form-label">Display Identifier</label>
                <input
                  type="text"
                  className="form-control"
                  placeholder="e.g., CollegeDB_Production"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  required
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '0.75rem' }}>
                <div className="form-group">
                  <label className="form-label">Host</label>
                  <input
                    type="text"
                    className="form-control"
                    value={formData.host}
                    onChange={(e) => setFormData({ ...formData, host: e.target.value })}
                    required
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Port</label>
                  <input
                    type="number"
                    className="form-control"
                    value={formData.port}
                    onChange={(e) => setFormData({ ...formData, port: Number(e.target.value) })}
                    required
                  />
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                <div className="form-group">
                  <label className="form-label">Database Name</label>
                  <input
                    type="text"
                    className="form-control"
                    placeholder="collegedb"
                    value={formData.database_name}
                    onChange={(e) => setFormData({ ...formData, database_name: e.target.value })}
                    required
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Username</label>
                  <input
                    type="text"
                    className="form-control"
                    value={formData.username}
                    onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                    required
                  />
                </div>
              </div>

              <div className="form-group">
                <label className="form-label">Password (Encrypted at Rest via HKDF-derived Key)</label>
                <input
                  type="password"
                  className="form-control"
                  placeholder="••••••••••••"
                  value={formData.password}
                  onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                  required
                />
              </div>

              <div style={{ display: 'flex', gap: '0.5rem', marginTop: '1.25rem' }}>
                <button type="button" onClick={handleTestConnection} className="btn btn-secondary" disabled={loading}>
                  Test Connection
                </button>
                <button type="submit" className="btn btn-primary" style={{ flex: 1 }} disabled={loading}>
                  {loading ? 'Saving...' : 'Save Database'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
