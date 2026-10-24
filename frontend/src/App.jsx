import React, { useState, useEffect, useCallback } from 'react';
import { useAuth } from './context/AuthContext';
import { api } from './api';
import Navbar from './components/Navbar';
import AlertsBanner from './components/AlertsBanner';
import StatCard from './components/StatCard';
import ChartsSection from './components/ChartsSection';
import BackupsTable from './components/BackupsTable';
import DatabasesSection from './components/DatabasesSection';
import SchedulesSection from './components/SchedulesSection';
import AuditLogsTable from './components/AuditLogsTable';

export default function App() {
  const { user, login, register, loading: authLoading } = useAuth();
  
  // Dashboard state
  const [stats, setStats] = useState(null);
  const [charts, setCharts] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [backups, setBackups] = useState([]);
  const [databases, setDatabases] = useState([]);
  const [schedules, setSchedules] = useState([]);
  const [logs, setLogs] = useState([]);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');

  // Auth form state
  const [isRegister, setIsRegister] = useState(false);
  const [authUsername, setAuthUsername] = useState('');
  const [authPassword, setAuthPassword] = useState('');
  const [authError, setAuthError] = useState(null);
  const [authSubmitting, setAuthSubmitting] = useState(false);

  // Data fetching
  const refreshData = useCallback(async () => {
    if (!user) return;
    try {
      const [
        statsData,
        chartsData,
        alertsData,
        backupsData,
        databasesData,
        schedulesData,
        logsData
      ] = await Promise.all([
        api.getStats().catch(() => null),
        api.getCharts().catch(() => null),
        api.getAlerts('OPEN').catch(() => []),
        api.getBackups().catch(() => []),
        api.getDatabases().catch(() => []),
        api.getSchedules().catch(() => []),
        api.getLogs().catch(() => [])
      ]);

      if (statsData) setStats(statsData);
      if (chartsData) setCharts(chartsData);
      setAlerts(alertsData || []);
      setBackups(backupsData || []);
      setDatabases(databasesData || []);
      setSchedules(schedulesData || []);
      setLogs(logsData || []);
      setLastUpdated(new Date());
    } catch (err) {
      console.error('Data refresh error:', err);
    }
  }, [user]);

  // Initial load and 15s auto-refresh
  useEffect(() => {
    if (user) {
      refreshData();
      const interval = setInterval(refreshData, 15000); // 15 seconds
      return () => clearInterval(interval);
    }
  }, [user, refreshData]);

  // Auth submit handler
  const handleAuthSubmit = async (e) => {
    e.preventDefault();
    setAuthError(null);
    setAuthSubmitting(true);
    try {
      if (isRegister) {
        await register(authUsername, authPassword);
      } else {
        await login(authUsername, authPassword);
      }
    } catch (err) {
      setAuthError(err.message);
    } finally {
      setAuthSubmitting(false);
    }
  };

  const handleResolveAlert = async (id) => {
    try {
      await api.resolveAlert(id);
      refreshData();
    } catch (err) {
      alert(`Failed to resolve alert: ${err.message}`);
    }
  };

  if (authLoading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh', background: 'var(--bg-primary)', color: '#fff' }}>
        Loading SecureDB...
      </div>
    );
  }

  // --- Login / Register View ---
  if (!user) {
    return (
      <div className="auth-wrapper">
        <div className="auth-card">
          <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
            <div style={{ display: 'inline-flex', padding: '0.75rem', background: 'var(--primary-glow)', borderRadius: '12px', border: '1px solid rgba(99, 102, 241, 0.3)', marginBottom: '1rem' }}>
              <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="#6366f1" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                <path d="m9 12 2 2 4-4" />
              </svg>
            </div>
            <h1 style={{ fontSize: '1.75rem', fontWeight: 800, color: '#fff' }}>
              Secure<span style={{ color: '#6366f1' }}>DB</span>
            </h1>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginTop: '0.4rem' }}>
              Automated Database Backup & Cryptographic Security
            </p>
          </div>

          <div style={{ display: 'flex', background: 'var(--bg-primary)', padding: '0.25rem', borderRadius: 8, marginBottom: '1.5rem' }}>
            <button
              onClick={() => { setIsRegister(false); setAuthError(null); }}
              className={`btn ${!isRegister ? 'btn-primary' : 'btn-secondary'}`}
              style={{ flex: 1, padding: '0.45rem', fontSize: '0.85rem' }}
            >
              Sign In
            </button>
            <button
              onClick={() => { setIsRegister(true); setAuthError(null); }}
              className={`btn ${isRegister ? 'btn-primary' : 'btn-secondary'}`}
              style={{ flex: 1, padding: '0.45rem', fontSize: '0.85rem' }}
            >
              Register
            </button>
          </div>

          {authError && (
            <div style={{ background: 'rgba(239, 68, 68, 0.15)', border: '1px solid #ef4444', color: '#f87171', padding: '0.75rem', borderRadius: 6, fontSize: '0.85rem', marginBottom: '1.25rem' }}>
              {authError}
            </div>
          )}

          <form onSubmit={handleAuthSubmit}>
            <div className="form-group">
              <label className="form-label">Username</label>
              <input
                type="text"
                className="form-control"
                placeholder="Enter username"
                value={authUsername}
                onChange={(e) => setAuthUsername(e.target.value)}
                required
                autoComplete="username"
              />
            </div>

            <div className="form-group">
              <label className="form-label">Password</label>
              <input
                type="password"
                className="form-control"
                placeholder="Enter password (min 8 characters)"
                value={authPassword}
                onChange={(e) => setAuthPassword(e.target.value)}
                required
                minLength={8}
                autoComplete={isRegister ? "new-password" : "current-password"}
              />
            </div>

            {isRegister && (
              <div style={{ fontSize: '0.75rem', color: '#818cf8', marginBottom: '1.25rem' }}>
                ℹ️ The first registered user is provisioned as <strong>System Admin</strong>. Subsequent users receive the viewer role.
              </div>
            )}

            <button type="submit" className="btn btn-primary" style={{ width: '100%', marginTop: '0.5rem' }} disabled={authSubmitting}>
              {authSubmitting ? 'Authenticating...' : (isRegister ? 'Create Account' : 'Sign In to Console')}
            </button>
          </form>

          <div style={{ marginTop: '1.5rem', textAlign: 'center', fontSize: '0.75rem', color: 'var(--text-dim)' }}>
            Argon2id Hashing • AES-256-GCM Envelope Encryption • HMAC-SHA256
          </div>
        </div>
      </div>
    );
  }

  // --- Authenticated Dashboard View ---
  return (
    <div className="app-container">
      <Navbar lastUpdated={lastUpdated} onRefresh={refreshData} />

      <main className="main-content">
        {/* Security Alerts Banner */}
        <AlertsBanner alerts={alerts} onResolve={handleResolveAlert} />

        {/* Top KPI Stat Cards */}
        <div className="stats-grid">
          <StatCard
            title="Total Backups"
            value={stats ? stats.total_backups : '...'}
            type="primary"
            icon="📦"
            subtitle="Encrypted snapshots"
          />
          <StatCard
            title="Safe & Verified"
            value={stats ? stats.safe_backups : '...'}
            type="safe"
            icon="🛡️"
            subtitle="HMAC & GCM tags valid"
          />
          <StatCard
            title="Failed / Tampered"
            value={stats ? (stats.tampered_backups + stats.failed_backups) : '...'}
            type={(stats?.tampered_backups || stats?.failed_backups) ? 'danger' : 'default'}
            icon="⚠️"
            subtitle={stats?.tampered_backups ? `${stats.tampered_backups} tampered detected!` : 'Zero integrity errors'}
          />
          <StatCard
            title="Open Security Alerts"
            value={stats ? stats.open_alerts : '...'}
            type={stats?.open_alerts ? 'warning' : 'safe'}
            icon="🚨"
            subtitle={stats?.open_alerts ? 'Requires investigation' : 'System nominal'}
          />
        </div>

        {/* Tab Navigation */}
        <div className="tab-navigation">
          <button
            onClick={() => setActiveTab('overview')}
            className={`tab-btn ${activeTab === 'overview' ? 'active' : ''}`}
          >
            <span>📊</span> Security Overview & Charts
          </button>
          <button
            onClick={() => setActiveTab('backups')}
            className={`tab-btn ${activeTab === 'backups' ? 'active' : ''}`}
          >
            <span>📦</span> Backups Repository ({backups.length})
          </button>
          <button
            onClick={() => setActiveTab('databases')}
            className={`tab-btn ${activeTab === 'databases' ? 'active' : ''}`}
          >
            <span>🗄️</span> Databases ({databases.length})
          </button>
          <button
            onClick={() => setActiveTab('schedules')}
            className={`tab-btn ${activeTab === 'schedules' ? 'active' : ''}`}
          >
            <span>⏱️</span> Automated Schedules ({schedules.length})
          </button>
          <button
            onClick={() => setActiveTab('audit')}
            className={`tab-btn ${activeTab === 'audit' ? 'active' : ''}`}
          >
            <span>⛓️</span> Audit Chain Logs ({logs.length})
          </button>
        </div>

        {/* Tab Content */}
        {activeTab === 'overview' && (
          <>
            <ChartsSection charts={charts} />
            <BackupsTable backups={backups} databases={databases} onRefresh={refreshData} />
          </>
        )}

        {activeTab === 'backups' && (
          <BackupsTable backups={backups} databases={databases} onRefresh={refreshData} />
        )}

        {activeTab === 'databases' && (
          <DatabasesSection databases={databases} onRefresh={refreshData} />
        )}

        {activeTab === 'schedules' && (
          <SchedulesSection schedules={schedules} databases={databases} onRefresh={refreshData} />
        )}

        {activeTab === 'audit' && (
          <AuditLogsTable logs={logs} onRefresh={refreshData} />
        )}
      </main>
    </div>
  );
}
