import React from 'react';
import { useAuth } from '../context/AuthContext';

export default function Navbar({ lastUpdated, onRefresh }) {
  const { user, logout } = useAuth();

  return (
    <header className="navbar">
      <div className="nav-brand">
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ color: '#6366f1' }}>
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          <path d="m9 12 2 2 4-4" />
        </svg>
        <span>Secure<span style={{ color: '#6366f1' }}>DB</span></span>
        <span className="brand-badge">CSE DEFENSE</span>
      </div>

      <div className="nav-actions">
        {lastUpdated && (
          <span style={{ fontSize: '0.785rem', color: 'var(--text-dim)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#10b981', display: 'inline-block' }}></span>
            Auto-refresh 15s (Last: {lastUpdated.toLocaleTimeString()})
          </span>
        )}

        <button onClick={onRefresh} className="btn btn-secondary btn-sm" title="Refresh Now">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8" />
            <path d="M3 3v5h5" />
            <path d="M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16" />
            <path d="M16 21h5v-5" />
          </svg>
          Sync
        </button>

        {user && (
          <div className="user-pill">
            <span style={{ fontWeight: 600 }}>{user.username}</span>
            <span className={`role-badge role-${user.role.toLowerCase()}`}>{user.role}</span>
          </div>
        )}

        <button onClick={logout} className="btn btn-secondary btn-sm" title="Logout">
          Sign out
        </button>
      </div>
    </header>
  );
}
