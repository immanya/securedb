import React from 'react';

export default function StatCard({ title, value, type = 'default', subtitle, icon }) {
  return (
    <div className={`stat-card ${type}`}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span className="stat-title">{title}</span>
        {icon && <span style={{ fontSize: '1.2rem', opacity: 0.8 }}>{icon}</span>}
      </div>
      <div className="stat-value">{value}</div>
      {subtitle && <span style={{ fontSize: '0.775rem', color: 'var(--text-muted)' }}>{subtitle}</span>}
    </div>
  );
}
