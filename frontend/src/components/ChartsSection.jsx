import React from 'react';
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
  BarChart, Bar
} from 'recharts';

export default function ChartsSection({ charts }) {
  if (!charts) return null;

  const { backup_size_history = [], status_distribution = [], login_attempts_7days = [] } = charts;

  const tooltipStyle = {
    backgroundColor: '#111827',
    borderColor: '#1f2937',
    borderRadius: '8px',
    color: '#fff',
    fontSize: '0.85rem'
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', marginBottom: '2rem' }}>
      <div className="charts-grid">
        {/* Chart 1: Backup Size Over Time */}
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">
              <span>📈</span> Encrypted Backup Volume Over Time
            </h3>
            <span style={{ fontSize: '0.785rem', color: 'var(--text-muted)' }}>4 MB AES-GCM Chunks</span>
          </div>
          <div style={{ width: '100%', height: 260 }}>
            {backup_size_history.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={backup_size_history} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="sizeGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#6366f1" stopOpacity={0.5}/>
                      <stop offset="95%" stopColor="#6366f1" stopOpacity={0.0}/>
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="date" stroke="#6b7280" fontSize={11} tickLine={false} />
                  <YAxis stroke="#6b7280" fontSize={11} unit=" KB" tickLine={false} />
                  <Tooltip contentStyle={tooltipStyle} formatter={(val) => [`${val} KB`, 'Encrypted Size']} />
                  <Area type="monotone" dataKey="size_kb" stroke="#6366f1" strokeWidth={2} fillOpacity={1} fill="url(#sizeGradient)" />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--text-dim)' }}>
                No backup snapshots recorded yet
              </div>
            )}
          </div>
        </div>

        {/* Chart 2: Status Distribution */}
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">
              <span>🛡️</span> Cryptographic Integrity Status
            </h3>
          </div>
          <div style={{ width: '100%', height: 260 }}>
            {status_distribution.some(d => d.value > 0) ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={status_distribution}
                    cx="50%"
                    cy="45%"
                    innerRadius={55}
                    outerRadius={80}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {status_distribution.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={tooltipStyle} />
                  <Legend 
                    verticalAlign="bottom" 
                    height={36} 
                    iconType="circle"
                    formatter={(val) => <span style={{ color: '#9ca3af', fontSize: '0.8rem' }}>{val}</span>}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--text-dim)' }}>
                No backups to evaluate
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Chart 3: Login Attempts (Success vs Failed) */}
      <div className="card">
        <div className="card-header">
          <h3 className="card-title">
            <span>🔐</span> Authentication Telemetry (Past 7 Days)
          </h3>
          <span style={{ fontSize: '0.785rem', color: 'var(--text-muted)' }}>Argon2id & Anomaly Monitor</span>
        </div>
        <div style={{ width: '100%', height: 220 }}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={login_attempts_7days} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <XAxis dataKey="day" stroke="#6b7280" fontSize={11} tickLine={false} />
              <YAxis stroke="#6b7280" fontSize={11} allowDecimals={false} tickLine={false} />
              <Tooltip contentStyle={tooltipStyle} />
              <Legend formatter={(val) => <span style={{ color: '#9ca3af', fontSize: '0.8rem', textTransform: 'capitalize' }}>{val}</span>} />
              <Bar dataKey="success" fill="#10b981" radius={[4, 4, 0, 0]} name="Successful Logins" />
              <Bar dataKey="failed" fill="#ef4444" radius={[4, 4, 0, 0]} name="Failed Attempts / Lockouts" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
