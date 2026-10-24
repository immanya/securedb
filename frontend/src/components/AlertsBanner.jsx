import React from 'react';
import { useAuth } from '../context/AuthContext';

export default function AlertsBanner({ alerts, onResolve }) {
  const { user } = useAuth();
  const canResolve = user?.role === 'admin' || user?.role === 'manager';

  if (!alerts || alerts.length === 0) return null;

  return (
    <div className="alerts-banner-container">
      {alerts.map((alert) => (
        <div 
          key={alert.id} 
          className={`alert-banner ${alert.severity === 'CRITICAL' ? 'alert-critical' : 'alert-high'}`}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <span style={{ fontSize: '1.25rem' }}>
              {alert.severity === 'CRITICAL' ? '🚨' : '⚠️'}
            </span>
            <div>
              <strong style={{ textTransform: 'uppercase', marginRight: '0.5rem' }}>
                [{alert.severity}] {alert.alert_type.replace('_', ' ')}:
              </strong>
              <span>{alert.message}</span>
              <span style={{ fontSize: '0.75rem', opacity: 0.8, marginLeft: '0.75rem' }}>
                {new Date(alert.created_at).toLocaleTimeString()}
              </span>
            </div>
          </div>

          {canResolve && (
            <button 
              onClick={() => onResolve(alert.id)} 
              className="btn btn-secondary btn-sm"
              style={{ background: 'rgba(0,0,0,0.3)', borderColor: 'rgba(255,255,255,0.2)' }}
            >
              Acknowledge & Resolve
            </button>
          )}
        </div>
      ))}
    </div>
  );
}
