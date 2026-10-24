import React, { useState } from 'react';
import { api } from '../api';

export default function AuditLogsTable({ logs, onRefresh }) {
  const [verifying, setVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState(null);

  const handleVerifyChain = async () => {
    setVerifying(true);
    try {
      const res = await api.verifyLogsChain();
      setVerificationResult(res);
    } catch (err) {
      setVerificationResult({
        valid: false,
        details: `Verification request failed: ${err.message}`
      });
    } finally {
      setVerifying(false);
    }
  };

  return (
    <div className="card" style={{ marginBottom: '2rem' }}>
      <div className="card-header">
        <div>
          <h3 className="card-title">
            <span>⛓️</span> Cryptographic Hash-Chained Audit Trail
          </h3>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: 2 }}>
            SHA-256 forward blockchain-style integrity linking every security event
          </p>
        </div>

        <button 
          onClick={handleVerifyChain} 
          className="btn btn-secondary btn-sm"
          disabled={verifying}
        >
          {verifying ? 'Verifying Chain...' : '🔍 Verify Chain Integrity'}
        </button>
      </div>

      {verificationResult && (
        <div style={{
          padding: '0.85rem 1.25rem',
          borderRadius: 8,
          marginBottom: '1rem',
          fontSize: '0.875rem',
          background: verificationResult.valid ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)',
          color: verificationResult.valid ? '#34d399' : '#f87171',
          border: `1px solid ${verificationResult.valid ? '#10b981' : '#ef4444'}`,
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}>
          <div>
            <strong>{verificationResult.valid ? '✓ Audit Chain Intact & Valid' : '⚠️ Audit Chain Corruption / Tamper Detected!'}</strong>
            <div style={{ fontSize: '0.8rem', marginTop: 2 }}>{verificationResult.details}</div>
            {!verificationResult.valid && verificationResult.broken_at_id && (
              <div style={{ fontWeight: 700, marginTop: 4 }}>
                Tampered Row Detected at Record ID #{verificationResult.broken_at_id}
              </div>
            )}
          </div>
          <button 
            onClick={() => setVerificationResult(null)} 
            className="btn btn-secondary btn-sm"
            style={{ background: 'transparent' }}
          >
            ✕
          </button>
        </div>
      )}

      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Timestamp</th>
              <th>Principal</th>
              <th>Action</th>
              <th>Resource</th>
              <th>Status</th>
              <th>Chained SHA-256 Hash</th>
            </tr>
          </thead>
          <tbody>
            {logs.length === 0 ? (
              <tr>
                <td colSpan="7" style={{ textAlign: 'center', padding: '1.5rem', color: 'var(--text-dim)' }}>
                  No security audit records logged yet.
                </td>
              </tr>
            ) : (
              logs.map((log) => {
                const isBrokenRow = verificationResult && !verificationResult.valid && verificationResult.broken_at_id === log.id;
                return (
                  <tr key={log.id} style={isBrokenRow ? { background: 'rgba(239, 68, 68, 0.2)' } : {}}>
                    <td style={{ fontWeight: 700 }}>#{log.id}</td>
                    <td style={{ color: 'var(--text-muted)', fontSize: '0.785rem' }}>
                      {new Date(log.timestamp_iso).toLocaleTimeString()}
                    </td>
                    <td>
                      <span style={{ fontWeight: 600 }}>{log.username}</span>
                    </td>
                    <td>
                      <code style={{ fontSize: '0.785rem', color: '#c7d2fe' }}>{log.action}</code>
                    </td>
                    <td>{log.resource}</td>
                    <td>
                      <span className={`badge ${
                        log.status === 'SUCCESS' || log.status === 'SAFE' ? 'badge-safe' :
                        log.status === 'DENIED' || log.status === 'TAMPERED' ? 'badge-tampered' : 'badge-failed'
                      }`}>
                        {log.status}
                      </span>
                    </td>
                    <td>
                      <code style={{ fontSize: '0.725rem', color: '#818cf8' }} title={`Prev: ${log.prev_hash}\nEntry: ${log.entry_hash}`}>
                        {log.entry_hash.slice(0, 12)}...{log.entry_hash.slice(-6)}
                      </code>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
