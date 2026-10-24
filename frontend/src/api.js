const API_BASE = '/api';

function getAuthHeaders() {
  const token = localStorage.getItem('securedb_token');
  return {
    'Content-Type': 'application/json',
    ...(token ? { 'Authorization': `Bearer ${token}` } : {})
  };
}

async function request(endpoint, options = {}) {
  const headers = { ...getAuthHeaders(), ...options.headers };
  const res = await fetch(`${API_BASE}${endpoint}`, { ...options, headers });
  
  if (res.status === 401 && !endpoint.includes('/auth/login') && !endpoint.includes('/auth/register')) {
    localStorage.removeItem('securedb_token');
    localStorage.removeItem('securedb_user');
    window.location.reload();
  }
  
  const data = await res.json().catch(() => null);
  if (!res.ok) {
    const errorMsg = data?.detail || `Request failed with status ${res.status}`;
    throw new Error(errorMsg);
  }
  return data;
}

export const api = {
  // Auth
  login: (username, password) => request('/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) }),
  register: (username, password) => request('/auth/register', { method: 'POST', body: JSON.stringify({ username, password }) }),
  logout: () => request('/auth/logout', { method: 'POST' }),
  getMe: () => request('/auth/me'),

  // Dashboard
  getStats: () => request('/dashboard/statistics'),
  getCharts: () => request('/dashboard/charts'),

  // Security Alerts
  getAlerts: (status) => request(`/security-alerts${status ? `?status_filter=${status}` : ''}`),
  resolveAlert: (id) => request(`/security-alerts/${id}/resolve`, { method: 'POST' }),

  // Databases
  getDatabases: () => request('/databases'),
  createDatabase: (dbData) => request('/databases', { method: 'POST', body: JSON.stringify(dbData) }),
  deleteDatabase: (id) => request(`/databases/${id}`, { method: 'DELETE' }),
  testConnection: (data) => request('/databases/test-connection', { method: 'POST', body: JSON.stringify(data) }),

  // Backups
  getBackups: () => request('/backups'),
  createBackup: (target_db_id) => request('/backups/create', { method: 'POST', body: JSON.stringify({ target_db_id }) }),
  verifyBackup: (id, deep = false) => request(`/backups/${id}/verify?deep=${deep}`, { method: 'POST' }),
  restoreBackup: (id, target_database_name, confirm_password) => 
    request(`/backups/${id}/restore`, { method: 'POST', body: JSON.stringify({ target_database_name, confirm_password }) }),
  deleteBackup: (id) => request(`/backups/${id}`, { method: 'DELETE' }),

  // Schedules
  getSchedules: () => request('/schedules'),
  createSchedule: (data) => request('/schedules', { method: 'POST', body: JSON.stringify(data) }),
  deleteSchedule: (id) => request(`/schedules/${id}`, { method: 'DELETE' }),

  // Audit Logs
  getLogs: () => request('/logs?limit=100'),
  verifyLogsChain: () => request('/logs/verify-chain')
};
