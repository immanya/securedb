import React, { createContext, useContext, useState, useEffect } from 'react';
import { api } from '../api';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    const saved = localStorage.getItem('securedb_user');
    return saved ? JSON.parse(saved) : null;
  });
  const [token, setToken] = useState(() => localStorage.getItem('securedb_token'));
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (token) {
      api.getMe()
        .then((userData) => {
          setUser(userData);
          localStorage.setItem('securedb_user', JSON.stringify(userData));
        })
        .catch(() => {
          logout();
        })
        .finally(() => setLoading(false));
    } else {
      setLoading(false);
    }
  }, [token]);

  const login = async (username, password) => {
    const data = await api.login(username, password);
    setToken(data.access_token);
    setUser(data.user);
    localStorage.setItem('securedb_token', data.access_token);
    localStorage.setItem('securedb_user', JSON.stringify(data.user));
    return data;
  };

  const register = async (username, password) => {
    const data = await api.register(username, password);
    // Automatically log in after registration
    return login(username, password);
  };

  const logout = async () => {
    try {
      await api.logout();
    } catch (e) {
      // Ignore error on logout
    }
    setUser(null);
    setToken(null);
    localStorage.removeItem('securedb_token');
    localStorage.removeItem('securedb_user');
  };

  return (
    <AuthContext.Provider value={{ user, token, login, register, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
