/* ============================================================
   Header Component — API RIPPER
   ============================================================ */

import React, { useEffect, useState, useRef } from 'react';

const Header: React.FC = () => {
  const [backendOnline, setBackendOnline] = useState(false);
  const [wsOnline, setWsOnline] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  // Health check polling
  useEffect(() => {
    const check = async () => {
      try {
        const res = await fetch('/health', { signal: AbortSignal.timeout(3000) });
        setBackendOnline(res.ok);
      } catch {
        setBackendOnline(false);
      }
    };
    check();
    const interval = setInterval(check, 15000);
    return () => clearInterval(interval);
  }, []);

  // WebSocket status check — connect to /ws/live to verify WS is working
  useEffect(() => {
    const connectWs = () => {
      try {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const ws = new WebSocket(`${protocol}//${window.location.host}/ws/status`);
        wsRef.current = ws;

        ws.onopen = () => setWsOnline(true);
        ws.onclose = () => {
          setWsOnline(false);
          // Reconnect after 5s
          setTimeout(connectWs, 5000);
        };
        ws.onerror = () => setWsOnline(false);
      } catch {
        setWsOnline(false);
      }
    };

    connectWs();

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  // Ping to keep alive
  useEffect(() => {
    const interval = setInterval(() => {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send('ping');
      }
    }, 25000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header className="app-header">
      <div style={{ flex: 1 }}>
        <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
          API RIPPER — Advanced API Security Scanner
        </span>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-4)' }}>
        {/* Backend Status */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          fontSize: 'var(--text-xs)',
          color: backendOnline ? 'var(--status-completed)' : 'var(--text-tertiary)',
        }}>
          <span style={{
            width: 8, height: 8, borderRadius: '50%',
            background: backendOnline ? 'var(--status-completed)' : '#ff4757',
          }} />
          {backendOnline ? 'Backend Online' : 'Backend Offline'}
        </div>
        {/* WebSocket Status */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          fontSize: 'var(--text-xs)',
          color: wsOnline ? 'var(--status-completed)' : 'var(--text-tertiary)',
        }}>
          <span style={{
            width: 8, height: 8, borderRadius: '50%',
            background: wsOnline ? 'var(--status-completed)' : 'var(--text-tertiary)',
          }} />
          {wsOnline ? 'Live' : 'WS Offline'}
        </div>
        {/* Version */}
        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)' }}>
          v4.0.0
        </span>
      </div>
    </header>
  );
};

export default Header;
