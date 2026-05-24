/* ============================================================
   App Layout — Shell wrapping all pages
   Includes persistent "Developed by Ayush Sharma" watermark
   ============================================================ */

import React from 'react';
import { Outlet, Link } from 'react-router-dom';
import Sidebar from './Sidebar';
import Header from './Header';
import { useUIStore } from '@/store';

const AppLayout: React.FC = () => {
  const sidebarCollapsed = useUIStore((s) => s.sidebarCollapsed);

  return (
    <div className={`app-layout ${sidebarCollapsed ? 'sidebar-collapsed' : ''}`}>
      <Sidebar />
      <main className="app-main">
        <Header />
        <div className="app-content fade-in">
          <Outlet />
        </div>
        {/* Persistent attribution watermark */}
        <footer className="app-watermark">
          <span>
            Developed by{' '}
            <Link to="/about" className="watermark-link">Ayush Sharma</Link>
          </span>
          <span className="watermark-separator">·</span>
          <span>API RIPPER v4.0</span>
        </footer>
      </main>
    </div>
  );
};

export default AppLayout;
