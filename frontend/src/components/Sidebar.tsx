/* ============================================================
   Sidebar Component
   ============================================================ */

import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  DashboardOutlined,
  AimOutlined,
  BugOutlined,
  ThunderboltOutlined,
  FileTextOutlined,
  SettingOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  ApiOutlined,
  RadarChartOutlined,
  SwapOutlined,
  UserOutlined,
} from '@ant-design/icons';
import { useUIStore } from '@/store';

const navSections = [
  {
    label: 'Overview',
    items: [
      { path: '/', icon: <DashboardOutlined />, label: 'Dashboard' },
      { path: '/assessments', icon: <AimOutlined />, label: 'Scans' },
      { path: '/threat-intel', icon: <RadarChartOutlined />, label: 'Threat Intel' },
    ],
  },
  {
    label: 'Analysis',
    items: [
      { path: '/findings', icon: <BugOutlined />, label: 'Findings' },
      { path: '/exploitation', icon: <ThunderboltOutlined />, label: 'Exploitation' },
      { path: '/attack-surface', icon: <ApiOutlined />, label: 'Attack Surface' },
      { path: '/scan-compare', icon: <SwapOutlined />, label: 'Scan Compare' },
    ],
  },
  {
    label: 'Output',
    items: [
      { path: '/reports', icon: <FileTextOutlined />, label: 'Reports' },
      { path: '/settings', icon: <SettingOutlined />, label: 'Settings' },
      { path: '/about', icon: <UserOutlined />, label: 'About' },
    ],
  },
];

const Sidebar: React.FC = () => {
  const { sidebarCollapsed, toggleSidebar } = useUIStore();

  return (
    <aside className={`app-sidebar ${sidebarCollapsed ? 'collapsed' : ''}`}>
      {/* Logo */}
      <div className="sidebar-logo">
        <div className="logo-icon" style={{ background: 'linear-gradient(135deg, #00e87b, #3b82f6)', color: '#0d1117', fontWeight: 900 }}>R</div>
        {!sidebarCollapsed && (
          <div>
            <div className="logo-text">API RIPPER</div>
            <div className="logo-sub">Security Scanner</div>
          </div>
        )}
      </div>

      {/* Navigation */}
      <nav className="sidebar-nav">
        {navSections.map((section) => (
          <div key={section.label}>
            {!sidebarCollapsed && (
              <div className="sidebar-section-label">{section.label}</div>
            )}
            {section.items.map((item) => (
              <NavLink
                key={item.path}
                to={item.path}
                end={item.path === '/'}
                className={({ isActive }) =>
                  `sidebar-item ${isActive ? 'active' : ''}`
                }
                title={sidebarCollapsed ? item.label : undefined}
              >
                <span className="item-icon">{item.icon}</span>
                {!sidebarCollapsed && <span>{item.label}</span>}
              </NavLink>
            ))}
          </div>
        ))}
      </nav>

      {/* Collapse toggle */}
      <div
        className="sidebar-item"
        onClick={toggleSidebar}
        style={{ margin: '0 8px 12px', cursor: 'pointer' }}
      >
        <span className="item-icon">
          {sidebarCollapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />}
        </span>
        {!sidebarCollapsed && <span>Collapse</span>}
      </div>
    </aside>
  );
};

export default Sidebar;
