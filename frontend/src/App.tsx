/* ============================================================
   App — Main routing hub
   ============================================================ */

import React, { Suspense, lazy } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ConfigProvider, theme, Spin } from 'antd';
import AppLayout from '@/components/AppLayout';
import { ErrorBoundary } from '@/components/ErrorBoundary';
import './index.css';

// Lazy-loaded pages
const Dashboard = lazy(() => import('@/pages/Dashboard'));
const AssessmentList = lazy(() => import('@/pages/AssessmentList'));
const AssessmentDetail = lazy(() => import('@/pages/AssessmentDetail'));
const VulnerabilityFindings = lazy(() => import('@/pages/VulnerabilityFindings'));
const ExploitationPanel = lazy(() => import('@/pages/ExploitationPanel'));
const ReportGenerator = lazy(() => import('@/pages/ReportGenerator'));
const Settings = lazy(() => import('@/pages/Settings'));
const AttackSurface = lazy(() => import('@/pages/AttackSurface'));
const ThreatIntelligence = lazy(() => import('@/pages/ThreatIntelligence'));
const ScanComparison = lazy(() => import('@/pages/ScanComparison'));
const About = lazy(() => import('@/pages/About'));

const PageLoader: React.FC = () => (
  <div style={{
    display: 'flex', alignItems: 'center', justifyContent: 'center',
    height: '60vh',
  }}>
    <Spin size="large" />
  </div>
);

const App: React.FC = () => {
  return (
    <ConfigProvider
      theme={{
        algorithm: theme.darkAlgorithm,
        token: {
          colorPrimary: '#00e87b',
          borderRadius: 8,
          fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, sans-serif",
          colorBgContainer: '#1c2333',
          colorBgElevated: '#161b22',
          colorBorder: '#30363d',
          colorText: '#e6edf3',
          colorTextSecondary: '#8b949e',
        },
      }}
    >
      <BrowserRouter>
        <ErrorBoundary>
          <Suspense fallback={<PageLoader />}>
            <Routes>
              <Route element={<AppLayout />}>
                <Route path="/" element={<Dashboard />} />
                <Route path="/assessments" element={<AssessmentList />} />
                <Route path="/assessments/:id" element={<AssessmentDetail />} />
                <Route path="/findings" element={<VulnerabilityFindings />} />
                <Route path="/exploitation" element={<ExploitationPanel />} />
                <Route path="/reports" element={<ReportGenerator />} />
                <Route path="/attack-surface" element={<AttackSurface />} />
                <Route path="/threat-intel" element={<ThreatIntelligence />} />
                <Route path="/scan-compare" element={<ScanComparison />} />
                <Route path="/settings" element={<Settings />} />
                <Route path="/about" element={<About />} />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Route>
            </Routes>
          </Suspense>
        </ErrorBoundary>
      </BrowserRouter>
    </ConfigProvider>
  );
};

export default App;
