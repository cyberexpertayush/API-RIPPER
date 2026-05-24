/* ============================================================
   About — Developer Profile & Open Source Attribution
   API RIPPER created by Ayush Sharma
   ============================================================ */

import React from 'react';
import { Tag, Tooltip } from 'antd';
import {
  UserOutlined, GithubOutlined, LinkedinOutlined,
  CodeOutlined, SafetyCertificateOutlined, ThunderboltOutlined,
  GlobalOutlined, HeartOutlined, CrownOutlined, StarOutlined,
} from '@ant-design/icons';

const About: React.FC = () => {
  return (
    <div className="fade-in">
      <div className="page-header" style={{ textAlign: 'center', marginBottom: 'var(--space-8)' }}>
        <h1><CrownOutlined style={{ marginRight: 8 }} />About API RIPPER</h1>
        <p>Open-source advanced API security scanner framework</p>
      </div>

      {/* ── Developer Profile Card ──────────────────────────── */}
      <div style={{ maxWidth: 720, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 'var(--space-6)' }}>

        <div className="card" style={{
          position: 'relative',
          overflow: 'hidden',
          padding: 'var(--space-8)',
          textAlign: 'center',
          background: 'linear-gradient(135deg, rgba(0, 232, 123, 0.06), rgba(59, 130, 246, 0.06))',
          border: '1px solid rgba(0, 232, 123, 0.2)',
        }}>
          {/* Background decoration */}
          <div style={{
            position: 'absolute', top: -40, right: -40,
            width: 200, height: 200, borderRadius: '50%',
            background: 'radial-gradient(circle, rgba(0,232,123,0.08), transparent)',
            pointerEvents: 'none',
          }} />

          {/* Avatar */}
          <div style={{
            width: 100, height: 100, borderRadius: '50%',
            background: 'linear-gradient(135deg, #00e87b, #3b82f6)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            margin: '0 auto var(--space-4)',
            fontSize: 42, fontWeight: 900, color: '#06080f',
            boxShadow: '0 0 30px rgba(0, 232, 123, 0.3)',
          }}>
            AS
          </div>

          <h2 style={{
            fontSize: 'var(--text-2xl)', fontWeight: 800,
            background: 'linear-gradient(135deg, #00e87b, #3b82f6)',
            WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
            backgroundClip: 'text',
            marginBottom: 'var(--space-1)',
          }}>
            Ayush Sharma
          </h2>

          <p style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-sm)', marginBottom: 'var(--space-4)' }}>
            Creator & Lead Developer of API RIPPER
          </p>

          <div style={{ display: 'flex', gap: 'var(--space-2)', justifyContent: 'center', flexWrap: 'wrap', marginBottom: 'var(--space-5)' }}>
            <Tag color="#00e87b" style={{ borderRadius: 12, padding: '2px 12px', fontWeight: 600 }}>
              <SafetyCertificateOutlined /> Security Researcher
            </Tag>
            <Tag color="#3b82f6" style={{ borderRadius: 12, padding: '2px 12px', fontWeight: 600 }}>
              <CodeOutlined /> Full-Stack Developer
            </Tag>
            <Tag color="#a855f7" style={{ borderRadius: 12, padding: '2px 12px', fontWeight: 600 }}>
              <ThunderboltOutlined /> Penetration Tester
            </Tag>
          </div>

          {/* Social Links */}
          <div style={{ display: 'flex', gap: 'var(--space-3)', justifyContent: 'center' }}>
            <a
              href="https://github.com/cyberexpertayush"
              target="_blank"
              rel="noopener noreferrer"
              style={{
                display: 'flex', alignItems: 'center', gap: 6,
                padding: '8px 20px', borderRadius: 'var(--radius-sm)',
                background: 'var(--bg-surface)', border: '1px solid var(--border-subtle)',
                color: 'var(--text-primary)', fontWeight: 600, fontSize: 'var(--text-sm)',
                transition: 'all 200ms', textDecoration: 'none',
              }}
              onMouseOver={(e) => { e.currentTarget.style.borderColor = '#00e87b'; e.currentTarget.style.boxShadow = '0 0 12px rgba(0,232,123,0.15)'; }}
              onMouseOut={(e) => { e.currentTarget.style.borderColor = 'var(--border-subtle)'; e.currentTarget.style.boxShadow = 'none'; }}
            >
              <GithubOutlined style={{ fontSize: 18 }} /> GitHub
            </a>
            <a
              href="https://linkedin.com/in/hackwithayush"
              target="_blank"
              rel="noopener noreferrer"
              style={{
                display: 'flex', alignItems: 'center', gap: 6,
                padding: '8px 20px', borderRadius: 'var(--radius-sm)',
                background: 'var(--bg-surface)', border: '1px solid var(--border-subtle)',
                color: 'var(--text-primary)', fontWeight: 600, fontSize: 'var(--text-sm)',
                transition: 'all 200ms', textDecoration: 'none',
              }}
              onMouseOver={(e) => { e.currentTarget.style.borderColor = '#3b82f6'; e.currentTarget.style.boxShadow = '0 0 12px rgba(59,130,246,0.15)'; }}
              onMouseOut={(e) => { e.currentTarget.style.borderColor = 'var(--border-subtle)'; e.currentTarget.style.boxShadow = 'none'; }}
            >
              <LinkedinOutlined style={{ fontSize: 18 }} /> LinkedIn
            </a>
            <a
              href="#"
              target="_blank"
              rel="noopener noreferrer"
              style={{
                display: 'flex', alignItems: 'center', gap: 6,
                padding: '8px 20px', borderRadius: 'var(--radius-sm)',
                background: 'var(--bg-surface)', border: '1px solid var(--border-subtle)',
                color: 'var(--text-primary)', fontWeight: 600, fontSize: 'var(--text-sm)',
                transition: 'all 200ms', textDecoration: 'none',
              }}
              onMouseOver={(e) => { e.currentTarget.style.borderColor = '#a855f7'; e.currentTarget.style.boxShadow = '0 0 12px rgba(168,85,247,0.15)'; }}
              onMouseOut={(e) => { e.currentTarget.style.borderColor = 'var(--border-subtle)'; e.currentTarget.style.boxShadow = 'none'; }}
            >
              <GlobalOutlined style={{ fontSize: 18 }} /> Portfolio
            </a>
          </div>
        </div>

        {/* ── Project Information ───────────────────────────── */}
        <div className="card">
          <h3 className="section-title"><StarOutlined /> Project</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
            <div style={{ display: 'flex', gap: 'var(--space-4)' }}>
              <div style={{
                width: 56, height: 56, borderRadius: 'var(--radius-md)',
                background: 'linear-gradient(135deg, #00e87b, #3b82f6)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontSize: 28, fontWeight: 900, color: '#06080f', flexShrink: 0,
              }}>R</div>
              <div>
                <div style={{ fontSize: 'var(--text-lg)', fontWeight: 700 }}>API RIPPER v4.0</div>
                <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', marginTop: 2 }}>
                  Advanced Autonomous API Security Scanner
                </div>
              </div>
            </div>
            <p style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-sm)', lineHeight: 1.8 }}>
              API RIPPER is a next-generation API security testing framework that combines multi-agent
              autonomous scanning with advanced exploitation capabilities. Featuring {13}+ security
              modules, {70}+ testing techniques, and real-time vulnerability detection powered by
              a knowledge graph-driven inference engine.
            </p>
          </div>
        </div>

        {/* ── Tech Stack ───────────────────────────────────── */}
        <div className="card">
          <h3 className="section-title"><CodeOutlined /> Technology Stack</h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-4)' }}>
            <div>
              <div style={{ fontSize: 'var(--text-xs)', fontWeight: 700, color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 'var(--space-2)' }}>
                Frontend
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-1)' }}>
                {['React 19 + TypeScript', 'Vite 6 (Build)', 'Zustand (State)', 'Ant Design 5 (UI)', 'D3.js (Visualization)', 'Axios (HTTP)'].map((tech) => (
                  <div key={tech} style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span style={{ width: 4, height: 4, borderRadius: '50%', background: '#3b82f6' }} />
                    {tech}
                  </div>
                ))}
              </div>
            </div>
            <div>
              <div style={{ fontSize: 'var(--text-xs)', fontWeight: 700, color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 'var(--space-2)' }}>
                Backend
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-1)' }}>
                {['Python 3.11+ / FastAPI', 'SQLAlchemy + SQLite', 'Multi-Agent Pipeline', 'WebSocket (Real-time)', 'ARSec Engine v4.0', 'Knowledge Graph'].map((tech) => (
                  <div key={tech} style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span style={{ width: 4, height: 4, borderRadius: '50%', background: '#00e87b' }} />
                    {tech}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* ── Open Source License ───────────────────────────── */}
        <div className="card" style={{
          background: 'linear-gradient(135deg, rgba(168, 85, 247, 0.06), rgba(0, 232, 123, 0.04))',
          border: '1px solid rgba(168, 85, 247, 0.2)',
        }}>
          <h3 className="section-title"><HeartOutlined /> Open Source</h3>
          <p style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-sm)', lineHeight: 1.8, marginBottom: 'var(--space-4)' }}>
            API RIPPER is open-source software created by <strong style={{ color: 'var(--accent-primary)' }}>Ayush Sharma</strong>.
            You are free to use, modify, and distribute this project under the following conditions:
          </p>
          <div style={{
            background: 'var(--bg-surface)', borderRadius: 'var(--radius-sm)',
            padding: 'var(--space-4)', border: '1px solid var(--border-subtle)',
            fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)',
            lineHeight: 2, color: 'var(--text-secondary)',
          }}>
            <div style={{ color: 'var(--accent-primary)', fontWeight: 700, marginBottom: 8 }}>Attribution Requirements:</div>
            <div>• Original author credit: <strong style={{ color: 'var(--text-primary)' }}>Ayush Sharma</strong> must be retained</div>
            <div>• The "Developed by Ayush Sharma" watermark must not be removed</div>
            <div>• This About page must remain intact in all distributions</div>
            <div>• Derivative works must acknowledge the original project</div>
            <div>• Commercial use requires maintaining attribution</div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default About;
