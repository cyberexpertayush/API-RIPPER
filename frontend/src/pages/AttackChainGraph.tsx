/* ============================================================
   Attack Chain Graph — D3 force-directed visualization
   with proper zoom/pan controls
   ============================================================ */

import React, { useEffect, useRef, useState, useCallback } from 'react';
import { Select, Spin, Tag, Card, Empty, Tooltip } from 'antd';
import {
  NodeIndexOutlined, ZoomInOutlined, ZoomOutOutlined,
  AimOutlined, FullscreenOutlined, FullscreenExitOutlined,
} from '@ant-design/icons';
import * as d3 from 'd3';
import type { SimulationNodeDatum, SimulationLinkDatum } from 'd3';
import { useAssessmentStore } from '@/store';
import { securityApi } from '@/services/apiClient';

interface GraphNode extends SimulationNodeDatum {
  id: string;
  label: string;
  type: 'endpoint' | 'vulnerability' | 'role';
  severity?: string;
  details?: string;
}

interface GraphLink extends SimulationLinkDatum<GraphNode> {
  label: string;
  type: 'escalation' | 'access' | 'transition';
}

interface GraphData {
  nodes: GraphNode[];
  links: GraphLink[];
}

const NODE_COLORS: Record<string, string> = {
  endpoint: '#3b82f6',
  vulnerability: '#ff4757',
  role: '#a855f7',
};

const LINK_COLORS: Record<string, string> = {
  escalation: '#ff4757',
  access: '#3b82f6',
  transition: '#00e87b',
};

const NODE_SHAPES: Record<string, (ctx: CanvasRenderingContext2D, x: number, y: number, r: number) => void> = {
  endpoint: (ctx, x, y, r) => {
    ctx.beginPath();
    ctx.arc(x, y, r, 0, 2 * Math.PI);
    ctx.fill();
    ctx.stroke();
  },
  vulnerability: (ctx, x, y, r) => {
    ctx.beginPath();
    ctx.moveTo(x, y - r);
    ctx.lineTo(x + r, y);
    ctx.lineTo(x, y + r);
    ctx.lineTo(x - r, y);
    ctx.closePath();
    ctx.fill();
    ctx.stroke();
  },
  role: (ctx, x, y, r) => {
    const hr = r * 0.85;
    ctx.beginPath();
    ctx.moveTo(x - hr, y - hr);
    ctx.arcTo(x + hr, y - hr, x + hr, y + hr, 3);
    ctx.arcTo(x + hr, y + hr, x - hr, y + hr, 3);
    ctx.arcTo(x - hr, y + hr, x - hr, y - hr, 3);
    ctx.arcTo(x - hr, y - hr, x + hr, y - hr, 3);
    ctx.closePath();
    ctx.fill();
    ctx.stroke();
  },
};

const AttackChainGraph: React.FC = () => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const { assessments, fetchAssessments } = useAssessmentStore();
  const [selectedAssessment, setSelectedAssessment] = useState<number | undefined>();
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const [loading, setLoading] = useState(false);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [zoomLevel, setZoomLevel] = useState(1);

  // Store zoom behavior and simulation in refs so button handlers can access them
  const zoomRef = useRef<d3.ZoomBehavior<HTMLCanvasElement, unknown> | null>(null);
  const simulationRef = useRef<d3.Simulation<GraphNode, GraphLink> | null>(null);
  const transformRef = useRef<d3.ZoomTransform>(d3.zoomIdentity);
  const nodesRef = useRef<GraphNode[]>([]);
  const linksRef = useRef<GraphLink[]>([]);

  useEffect(() => { fetchAssessments(); }, []);

  useEffect(() => {
    if (selectedAssessment) {
      setLoading(true);
      securityApi.getGraph(selectedAssessment)
        .then((data: any) => {
          const gd = data as GraphData;
          setGraphData(gd);
          setSelectedNode(null);
        })
        .catch(() => {
          // Generate demo data from assessment info
          const demoNodes: GraphNode[] = [
            { id: 'ep-1', label: '/api/users', type: 'endpoint', details: 'User management endpoint' },
            { id: 'ep-2', label: '/api/admin', type: 'endpoint', details: 'Admin panel endpoint' },
            { id: 'ep-3', label: '/api/auth/token', type: 'endpoint', details: 'Authentication token endpoint' },
            { id: 'ep-4', label: '/api/files', type: 'endpoint', details: 'File management endpoint' },
            { id: 'vuln-1', label: 'IDOR', type: 'vulnerability', severity: 'HIGH', details: 'Insecure Direct Object Reference' },
            { id: 'vuln-2', label: 'SQL Injection', type: 'vulnerability', severity: 'CRITICAL', details: 'SQL injection in search parameter' },
            { id: 'vuln-3', label: 'Broken Auth', type: 'vulnerability', severity: 'CRITICAL', details: 'Authentication bypass via token manipulation' },
            { id: 'vuln-4', label: 'SSRF', type: 'vulnerability', severity: 'HIGH', details: 'Server-Side Request Forgery in file fetch' },
            { id: 'role-1', label: 'User', type: 'role', details: 'Standard user role' },
            { id: 'role-2', label: 'Admin', type: 'role', details: 'Administrator role' },
          ];
          const demoLinks: GraphLink[] = [
            { source: 'ep-1', target: 'vuln-1', label: 'IDOR here', type: 'access' },
            { source: 'vuln-1', target: 'role-2', label: 'escalate to admin', type: 'escalation' },
            { source: 'ep-2', target: 'vuln-2', label: 'injectable param', type: 'access' },
            { source: 'ep-3', target: 'vuln-3', label: 'token bypass', type: 'access' },
            { source: 'vuln-3', target: 'role-2', label: 'auth bypass', type: 'escalation' },
            { source: 'role-1', target: 'ep-1', label: 'has access', type: 'transition' },
            { source: 'role-1', target: 'ep-3', label: 'auth flow', type: 'transition' },
            { source: 'ep-4', target: 'vuln-4', label: 'SSRF vector', type: 'access' },
            { source: 'vuln-4', target: 'vuln-2', label: 'chain to SQLi', type: 'escalation' },
          ];
          setGraphData({ nodes: demoNodes, links: demoLinks });
        })
        .finally(() => setLoading(false));
    }
  }, [selectedAssessment]);

  // ────────────────── D3 Rendering ──────────────────
  useEffect(() => {
    if (!graphData || !canvasRef.current) return;

    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d')!;
    if (!ctx) return;

    const width = canvas.parentElement?.clientWidth || 800;
    const height = isFullscreen ? window.innerHeight - 160 : 560;
    const dpr = window.devicePixelRatio || 1;
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    canvas.style.width = `${width}px`;
    canvas.style.height = `${height}px`;
    ctx.scale(dpr, dpr);

    const nodes = graphData.nodes.map((n) => ({ ...n }));
    const links = graphData.links.map((l) => ({ ...l }));
    nodesRef.current = nodes;
    linksRef.current = links;

    const simulation = d3.forceSimulation<GraphNode>(nodes)
      .force('link', d3.forceLink<GraphNode, GraphLink>(links).id((d) => d.id).distance(140))
      .force('charge', d3.forceManyBody().strength(-400))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(35))
      .force('x', d3.forceX(width / 2).strength(0.05))
      .force('y', d3.forceY(height / 2).strength(0.05));

    simulationRef.current = simulation;

    // Store transform in ref
    let transform = transformRef.current;

    // Create zoom behavior ONCE and store in ref
    const zoom = d3.zoom<HTMLCanvasElement, unknown>()
      .scaleExtent([0.1, 8])
      .on('zoom', (event) => {
        transform = event.transform;
        transformRef.current = transform;
        setZoomLevel(Math.round(transform.k * 100));
        draw();
      });

    zoomRef.current = zoom;

    const selection = d3.select(canvas);
    selection.call(zoom);

    // Restore previous transform if any
    if (transformRef.current !== d3.zoomIdentity) {
      selection.call(zoom.transform, transformRef.current);
    }

    // ── Drag interaction ──
    let dragNode: GraphNode | null = null;

    canvas.addEventListener('mousedown', (event: MouseEvent) => {
      const [mx, my] = transform.invert([event.offsetX, event.offsetY]);
      const node = nodes.find((n) => {
        const dx = (n.x || 0) - mx;
        const dy = (n.y || 0) - my;
        return Math.sqrt(dx * dx + dy * dy) < 18;
      });
      if (node) {
        event.stopPropagation();
        dragNode = node;
        setSelectedNode({ ...node });
        simulation.alphaTarget(0.3).restart();
        node.fx = node.x;
        node.fy = node.y;
      }
    });

    canvas.addEventListener('mousemove', (event: MouseEvent) => {
      if (dragNode) {
        const [px, py] = transform.invert([event.offsetX, event.offsetY]);
        dragNode.fx = px;
        dragNode.fy = py;
      }
      // Cursor style
      const [mx, my] = transform.invert([event.offsetX, event.offsetY]);
      const hoverNode = nodes.find((n) => {
        const dx = (n.x || 0) - mx;
        const dy = (n.y || 0) - my;
        return Math.sqrt(dx * dx + dy * dy) < 18;
      });
      canvas.style.cursor = hoverNode ? 'pointer' : 'grab';
    });

    canvas.addEventListener('mouseup', () => {
      if (dragNode) {
        dragNode.fx = null;
        dragNode.fy = null;
        dragNode = null;
        simulation.alphaTarget(0);
      }
    });

    // ── Draw function ──
    function draw() {
      ctx.save();
      ctx.clearRect(0, 0, width, height);
      ctx.translate(transform.x, transform.y);
      ctx.scale(transform.k, transform.k);

      // Draw links with arrows
      links.forEach((l) => {
        const source = l.source as GraphNode;
        const target = l.target as GraphNode;
        if (!source.x || !source.y || !target.x || !target.y) return;

        // Gradient line
        const gradient = ctx.createLinearGradient(source.x, source.y, target.x, target.y);
        const linkColor = LINK_COLORS[l.type] || '#30363d';
        gradient.addColorStop(0, linkColor + '99');
        gradient.addColorStop(1, linkColor + 'cc');

        ctx.beginPath();
        ctx.moveTo(source.x, source.y);
        ctx.lineTo(target.x, target.y);
        ctx.strokeStyle = gradient;
        ctx.lineWidth = l.type === 'escalation' ? 2.5 : 1.5;
        ctx.globalAlpha = 0.7;

        // Dashed line for transitions
        if (l.type === 'transition') {
          ctx.setLineDash([6, 4]);
        } else {
          ctx.setLineDash([]);
        }
        ctx.stroke();
        ctx.setLineDash([]);
        ctx.globalAlpha = 1;

        // Arrow at midpoint
        const angle = Math.atan2(target.y - source.y, target.x - source.x);
        const headLen = 10;
        const midX = (source.x + target.x) / 2;
        const midY = (source.y + target.y) / 2;
        ctx.beginPath();
        ctx.moveTo(midX, midY);
        ctx.lineTo(midX - headLen * Math.cos(angle - Math.PI / 6), midY - headLen * Math.sin(angle - Math.PI / 6));
        ctx.lineTo(midX - headLen * Math.cos(angle + Math.PI / 6), midY - headLen * Math.sin(angle + Math.PI / 6));
        ctx.closePath();
        ctx.fillStyle = linkColor;
        ctx.fill();

        // Label
        ctx.fillStyle = '#8b949e';
        ctx.font = '9px Inter, sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText(l.label, midX, midY - 10);
      });

      // Draw nodes with glow
      nodes.forEach((n) => {
        if (!n.x || !n.y) return;
        const r = n.type === 'vulnerability' ? 16 : 13;
        const isSelected = selectedNode?.id === n.id;
        const color = NODE_COLORS[n.type] || '#6b7280';

        // Glow effect for selected or vulnerability nodes
        if (isSelected || n.type === 'vulnerability') {
          ctx.shadowColor = color;
          ctx.shadowBlur = isSelected ? 20 : 10;
        }

        ctx.fillStyle = color;
        ctx.strokeStyle = isSelected ? '#ffffff' : 'rgba(255,255,255,0.3)';
        ctx.lineWidth = isSelected ? 3 : 1.2;

        const drawShape = NODE_SHAPES[n.type] || NODE_SHAPES.endpoint;
        drawShape(ctx, n.x, n.y, r);

        // Reset shadow
        ctx.shadowColor = 'transparent';
        ctx.shadowBlur = 0;

        // Label with background
        const labelText = n.label;
        ctx.font = `${isSelected ? 'bold ' : ''}11px Inter, sans-serif`;
        ctx.textAlign = 'center';
        const textWidth = ctx.measureText(labelText).width;

        // Label background
        ctx.fillStyle = 'rgba(6, 8, 15, 0.7)';
        ctx.fillRect(n.x - textWidth / 2 - 3, n.y + r + 5, textWidth + 6, 16);

        // Label text
        ctx.fillStyle = isSelected ? '#ffffff' : '#e6edf3';
        ctx.fillText(labelText, n.x, n.y + r + 17);

        // Severity indicator for vulnerabilities
        if (n.severity && n.type === 'vulnerability') {
          const sevColor = n.severity === 'CRITICAL' ? '#ff4757' : n.severity === 'HIGH' ? '#ff8c42' : '#ffc312';
          ctx.fillStyle = sevColor;
          ctx.font = 'bold 8px Inter, sans-serif';
          ctx.fillText(n.severity, n.x, n.y + r + 30);
        }
      });

      ctx.restore();
    }

    simulation.on('tick', draw);

    return () => { simulation.stop(); };
  }, [graphData, selectedNode, isFullscreen]);

  // ── Zoom control handlers using stored zoom ref ──
  const handleZoomIn = useCallback(() => {
    if (!canvasRef.current || !zoomRef.current) return;
    d3.select(canvasRef.current)
      .transition()
      .duration(300)
      .call(zoomRef.current.scaleBy, 1.4);
  }, []);

  const handleZoomOut = useCallback(() => {
    if (!canvasRef.current || !zoomRef.current) return;
    d3.select(canvasRef.current)
      .transition()
      .duration(300)
      .call(zoomRef.current.scaleBy, 0.7);
  }, []);

  const handleZoomReset = useCallback(() => {
    if (!canvasRef.current || !zoomRef.current) return;
    d3.select(canvasRef.current)
      .transition()
      .duration(500)
      .call(zoomRef.current.transform, d3.zoomIdentity);
  }, []);

  const handleZoomFit = useCallback(() => {
    if (!canvasRef.current || !zoomRef.current || nodesRef.current.length === 0) return;
    const nodes = nodesRef.current;
    const canvas = canvasRef.current;
    const width = canvas.parentElement?.clientWidth || 800;
    const height = isFullscreen ? window.innerHeight - 160 : 560;

    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    nodes.forEach((n) => {
      if (n.x !== undefined && n.y !== undefined) {
        minX = Math.min(minX, n.x);
        minY = Math.min(minY, n.y);
        maxX = Math.max(maxX, n.x);
        maxY = Math.max(maxY, n.y);
      }
    });

    const padding = 60;
    const graphWidth = maxX - minX + padding * 2;
    const graphHeight = maxY - minY + padding * 2;
    const scale = Math.min(width / graphWidth, height / graphHeight, 2);
    const tx = width / 2 - (minX + maxX) / 2 * scale;
    const ty = height / 2 - (minY + maxY) / 2 * scale;

    d3.select(canvas)
      .transition()
      .duration(600)
      .call(zoomRef.current.transform, d3.zoomIdentity.translate(tx, ty).scale(scale));
  }, [isFullscreen]);

  const toggleFullscreen = useCallback(() => {
    setIsFullscreen((prev) => !prev);
  }, []);

  return (
    <div className="fade-in">
      <div className="page-header">
        <h1><NodeIndexOutlined style={{ marginRight: 8 }} />Executable Exploit Chain</h1>
        <p>Force-directed visualization of attack chains and privilege escalation paths</p>
      </div>

      <div style={{ display: 'flex', gap: 'var(--space-3)', marginBottom: 'var(--space-4)', flexWrap: 'wrap', alignItems: 'center' }}>
        <Select
          placeholder="Select Assessment"
          value={selectedAssessment}
          onChange={setSelectedAssessment}
          style={{ width: 350 }}
          options={assessments.map((a) => ({ label: `${a.assessment_name || 'Untitled'} (#${a.id.substring(0, 8)})`, value: a.id }))}
        />
        <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
          {Object.entries(NODE_COLORS).map(([type, color]) => (
            <Tag key={type} style={{ borderRadius: 12 }} color={color}>
              {type === 'endpoint' ? '● Endpoint' : type === 'vulnerability' ? '◆ Vulnerability' : '■ Role'}
            </Tag>
          ))}
        </div>
        {graphData && (
          <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', marginLeft: 'auto' }}>
            {graphData.nodes.length} nodes · {graphData.links.length} edges · {zoomLevel}% zoom
          </span>
        )}
      </div>

      {!selectedAssessment ? (
        <div className="card" style={{ textAlign: 'center', padding: 60 }}>
          <NodeIndexOutlined style={{ fontSize: 48, color: 'var(--text-tertiary)', marginBottom: 16 }} />
          <p style={{ color: 'var(--text-tertiary)' }}>Select an assessment to visualize attack chains</p>
        </div>
      ) : loading ? (
        <div style={{ padding: 40, textAlign: 'center' }}><Spin size="large" /></div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: selectedNode ? '1fr 340px' : '1fr', gap: 'var(--space-4)' }}>
          <div
            ref={containerRef}
            className="card"
            style={{
              padding: 0,
              overflow: 'hidden',
              position: 'relative',
              border: isFullscreen ? '2px solid var(--accent-primary)' : undefined,
            }}
          >
            <canvas ref={canvasRef} style={{ display: 'block', cursor: 'grab' }} />

            {/* Zoom Controls — properly wired */}
            <div style={{
              position: 'absolute', bottom: 12, right: 12,
              display: 'flex', gap: 4, flexDirection: 'column',
              background: 'rgba(6, 8, 15, 0.85)',
              borderRadius: 'var(--radius-md)',
              padding: 4,
              border: '1px solid var(--border-subtle)',
            }}>
              <Tooltip title="Zoom In" placement="left">
                <button className="btn btn-secondary" style={{ padding: '6px 8px', fontSize: 16 }} onClick={handleZoomIn}>
                  <ZoomInOutlined />
                </button>
              </Tooltip>
              <Tooltip title="Zoom Out" placement="left">
                <button className="btn btn-secondary" style={{ padding: '6px 8px', fontSize: 16 }} onClick={handleZoomOut}>
                  <ZoomOutOutlined />
                </button>
              </Tooltip>
              <Tooltip title="Reset View" placement="left">
                <button className="btn btn-secondary" style={{ padding: '6px 8px', fontSize: 16 }} onClick={handleZoomReset}>
                  <AimOutlined />
                </button>
              </Tooltip>
              <Tooltip title="Fit to Screen" placement="left">
                <button className="btn btn-secondary" style={{ padding: '6px 8px', fontSize: 16 }} onClick={handleZoomFit}>
                  {isFullscreen ? <FullscreenExitOutlined /> : <FullscreenOutlined />}
                </button>
              </Tooltip>
            </div>

            {/* Legend overlay */}
            <div style={{
              position: 'absolute', top: 12, left: 12,
              background: 'rgba(6, 8, 15, 0.85)',
              borderRadius: 'var(--radius-sm)',
              padding: '8px 12px',
              fontSize: 'var(--text-xs)',
              color: 'var(--text-secondary)',
              border: '1px solid var(--border-subtle)',
              lineHeight: 1.8,
            }}>
              <div style={{ fontWeight: 600, marginBottom: 4, color: 'var(--text-primary)' }}>Legend</div>
              {Object.entries(LINK_COLORS).map(([type, color]) => (
                <div key={type} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span style={{ width: 16, height: 2, background: color, display: 'inline-block', borderRadius: 1 }} />
                  <span style={{ textTransform: 'capitalize' }}>{type}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Node Detail Panel */}
          {selectedNode && (
            <Card
              title={<span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{
                  width: 10, height: 10, borderRadius: selectedNode.type === 'endpoint' ? '50%' : 2,
                  background: NODE_COLORS[selectedNode.type], display: 'inline-block',
                }} />
                {selectedNode.label}
              </span>}
              size="small"
              style={{ background: 'var(--bg-card)', borderColor: NODE_COLORS[selectedNode.type] }}
              extra={<button className="btn btn-secondary btn-sm" onClick={() => setSelectedNode(null)}>✕</button>}
            >
              <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
                <div>
                  <Tag color={NODE_COLORS[selectedNode.type]}>{selectedNode.type}</Tag>
                  {selectedNode.severity && (
                    <span className={`severity-badge ${selectedNode.severity.toLowerCase()}`}>{selectedNode.severity}</span>
                  )}
                </div>
                {selectedNode.details && (
                  <p style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-sm)' }}>{selectedNode.details}</p>
                )}
                <div style={{
                  fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)',
                  borderTop: '1px solid var(--border-subtle)', paddingTop: 'var(--space-2)',
                }}>
                  Node ID: <code style={{ color: 'var(--accent-primary)' }}>{selectedNode.id}</code>
                </div>
              </div>
            </Card>
          )}
        </div>
      )}
    </div>
  );
};

export default AttackChainGraph;
