import React, { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';
import { Card, Typography, Badge, Spin, Alert } from 'antd';

const { Title, Text } = Typography;

interface Node {
  id: string;
  label: string;
  group: number;
  risk_score?: number;
  radius?: number;
  x?: number;
  y?: number;
  fx?: number | null;
  fy?: number | null;
}

interface Link {
  source: string | Node;
  target: string | Node;
  type: string; // "data_flow", "auth_dependency", "exploit_chain"
}

interface AttackGraphProps {
  endpoints: any[];
  relationships: any[];
  chains: any[];
}

export const AttackGraph: React.FC<AttackGraphProps> = ({ endpoints, relationships, chains }) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!containerRef.current) return;
    if (!endpoints || endpoints.length === 0) {
      setLoading(false);
      return;
    }

    const width = containerRef.current.clientWidth || 800;
    const height = 500;

    // Build Nodes
    const nodes: Node[] = endpoints.map((ep: any) => ({
      id: ep.url,
      label: ep.url.split('/').pop() || ep.url,
      group: ep.auth_required ? 1 : 2, // 1: Protected, 2: Public
      risk_score: ep.risk_score || 1,
      radius: Math.max(10, Math.min(25, 10 + ((ep.risk_score || 0) * 5))),
    }));

    // Build Links
    const links: Link[] = relationships.map((rel: any) => ({
      source: rel.source,
      target: rel.target,
      type: rel.type,
    }));

    // Inject Chain execution links (highlighted paths)
    chains.forEach((chain: any) => {
      const endpointsInvolved = chain.endpoints_involved || [];
      for (let i = 0; i < endpointsInvolved.length - 1; i++) {
        links.push({
          source: endpointsInvolved[i],
          target: endpointsInvolved[i + 1],
          type: "exploit_chain",
        });
      }
    });

    // Clear previous SVG
    d3.select(containerRef.current).selectAll("*").remove();

    const svg = d3.select(containerRef.current)
      .append("svg")
      .attr("width", width)
      .attr("height", height)
      .attr("viewBox", [0, 0, width, height]);

    // Defs for arrowheads
    svg.append("defs").selectAll("marker")
      .data(["data_flow", "auth_dependency", "exploit_chain"])
      .join("marker")
      .attr("id", d => `arrow-${d}`)
      .attr("viewBox", "0 -5 10 10")
      .attr("refX", 25)
      .attr("refY", 0)
      .attr("markerWidth", 6)
      .attr("markerHeight", 6)
      .attr("orient", "auto")
      .append("path")
      .attr("fill", d => d === "exploit_chain" ? "#ff4d4f" : d === "auth_dependency" ? "#1890ff" : "#8c8c8c")
      .attr("d", "M0,-5L10,0L0,5");

    const simulation = d3.forceSimulation(nodes as any)
      .force("link", d3.forceLink(links).id((d: any) => d.id).distance(100))
      .force("charge", d3.forceManyBody().strength(-300))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide().radius((d: any) => d.radius + 10));

    // Links
    const link = svg.append("g")
      .selectAll("path")
      .data(links)
      .join("path")
      .attr("stroke", (d: any) => d.type === "exploit_chain" ? "#ff4d4f" : d.type === "auth_dependency" ? "#1890ff" : "#d9d9d9")
      .attr("stroke-width", (d: any) => d.type === "exploit_chain" ? 3 : 1.5)
      .attr("stroke-dasharray", (d: any) => d.type === "auth_dependency" ? "5,5" : "none")
      .attr("fill", "none")
      .attr("marker-end", (d: any) => `url(#arrow-${d.type})`);

    // Nodes
    const node = svg.append("g")
      .selectAll("g")
      .data(nodes)
      .join("g")
      .call(d3.drag()
        .on("start", dragstarted)
        .on("drag", dragged)
        .on("end", dragended) as any);

    node.append("circle")
      .attr("r", d => d.radius!)
      .attr("fill", d => d.group === 1 ? "#52c41a" : "#faad14") // green if protected, yellow if public
      .attr("stroke", d => (d.risk_score || 0) > 2 ? "#ff4d4f" : "#fff")
      .attr("stroke-width", d => (d.risk_score || 0) > 2 ? 3 : 1);

    node.append("text")
      .text(d => d.label)
      .attr("x", 12)
      .attr("y", 4)
      .attr("font-size", "12px")
      .attr("fill", "#000")
      .attr("style", "text-shadow: 1px 1px 2px #fff; font-weight: 500;");

    simulation.on("tick", () => {
      link.attr("d", (d: any) => {
        const dx = d.target.x - d.source.x;
        const dy = d.target.y - d.source.y;
        const dr = d.type === "exploit_chain" ? 0 : Math.sqrt(dx * dx + dy * dy); // straight lines for chains, curved for others
        return `M${d.source.x},${d.source.y}A${dr},${dr} 0 0,1 ${d.target.x},${d.target.y}`;
      });

      node.attr("transform", d => `translate(${d.x},${d.y})`);
    });

    setLoading(false);

    function dragstarted(event: any, d: any) {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      d.fx = d.x;
      d.fy = d.y;
    }

    function dragged(event: any, d: any) {
      d.fx = event.x;
      d.fy = event.y;
    }

    function dragended(event: any, d: any) {
      if (!event.active) simulation.alphaTarget(0);
      d.fx = null;
      d.fy = null;
    }

    return () => {
      simulation.stop();
    };
  }, [endpoints, relationships, chains]);

  if (!endpoints || endpoints.length === 0) {
    return <Alert message="No endpoints mapped yet. The Knowledge Graph is empty." type="info" showIcon />;
  }

  return (
    <Card title={<Title level={4}>Interactive Attack Surface Map</Title>} bordered={false} style={{ width: '100%' }}>
      <div style={{ display: 'flex', gap: '20px', marginBottom: '10px' }}>
        <Badge color="#52c41a" text="Protected Endpoint" />
        <Badge color="#faad14" text="Public Endpoint" />
        <Badge color="#ff4d4f" text="High Risk" />
        <Badge color="#1890ff" text="Auth Dependency" />
        <span style={{ borderBottom: '3px solid #ff4d4f', paddingBottom: '2px', fontWeight: 'bold' }}>
          Executable Exploit Chain
        </span>
      </div>
      <Spin spinning={loading}>
        <div ref={containerRef} style={{ width: '100%', height: '500px', border: '1px solid #f0f0f0', borderRadius: '8px', background: '#fafafa' }} />
      </Spin>
    </Card>
  );
};
