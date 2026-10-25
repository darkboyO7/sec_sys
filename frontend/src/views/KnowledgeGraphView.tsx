import React, { useState, useEffect, useMemo } from 'react';
import {
  Network,
  RefreshCw,
  AlertTriangle,
  Eye,
  PlusCircle,
  Maximize2,
  ZoomIn,
  ZoomOut,
} from 'lucide-react';
import { api } from '../services/api';
import type {
  Project,
  GraphStats,
  GraphNode,
  GraphNeighborhoodResponse,
  GraphNodeCategory,
  RelationshipType,
  RelationshipStatus,
  GraphRelationshipCreate,
} from '../types';

interface KnowledgeGraphViewProps {
  currentProject: Project | null;
  initialNodeId?: string | null;
}

const CATEGORY_COLORS: Record<
  GraphNodeCategory,
  { label: string; fill: string; stroke: string; text: string; bg: string }
> = {
  ASSET: { label: 'Asset', fill: '#06b6d4', stroke: '#22d3ee', text: 'text-cyan-400', bg: 'bg-cyan-500/10' },
  SERVICE: { label: 'Service', fill: '#3b82f6', stroke: '#60a5fa', text: 'text-blue-400', bg: 'bg-blue-500/10' },
  APPLICATION: { label: 'Application', fill: '#8b5cf6', stroke: '#a78bfa', text: 'text-violet-400', bg: 'bg-violet-500/10' },
  IDENTITY: { label: 'Identity', fill: '#ec4899', stroke: '#f472b6', text: 'text-pink-400', bg: 'bg-pink-500/10' },
  ROLE: { label: 'Role', fill: '#f43f5e', stroke: '#fb7185', text: 'text-rose-400', bg: 'bg-rose-500/10' },
  PERMISSION: { label: 'Permission', fill: '#e11d48', stroke: '#f43f5e', text: 'text-red-400', bg: 'bg-red-500/10' },
  VULNERABILITY: { label: 'Vulnerability', fill: '#ef4444', stroke: '#f87171', text: 'text-red-400', bg: 'bg-red-500/10' },
  FINDING: { label: 'Finding', fill: '#f97316', stroke: '#fb923c', text: 'text-orange-400', bg: 'bg-orange-500/10' },
  EVIDENCE: { label: 'Evidence', fill: '#eab308', stroke: '#facc15', text: 'text-yellow-400', bg: 'bg-yellow-500/10' },
  SECURITY_CONTROL: { label: 'Security Control', fill: '#10b981', stroke: '#34d399', text: 'text-emerald-400', bg: 'bg-emerald-500/10' },
  DEPENDENCY: { label: 'Dependency', fill: '#14b8a6', stroke: '#2dd4bf', text: 'text-teal-400', bg: 'bg-teal-500/10' },
  REMEDIATION: { label: 'Remediation', fill: '#059669', stroke: '#10b981', text: 'text-emerald-400', bg: 'bg-emerald-500/10' },
  ASSESSMENT: { label: 'Assessment', fill: '#a855f7', stroke: '#c084fc', text: 'text-purple-400', bg: 'bg-purple-500/10' },
};

const RELATIONSHIP_TYPES: RelationshipType[] = [
  'RUNS',
  'DEPENDS_ON',
  'AUTHENTICATES_TO',
  'CAN_ACCESS',
  'EXPOSES',
  'AFFECTED_BY',
  'MITIGATES',
  'OBSERVED_AT',
  'VERIFIED_BY',
  'BELONGS_TO',
  'ASSOCIATED_WITH',
];

export const KnowledgeGraphView: React.FC<KnowledgeGraphViewProps> = ({
  currentProject,
  initialNodeId,
}) => {
  const [stats, setStats] = useState<GraphStats | null>(null);
  const [neighborhood, setNeighborhood] = useState<GraphNeighborhoodResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Traversal settings
  const [activeRootNodeId, setActiveRootNodeId] = useState<string | null>(initialNodeId || null);
  const [depth, setDepth] = useState<number>(2);
  const [maxNodes, setMaxNodes] = useState<number>(40);
  const [statusFilter, setStatusFilter] = useState<string>('ALL');

  // Selected Node for Drawer
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

  // Manual Edge Creation Modal
  const [isEdgeModalOpen, setIsEdgeModalOpen] = useState<boolean>(false);
  const [edgeForm, setEdgeForm] = useState<GraphRelationshipCreate>({
    source_node_id: '',
    target_node_id: '',
    relationship_type: 'DEPENDS_ON',
    status: 'VERIFIED',
    confidence: 1.0,
    provenance: 'ANALYST_ASSERTION',
    evidence_reference: '',
  });
  const [edgeSubmitting, setEdgeSubmitting] = useState<boolean>(false);
  const [edgeError, setEdgeError] = useState<string | null>(null);

  // Canvas zoom/pan
  const [zoomLevel, setZoomLevel] = useState<number>(1);

  // Load project graph statistics
  const loadStats = async () => {
    if (!currentProject) return;
    try {
      const s = await api.getGraphStats(currentProject.id);
      setStats(s);
    } catch (err: any) {
      console.error('Failed to load graph stats:', err);
    }
  };

  // Load neighborhood
  const loadNeighborhood = async (rootId?: string) => {
    if (!currentProject) return;
    try {
      setLoading(true);
      setError(null);

      // If no explicit root ID, check if we have one or find one from stats/assets
      let targetRootId = rootId || activeRootNodeId;
      if (!targetRootId) {
        // Query assets to find first asset graph node as initial anchor
        const assets = await api.listAssets(currentProject.id, { limit: 1 });
        if (assets.length > 0) {
          const assetDetail = await api.getAsset(currentProject.id, assets[0].id);
          if (assetDetail.graph_node_id) {
            targetRootId = assetDetail.graph_node_id;
            setActiveRootNodeId(targetRootId);
          }
        }
      }

      if (!targetRootId) {
        setNeighborhood(null);
        setLoading(false);
        return;
      }

      const res = await api.getGraphNeighborhood(currentProject.id, targetRootId, {
        depth,
        maxNodes,
      });

      setNeighborhood(res);
      setActiveRootNodeId(targetRootId);

      // Auto-select root node if nothing selected
      const root = res.nodes.find((n) => n.id === targetRootId);
      if (root && !selectedNode) {
        setSelectedNode(root);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load graph neighborhood');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadStats();
    loadNeighborhood(initialNodeId || undefined);
  }, [currentProject?.id, depth, maxNodes]);

  const handleCreateRelationship = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentProject) return;
    try {
      setEdgeSubmitting(true);
      setEdgeError(null);
      await api.createGraphRelationship(currentProject.id, edgeForm);
      setIsEdgeModalOpen(false);
      await loadStats();
      if (activeRootNodeId) {
        await loadNeighborhood(activeRootNodeId);
      }
    } catch (err: any) {
      setEdgeError(err.message || 'Failed to create graph relationship');
    } finally {
      setEdgeSubmitting(false);
    }
  };

  // Node positions calculation (Orbit / Radial distribution centered on root node)
  const layout = useMemo(() => {
    if (!neighborhood || neighborhood.nodes.length === 0) {
      return { nodePositions: new Map<string, { x: number; y: number }>(), width: 800, height: 600 };
    }

    const width = 800;
    const height = 600;
    const centerX = width / 2;
    const centerY = height / 2;
    const positions = new Map<string, { x: number; y: number }>();

    const rootId = neighborhood.root_node_id;
    positions.set(rootId, { x: centerX, y: centerY });

    const otherNodes = neighborhood.nodes.filter((n) => n.id !== rootId);

    // Group other nodes into concentric rings (depth 1, depth 2)
    // Nodes directly connected to root go into ring 1
    const directNeighbors = new Set<string>();
    (neighborhood.relationships || []).forEach((rel) => {
      if (rel.source_node_id === rootId) directNeighbors.add(rel.target_node_id);
      if (rel.target_node_id === rootId) directNeighbors.add(rel.source_node_id);
    });

    const ring1Nodes: GraphNode[] = [];
    const ring2Nodes: GraphNode[] = [];

    otherNodes.forEach((node) => {
      if (directNeighbors.has(node.id)) {
        ring1Nodes.push(node);
      } else {
        ring2Nodes.push(node);
      }
    });

    // Place Ring 1
    const r1 = 150;
    const angleStep1 = (2 * Math.PI) / Math.max(ring1Nodes.length, 1);
    ring1Nodes.forEach((node, i) => {
      const angle = i * angleStep1 - Math.PI / 2;
      positions.set(node.id, {
        x: centerX + r1 * Math.cos(angle),
        y: centerY + r1 * Math.sin(angle),
      });
    });

    // Place Ring 2
    const r2 = 250;
    const angleStep2 = (2 * Math.PI) / Math.max(ring2Nodes.length, 1);
    ring2Nodes.forEach((node, i) => {
      const angle = i * angleStep2 - Math.PI / 2 + 0.3;
      positions.set(node.id, {
        x: centerX + r2 * Math.cos(angle),
        y: centerY + r2 * Math.sin(angle),
      });
    });

    return { nodePositions: positions, width, height };
  }, [neighborhood]);

  // Filtered relationships
  const visibleRelationships = useMemo(() => {
    if (!neighborhood) return [];
    const rels = neighborhood.relationships || [];
    if (statusFilter === 'ALL') return rels;
    return rels.filter((r) => r.status === statusFilter);
  }, [neighborhood, statusFilter]);

  // Relationships connected to selected node
  const selectedNodeRelationships = useMemo(() => {
    if (!neighborhood || !selectedNode) return { incoming: [], outgoing: [] };
    const rels = neighborhood.relationships || [];
    const incoming = rels.filter((r) => r.target_node_id === selectedNode.id);
    const outgoing = rels.filter((r) => r.source_node_id === selectedNode.id);
    return { incoming, outgoing };
  }, [neighborhood, selectedNode]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 uppercase font-semibold">
              Universal Security Knowledge Graph
            </span>
            <span className="text-xs text-slate-500 font-mono">
              Topology: Bounded Relational
            </span>
          </div>
          <h1 className="text-2xl font-bold text-slate-100 flex items-center gap-2">
            <Network className="w-6 h-6 text-cyan-400" />
            Security Knowledge Graph Explorer
          </h1>
          <p className="text-sm text-slate-400">
            Cycle-safe bounded traversal connecting assets, vulnerabilities, findings, and controls with verification states.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => {
              loadStats();
              if (activeRootNodeId) loadNeighborhood(activeRootNodeId);
            }}
            className="flex items-center gap-2 px-3 py-2 bg-cyber-800 hover:bg-cyber-750 text-slate-300 border border-cyber-700 rounded-lg text-sm transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
            Refresh Graph
          </button>
          <button
            onClick={() => {
              if (selectedNode) {
                setEdgeForm({
                  ...edgeForm,
                  source_node_id: selectedNode.id,
                });
              }
              setIsEdgeModalOpen(true);
            }}
            className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-sm font-medium shadow-lg shadow-cyan-950/40 transition-colors"
          >
            <PlusCircle className="w-4 h-4" />
            Add Relationship
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-4 shadow-sm">
            <div className="text-xs font-mono text-slate-400 uppercase tracking-wider mb-1">Total Graph Nodes</div>
            <div className="text-2xl font-bold text-slate-100">{stats.total_nodes}</div>
            <div className="text-xs text-slate-500 mt-1">Cross-entity graph vertices</div>
          </div>
          <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-4 shadow-sm">
            <div className="text-xs font-mono text-cyan-400 uppercase tracking-wider mb-1">Total Relationships</div>
            <div className="text-2xl font-bold text-cyan-400">{stats.total_edges}</div>
            <div className="text-xs text-slate-500 mt-1">Typed directed graph edges</div>
          </div>
          <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-4 shadow-sm">
            <div className="text-xs font-mono text-emerald-400 uppercase tracking-wider mb-1">Active Neighborhood</div>
            <div className="text-2xl font-bold text-emerald-400">
              {neighborhood?.nodes.length || 0} nodes
            </div>
            <div className="text-xs text-slate-500 mt-1">
              {neighborhood?.relationships.length || 0} visible edges
            </div>
          </div>
          <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-4 shadow-sm">
            <div className="text-xs font-mono text-purple-400 uppercase tracking-wider mb-1">Node Categories</div>
            <div className="text-2xl font-bold text-purple-400">
              {Object.keys(stats.nodes_by_category || {}).length}
            </div>
            <div className="text-xs text-slate-500 mt-1">Distinct domain classes</div>
          </div>
        </div>
      )}

      {error && (
        <div className="p-4 bg-red-950/30 border border-red-500/40 rounded-xl flex items-center gap-3 text-red-300 text-sm">
          <AlertTriangle className="w-5 h-5 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Traversal Controls Bar */}
      <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-2">
              <label className="text-xs font-mono text-slate-400">Anchor Root:</label>
              <select
                value={activeRootNodeId || ''}
                onChange={(e) => {
                  const newId = e.target.value;
                  setActiveRootNodeId(newId);
                  loadNeighborhood(newId);
                }}
                className="bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 max-w-xs font-mono"
              >
                {neighborhood?.nodes.map((n) => (
                  <option key={n.id} value={n.id}>
                    [{n.category}] {n.label}
                  </option>
                ))}
              </select>
            </div>

            <div className="flex items-center gap-2">
              <label className="text-xs font-mono text-slate-400">Depth:</label>
              <select
                value={depth}
                onChange={(e) => setDepth(Number(e.target.value))}
                className="bg-cyber-900 border border-cyber-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
              >
                <option value={1}>1 hop</option>
                <option value={2}>2 hops</option>
                <option value={3}>3 hops</option>
                <option value={4}>4 hops</option>
              </select>
            </div>

            <div className="flex items-center gap-2">
              <label className="text-xs font-mono text-slate-400">Max Nodes:</label>
              <select
                value={maxNodes}
                onChange={(e) => setMaxNodes(Number(e.target.value))}
                className="bg-cyber-900 border border-cyber-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
              >
                <option value={20}>20 nodes</option>
                <option value={40}>40 nodes</option>
                <option value={80}>80 nodes</option>
                <option value={120}>120 nodes</option>
              </select>
            </div>

            <div className="flex items-center gap-2">
              <label className="text-xs font-mono text-slate-400">Status:</label>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="bg-cyber-900 border border-cyber-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
              >
                <option value="ALL">All Relationships</option>
                <option value="VERIFIED">VERIFIED (Solid)</option>
                <option value="INFERRED">INFERRED (Dashed)</option>
                <option value="HYPOTHETICAL">HYPOTHETICAL (Dotted)</option>
                <option value="STALE">STALE (Dimmed)</option>
              </select>
            </div>
          </div>

          {/* Zoom controls */}
          <div className="flex items-center gap-1.5 bg-cyber-900 border border-cyber-700 rounded-lg p-1">
            <button
              onClick={() => setZoomLevel(Math.max(0.6, zoomLevel - 0.2))}
              className="p-1 text-slate-400 hover:text-slate-200 rounded"
              title="Zoom Out"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <span className="text-[11px] font-mono text-slate-400 px-1">
              {(zoomLevel * 100).toFixed(0)}%
            </span>
            <button
              onClick={() => setZoomLevel(Math.min(1.8, zoomLevel + 0.2))}
              className="p-1 text-slate-400 hover:text-slate-200 rounded"
              title="Zoom In"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => setZoomLevel(1)}
              className="p-1 text-slate-400 hover:text-slate-200 rounded text-[10px] font-mono"
              title="Reset Zoom"
            >
              1:1
            </button>
          </div>
        </div>

        {neighborhood?.truncated && (
          <div className="p-2.5 bg-amber-950/20 border border-amber-500/30 rounded-lg text-xs text-amber-300 flex items-center gap-2 font-mono">
            <AlertTriangle className="w-4 h-4 flex-shrink-0" />
            <span>Graph query hit upper traversal limit; displaying top bounded neighborhood to maintain stability.</span>
          </div>
        )}
      </div>

      {/* Main Canvas + Side Inspector Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* SVG Graph Canvas */}
        <div className="lg:col-span-3 bg-cyber-950 border border-cyber-750 rounded-xl relative overflow-hidden min-h-[550px] shadow-inner flex items-center justify-center">
          {loading && !neighborhood ? (
            <div className="text-center text-slate-500 font-mono text-xs">
              <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-cyan-400" />
              Traversing bounded graph neighborhood...
            </div>
          ) : !neighborhood || neighborhood.nodes.length === 0 ? (
            <div className="text-center text-slate-500 font-mono text-xs p-8">
              <Network className="w-8 h-8 mx-auto mb-3 text-slate-600" />
              No graph entities found in this project yet. Ingest an asset or run an assessment to construct the security graph.
            </div>
          ) : (
            <div
              className="w-full h-full flex items-center justify-center transition-transform duration-200"
              style={{ transform: `scale(${zoomLevel})` }}
            >
              <svg
                width={layout.width}
                height={layout.height}
                viewBox={`0 0 ${layout.width} ${layout.height}`}
                className="select-none"
              >
                <defs>
                  {/* Arrow markers */}
                  <marker
                    id="arrow-verified"
                    viewBox="0 0 10 10"
                    refX="22"
                    refY="5"
                    markerWidth="6"
                    markerHeight="6"
                    orient="auto-start-reverse"
                  >
                    <path d="M 0 0 L 10 5 L 0 10 z" fill="#10b981" />
                  </marker>
                  <marker
                    id="arrow-inferred"
                    viewBox="0 0 10 10"
                    refX="22"
                    refY="5"
                    markerWidth="6"
                    markerHeight="6"
                    orient="auto-start-reverse"
                  >
                    <path d="M 0 0 L 10 5 L 0 10 z" fill="#f59e0b" />
                  </marker>
                  <marker
                    id="arrow-hypothetical"
                    viewBox="0 0 10 10"
                    refX="22"
                    refY="5"
                    markerWidth="6"
                    markerHeight="6"
                    orient="auto-start-reverse"
                  >
                    <path d="M 0 0 L 10 5 L 0 10 z" fill="#c084fc" />
                  </marker>
                  <marker
                    id="arrow-stale"
                    viewBox="0 0 10 10"
                    refX="22"
                    refY="5"
                    markerWidth="6"
                    markerHeight="6"
                    orient="auto-start-reverse"
                  >
                    <path d="M 0 0 L 10 5 L 0 10 z" fill="#64748b" />
                  </marker>
                </defs>

                {/* Render Edges */}
                {visibleRelationships.map((rel) => {
                  const sourcePos = layout.nodePositions.get(rel.source_node_id);
                  const targetPos = layout.nodePositions.get(rel.target_node_id);
                  if (!sourcePos || !targetPos) return null;

                  const isSelectedConnected =
                    selectedNode &&
                    (rel.source_node_id === selectedNode.id || rel.target_node_id === selectedNode.id);

                  let stroke = '#10b981';
                  let strokeDash = undefined;
                  let marker = 'url(#arrow-verified)';

                  if (rel.status === 'INFERRED') {
                    stroke = '#f59e0b';
                    strokeDash = '6 3';
                    marker = 'url(#arrow-inferred)';
                  } else if (rel.status === 'HYPOTHETICAL') {
                    stroke = '#c084fc';
                    strokeDash = '2 3';
                    marker = 'url(#arrow-hypothetical)';
                  } else if (rel.status === 'STALE') {
                    stroke = '#64748b';
                    marker = 'url(#arrow-stale)';
                  }

                  const midX = (sourcePos.x + targetPos.x) / 2;
                  const midY = (sourcePos.y + targetPos.y) / 2;

                  return (
                    <g key={rel.id} className="group">
                      <line
                        x1={sourcePos.x}
                        y1={sourcePos.y}
                        x2={targetPos.x}
                        y2={targetPos.y}
                        stroke={stroke}
                        strokeWidth={isSelectedConnected ? 2.5 : 1.5}
                        strokeDasharray={strokeDash}
                        opacity={isSelectedConnected ? 1 : 0.6}
                        markerEnd={marker}
                        className="transition-all"
                      />
                      {/* Midpoint Label */}
                      <text
                        x={midX}
                        y={midY - 4}
                        textAnchor="middle"
                        fill={stroke}
                        fontSize="9"
                        fontFamily="monospace"
                        className="opacity-0 group-hover:opacity-100 transition-opacity bg-cyber-900 pointer-events-none"
                      >
                        {rel.relationship_type} ({(rel.confidence * 100).toFixed(0)}%)
                      </text>
                    </g>
                  );
                })}

                {/* Render Nodes */}
                {neighborhood.nodes.map((node) => {
                  const pos = layout.nodePositions.get(node.id);
                  if (!pos) return null;

                  const isRoot = node.id === neighborhood.root_node_id;
                  const isSelected = selectedNode?.id === node.id;
                  const catCfg = CATEGORY_COLORS[node.category] || CATEGORY_COLORS.ASSET;

                  return (
                    <g
                      key={node.id}
                      transform={`translate(${pos.x}, ${pos.y})`}
                      onClick={() => setSelectedNode(node)}
                      className="cursor-pointer group"
                    >
                      {/* Outer pulse for root or selected */}
                      {(isRoot || isSelected) && (
                        <circle
                          r={isRoot ? 24 : 20}
                          fill="none"
                          stroke={catCfg.stroke}
                          strokeWidth="2"
                          strokeDasharray="4 2"
                          className="animate-spin"
                          style={{ animationDuration: '8s' }}
                        />
                      )}

                      {/* Main Node Circle */}
                      <circle
                        r={isRoot ? 16 : 12}
                        fill={catCfg.fill}
                        stroke="#0f172a"
                        strokeWidth="2"
                        className="transition-transform group-hover:scale-125"
                      />

                      {/* Node Label */}
                      <text
                        y={isRoot ? 28 : 22}
                        textAnchor="middle"
                        fill="#cbd5e1"
                        fontSize={isRoot ? 11 : 9}
                        fontFamily="monospace"
                        fontWeight={isRoot ? 'bold' : 'normal'}
                        className="pointer-events-none drop-shadow"
                      >
                        {node.label.length > 16 ? `${node.label.slice(0, 14)}...` : node.label}
                      </text>

                      {/* Node Category Sublabel */}
                      <text
                        y={isRoot ? 40 : 32}
                        textAnchor="middle"
                        fill="#64748b"
                        fontSize="8"
                        fontFamily="monospace"
                        className="pointer-events-none uppercase"
                      >
                        {node.category}
                      </text>
                    </g>
                  );
                })}
              </svg>
            </div>
          )}

          {/* Graph Legend Overlay */}
          <div className="absolute bottom-3 left-3 bg-cyber-900/90 backdrop-blur-sm border border-cyber-750 rounded-lg p-2.5 text-[10px] font-mono space-y-1.5 shadow-md">
            <div className="text-slate-400 uppercase font-semibold">Verification Legend</div>
            <div className="flex items-center gap-2">
              <span className="w-3 h-0.5 bg-emerald-400 inline-block"></span>
              <span className="text-emerald-400">VERIFIED (Solid)</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-3 h-0.5 bg-amber-400 inline-block border-b border-dashed"></span>
              <span className="text-amber-400">INFERRED (Dashed)</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-3 h-0.5 bg-purple-400 inline-block border-b border-dotted"></span>
              <span className="text-purple-400">HYPOTHETICAL (Dotted)</span>
            </div>
          </div>
        </div>

        {/* Side Node Inspector */}
        <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-5 space-y-5 h-full overflow-y-auto">
          {selectedNode ? (
            <>
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span
                    className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase font-semibold ${
                      CATEGORY_COLORS[selectedNode.category]?.bg || 'bg-cyber-800'
                    } ${
                      CATEGORY_COLORS[selectedNode.category]?.text || 'text-slate-300'
                    }`}
                  >
                    {selectedNode.category}
                  </span>
                  {selectedNode.id === neighborhood?.root_node_id && (
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                      Anchor Root
                    </span>
                  )}
                </div>
                <h3 className="text-lg font-bold text-slate-100 break-words">{selectedNode.label}</h3>
                <p className="text-[10px] font-mono text-slate-500 mt-0.5 break-all">ID: {selectedNode.id}</p>
              </div>

              {selectedNode.id !== neighborhood?.root_node_id && (
                <button
                  onClick={() => {
                    setActiveRootNodeId(selectedNode.id);
                    loadNeighborhood(selectedNode.id);
                  }}
                  className="w-full py-2 bg-cyber-800 hover:bg-cyan-950/40 text-cyan-400 border border-cyber-700 hover:border-cyan-500/40 rounded-lg text-xs font-mono transition-colors flex items-center justify-center gap-2"
                >
                  <Maximize2 className="w-3.5 h-3.5" />
                  Re-center Graph Here
                </button>
              )}

              {/* Edge Counts */}
              <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                <div className="p-2.5 bg-cyber-900 border border-cyber-800 rounded-lg">
                  <span className="text-slate-500 block text-[10px]">Incoming Edges</span>
                  <span className="text-slate-200 font-bold">{selectedNodeRelationships.incoming.length}</span>
                </div>
                <div className="p-2.5 bg-cyber-900 border border-cyber-800 rounded-lg">
                  <span className="text-slate-500 block text-[10px]">Outgoing Edges</span>
                  <span className="text-slate-200 font-bold">{selectedNodeRelationships.outgoing.length}</span>
                </div>
              </div>

              {/* Connected Relationships */}
              <div className="space-y-2">
                <h4 className="text-xs font-mono uppercase text-slate-400 tracking-wider">
                  Relationships ({selectedNodeRelationships.outgoing.length + selectedNodeRelationships.incoming.length})
                </h4>

                <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1 text-xs">
                  {selectedNodeRelationships.outgoing.map((rel) => {
                    const targetNode = neighborhood?.nodes.find((n) => n.id === rel.target_node_id);
                    return (
                      <div
                        key={rel.id}
                        className="p-2 bg-cyber-900 border border-cyber-800 rounded text-[11px] font-mono"
                      >
                        <div className="flex items-center justify-between text-cyan-400">
                          <span>→ {rel.relationship_type}</span>
                          <span className="text-[10px] text-slate-500">{rel.status}</span>
                        </div>
                        <div className="text-slate-300 mt-0.5 truncate">
                          Target: {targetNode?.label || rel.target_node_id.slice(0, 8)}
                        </div>
                      </div>
                    );
                  })}

                  {selectedNodeRelationships.incoming.map((rel) => {
                    const srcNode = neighborhood?.nodes.find((n) => n.id === rel.source_node_id);
                    return (
                      <div
                        key={rel.id}
                        className="p-2 bg-cyber-900 border border-cyber-800 rounded text-[11px] font-mono"
                      >
                        <div className="flex items-center justify-between text-emerald-400">
                          <span>← {rel.relationship_type}</span>
                          <span className="text-[10px] text-slate-500">{rel.status}</span>
                        </div>
                        <div className="text-slate-300 mt-0.5 truncate">
                          Source: {srcNode?.label || rel.source_node_id.slice(0, 8)}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Node Properties */}
              <div className="space-y-2">
                <h4 className="text-xs font-mono uppercase text-slate-400 tracking-wider">Properties</h4>
                <div className="bg-cyber-950 border border-cyber-800 rounded-lg p-2.5 font-mono text-[11px] text-slate-300 overflow-x-auto max-h-40">
                  <pre>{JSON.stringify(selectedNode.properties, null, 2)}</pre>
                </div>
              </div>
            </>
          ) : (
            <div className="py-16 text-center text-slate-500 font-mono text-xs">
              <Eye className="w-6 h-6 mx-auto mb-2 text-slate-600" />
              Click any node in the graph canvas to inspect its relationships and properties.
            </div>
          )}
        </div>
      </div>

      {/* Add Relationship Modal */}
      {isEdgeModalOpen && (
        <div className="fixed inset-0 z-50 bg-cyber-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-lg bg-cyber-900 border border-cyber-750 rounded-2xl p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-cyber-750 pb-3">
              <div>
                <h3 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                  <PlusCircle className="w-5 h-5 text-cyan-400" />
                  Add Graph Relationship
                </h3>
                <p className="text-xs text-slate-400">
                  Connect two project entities with typed semantic linkage. Cross-project connections are strictly rejected.
                </p>
              </div>
              <button
                onClick={() => setIsEdgeModalOpen(false)}
                className="text-slate-400 hover:text-slate-200"
              >
                ✕
              </button>
            </div>

            {edgeError && (
              <div className="p-3 bg-red-950/30 border border-red-500/40 rounded-lg text-xs text-red-300">
                {edgeError}
              </div>
            )}

            <form onSubmit={handleCreateRelationship} className="space-y-4">
              <div className="space-y-1.5">
                <label className="text-xs font-mono text-slate-300 block">
                  Source Node <span className="text-cyan-400">*</span>
                </label>
                <select
                  required
                  value={edgeForm.source_node_id}
                  onChange={(e) => setEdgeForm({ ...edgeForm, source_node_id: e.target.value })}
                  className="w-full bg-cyber-950 border border-cyber-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                >
                  <option value="">Select Source Node...</option>
                  {neighborhood?.nodes.map((n) => (
                    <option key={n.id} value={n.id}>
                      [{n.category}] {n.label}
                    </option>
                  ))}
                </select>
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-mono text-slate-300 block">
                  Relationship Type <span className="text-cyan-400">*</span>
                </label>
                <select
                  value={edgeForm.relationship_type}
                  onChange={(e) =>
                    setEdgeForm({
                      ...edgeForm,
                      relationship_type: e.target.value as RelationshipType,
                    })
                  }
                  className="w-full bg-cyber-950 border border-cyber-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                >
                  {RELATIONSHIP_TYPES.map((t) => (
                    <option key={t} value={t}>
                      {t}
                    </option>
                  ))}
                </select>
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-mono text-slate-300 block">
                  Target Node <span className="text-cyan-400">*</span>
                </label>
                <select
                  required
                  value={edgeForm.target_node_id}
                  onChange={(e) => setEdgeForm({ ...edgeForm, target_node_id: e.target.value })}
                  className="w-full bg-cyber-950 border border-cyber-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                >
                  <option value="">Select Target Node...</option>
                  {neighborhood?.nodes
                    .filter((n) => n.id !== edgeForm.source_node_id)
                    .map((n) => (
                      <option key={n.id} value={n.id}>
                        [{n.category}] {n.label}
                      </option>
                    ))}
                </select>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <label className="text-xs font-mono text-slate-300 block">Status</label>
                  <select
                    value={edgeForm.status}
                    onChange={(e) =>
                      setEdgeForm({
                        ...edgeForm,
                        status: e.target.value as RelationshipStatus,
                      })
                    }
                    className="w-full bg-cyber-950 border border-cyber-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                  >
                    <option value="VERIFIED">VERIFIED</option>
                    <option value="INFERRED">INFERRED</option>
                    <option value="HYPOTHETICAL">HYPOTHETICAL</option>
                  </select>
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-mono text-slate-300 block">
                    Confidence ({(edgeForm.confidence! * 100).toFixed(0)}%)
                  </label>
                  <input
                    type="range"
                    min="0.1"
                    max="1.0"
                    step="0.05"
                    value={edgeForm.confidence}
                    onChange={(e) =>
                      setEdgeForm({ ...edgeForm, confidence: parseFloat(e.target.value) })
                    }
                    className="w-full accent-cyan-500"
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-mono text-slate-300 block">Provenance Reference</label>
                <input
                  type="text"
                  placeholder="e.g. Architecture Diagram Review / Port Scan correlation"
                  value={edgeForm.provenance || ''}
                  onChange={(e) => setEdgeForm({ ...edgeForm, provenance: e.target.value })}
                  className="w-full bg-cyber-950 border border-cyber-700 rounded-lg px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

              <div className="flex items-center justify-end gap-3 pt-3 border-t border-cyber-750">
                <button
                  type="button"
                  onClick={() => setIsEdgeModalOpen(false)}
                  className="px-4 py-2 bg-cyber-800 hover:bg-cyber-750 text-slate-300 rounded-lg text-xs font-medium transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={edgeSubmitting || !edgeForm.source_node_id || !edgeForm.target_node_id}
                  className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white rounded-lg text-xs font-medium shadow-md transition-colors"
                >
                  {edgeSubmitting ? 'Connecting...' : 'Create Relationship'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
