import React, { useState, useEffect } from 'react';
import {
  Server,
  Search,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  Clock,
  ArrowRight,
  Eye,
  PlusCircle,
  Network,
  Shield,
  Layers,
  Database,
  Globe,
  Radio,
  FileText,
  Copy,
  Check,
} from 'lucide-react';
import { api } from '../services/api';
import type {
  Project,
  Asset,
  AssetDetail,
  AssetObservation,
  VulnerabilityFinding,
  AssetType,
  AssetCriticality,
  AssetStatus,
  AssetCreateFixtureRequest,
} from '../types';

interface AssetInventoryViewProps {
  currentProject: Project | null;
  onNavigateToGraph?: (graphNodeId?: string) => void;
}

const ASSET_TYPE_CONFIG: Record<
  AssetType,
  { label: string; icon: any; bg: string; text: string; border: string }
> = {
  HOST: { label: 'Host', icon: Server, bg: 'bg-blue-500/10', text: 'text-blue-400', border: 'border-blue-500/30' },
  IP_ADDRESS: { label: 'IP Address', icon: Radio, bg: 'bg-cyan-500/10', text: 'text-cyan-400', border: 'border-cyan-500/30' },
  DOMAIN: { label: 'Domain', icon: Globe, bg: 'bg-teal-500/10', text: 'text-teal-400', border: 'border-teal-500/30' },
  HOSTNAME: { label: 'Hostname', icon: Globe, bg: 'bg-emerald-500/10', text: 'text-emerald-400', border: 'border-emerald-500/30' },
  SERVICE: { label: 'Service', icon: Layers, bg: 'bg-indigo-500/10', text: 'text-indigo-400', border: 'border-indigo-500/30' },
  SOFTWARE_COMPONENT: { label: 'Software', icon: Layers, bg: 'bg-purple-500/10', text: 'text-purple-400', border: 'border-purple-500/30' },
  WEB_APP: { label: 'Web App', icon: Globe, bg: 'bg-violet-500/10', text: 'text-violet-400', border: 'border-violet-500/30' },
  API_ENDPOINT: { label: 'API Endpoint', icon: Radio, bg: 'bg-sky-500/10', text: 'text-sky-400', border: 'border-sky-500/30' },
  CLOUD_RESOURCE: { label: 'Cloud Resource', icon: Server, bg: 'bg-amber-500/10', text: 'text-amber-400', border: 'border-amber-500/30' },
  IDENTITY: { label: 'Identity', icon: Shield, bg: 'bg-pink-500/10', text: 'text-pink-400', border: 'border-pink-500/30' },
  DATA_STORE: { label: 'Data Store', icon: Database, bg: 'bg-rose-500/10', text: 'text-rose-400', border: 'border-rose-500/30' },
  SECURITY_CONTROL: { label: 'Security Control', icon: Shield, bg: 'bg-emerald-500/10', text: 'text-emerald-400', border: 'border-emerald-500/30' },
};

const CRITICALITY_CONFIG: Record<
  AssetCriticality,
  { label: string; bg: string; text: string; border: string }
> = {
  CRITICAL: { label: 'Critical', bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/30' },
  HIGH: { label: 'High', bg: 'bg-orange-500/10', text: 'text-orange-400', border: 'border-orange-500/30' },
  MEDIUM: { label: 'Medium', bg: 'bg-yellow-500/10', text: 'text-yellow-400', border: 'border-yellow-500/30' },
  LOW: { label: 'Low', bg: 'bg-blue-500/10', text: 'text-blue-400', border: 'border-blue-500/30' },
  INFO: { label: 'Info', bg: 'bg-zinc-500/10', text: 'text-zinc-400', border: 'border-zinc-500/30' },
};

const STATUS_CONFIG: Record<
  AssetStatus,
  { label: string; bg: string; text: string; border: string }
> = {
  ACTIVE: { label: 'Active', bg: 'bg-emerald-500/10', text: 'text-emerald-400', border: 'border-emerald-500/30' },
  INACTIVE: { label: 'Inactive', bg: 'bg-zinc-500/10', text: 'text-zinc-400', border: 'border-zinc-500/30' },
  DECOMMISSIONED: { label: 'Decommissioned', bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/30' },
  UNDER_REVIEW: { label: 'Under Review', bg: 'bg-amber-500/10', text: 'text-amber-400', border: 'border-amber-500/30' },
};

export const AssetInventoryView: React.FC<AssetInventoryViewProps> = ({
  currentProject,
  onNavigateToGraph,
}) => {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [search, setSearch] = useState<string>('');
  const [typeFilter, setTypeFilter] = useState<string>('ALL');
  const [criticalityFilter, setCriticalityFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [onlyAmbiguous, setOnlyAmbiguous] = useState<boolean>(false);

  // Detail Modal State
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null);
  const [assetDetail, setAssetDetail] = useState<AssetDetail | null>(null);
  const [assetObservations, setAssetObservations] = useState<AssetObservation[]>([]);
  const [assetFindings, setAssetFindings] = useState<VulnerabilityFinding[]>([]);
  const [detailLoading, setDetailLoading] = useState<boolean>(false);

  // Ambiguity Resolution Form
  const [resolutionNotes, setResolutionNotes] = useState<string>('');
  const [resolvingAmbiguity, setResolvingAmbiguity] = useState<boolean>(false);

  // Ingest Fixture Asset Modal
  const [isFixtureModalOpen, setIsFixtureModalOpen] = useState<boolean>(false);
  const [fixtureForm, setFixtureForm] = useState<AssetCreateFixtureRequest>({
    asset_type: 'WEB_APP',
    canonical_identifier: '',
    name: '',
    environment: 'PRODUCTION',
    criticality: 'MEDIUM',
    attributes: {},
    source: 'FIXTURE',
    confidence: 1.0,
    is_ambiguous: false,
    ambiguity_reason: '',
  });
  const [fixtureRawAttrs, setFixtureRawAttrs] = useState<string>('{\n  "purpose": "Primary application service"\n}');
  const [fixtureSubmitting, setFixtureSubmitting] = useState<boolean>(false);
  const [fixtureError, setFixtureError] = useState<string | null>(null);

  // Copy feedback state
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const loadAssets = async () => {
    if (!currentProject) return;
    try {
      setLoading(true);
      setError(null);
      const data = await api.listAssets(currentProject.id, {
        search: search.trim() || undefined,
        assetType: typeFilter !== 'ALL' ? typeFilter : undefined,
        criticality: criticalityFilter !== 'ALL' ? criticalityFilter : undefined,
        status: statusFilter !== 'ALL' ? statusFilter : undefined,
        isAmbiguous: onlyAmbiguous ? true : undefined,
      });
      setAssets(data);
    } catch (err: any) {
      setError(err.message || 'Failed to load asset inventory');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAssets();
  }, [currentProject?.id, search, typeFilter, criticalityFilter, statusFilter, onlyAmbiguous]);

  const loadAssetDetail = async (assetId: string) => {
    if (!currentProject) return;
    try {
      setDetailLoading(true);
      setSelectedAssetId(assetId);
      const [detail, observations, findings] = await Promise.all([
        api.getAsset(currentProject.id, assetId),
        api.listAssetObservations(currentProject.id, assetId),
        api.listAssetFindings(currentProject.id, assetId),
      ]);
      setAssetDetail(detail);
      setAssetObservations(observations);
      setAssetFindings(findings);
    } catch (err: any) {
      setError(err.message || 'Failed to load asset details');
    } finally {
      setDetailLoading(false);
    }
  };

  const handleResolveAmbiguity = async () => {
    if (!currentProject || !assetDetail || !resolutionNotes.trim()) return;
    try {
      setResolvingAmbiguity(true);
      const updated = await api.resolveAssetAmbiguity(currentProject.id, assetDetail.id, {
        resolution_notes: resolutionNotes.trim(),
      });
      setAssetDetail(updated);
      setResolutionNotes('');
      await loadAssets();
    } catch (err: any) {
      setError(err.message || 'Failed to resolve asset ambiguity');
    } finally {
      setResolvingAmbiguity(false);
    }
  };

  const handleCreateFixture = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentProject) return;
    try {
      setFixtureSubmitting(true);
      setFixtureError(null);

      let parsedAttrs = {};
      if (fixtureRawAttrs.trim()) {
        try {
          parsedAttrs = JSON.parse(fixtureRawAttrs);
        } catch {
          throw new Error('Attributes must be valid JSON');
        }
      }

      const payload: AssetCreateFixtureRequest = {
        ...fixtureForm,
        canonical_identifier: fixtureForm.canonical_identifier.trim(),
        name: fixtureForm.name?.trim() || undefined,
        attributes: parsedAttrs,
        ambiguity_reason: fixtureForm.is_ambiguous ? fixtureForm.ambiguity_reason : undefined,
      };

      await api.createFixtureAsset(currentProject.id, payload);
      setIsFixtureModalOpen(false);
      setFixtureForm({
        asset_type: 'WEB_APP',
        canonical_identifier: '',
        name: '',
        environment: 'PRODUCTION',
        criticality: 'MEDIUM',
        attributes: {},
        source: 'FIXTURE',
        confidence: 1.0,
        is_ambiguous: false,
        ambiguity_reason: '',
      });
      await loadAssets();
    } catch (err: any) {
      setFixtureError(err.message || 'Failed to create fixture asset');
    } finally {
      setFixtureSubmitting(false);
    }
  };

  // Metrics
  const totalAssets = assets.length;
  const criticalHighCount = assets.filter(
    (a) => a.criticality === 'CRITICAL' || a.criticality === 'HIGH'
  ).length;
  const activeCount = assets.filter((a) => a.status === 'ACTIVE').length;
  const ambiguousCount = assets.filter((a) => a.is_ambiguous).length;

  return (
    <div className="space-y-6">
      {/* View Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 uppercase font-semibold">
              Phase 4 Core Intelligence
            </span>
            <span className="text-xs text-slate-500 font-mono">
              Project: {currentProject?.name || 'None'}
            </span>
          </div>
          <h1 className="text-2xl font-bold text-slate-100 flex items-center gap-2">
            <Server className="w-6 h-6 text-cyan-400" />
            Persistent Asset Inventory
          </h1>
          <p className="text-sm text-slate-400">
            Deterministic classification, typed normalization, observation provenance, and conflict retention.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => loadAssets()}
            className="flex items-center gap-2 px-3 py-2 bg-cyber-800 hover:bg-cyber-750 text-slate-300 border border-cyber-700 rounded-lg text-sm transition-colors"
            title="Refresh assets"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
            Refresh
          </button>
          <button
            onClick={() => setIsFixtureModalOpen(true)}
            className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-sm font-medium shadow-lg shadow-cyan-950/40 transition-colors"
          >
            <PlusCircle className="w-4 h-4" />
            Ingest Fixture Asset
          </button>
        </div>
      </div>

      {/* Top Metrics Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-4 shadow-sm">
          <div className="text-xs font-mono text-slate-400 uppercase tracking-wider mb-1">Total Assets</div>
          <div className="text-2xl font-bold text-slate-100">{totalAssets}</div>
          <div className="text-xs text-slate-500 mt-1">Reconciled inventory entities</div>
        </div>
        <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-4 shadow-sm">
          <div className="text-xs font-mono text-rose-400 uppercase tracking-wider mb-1">Critical & High</div>
          <div className="text-2xl font-bold text-rose-400">{criticalHighCount}</div>
          <div className="text-xs text-slate-500 mt-1">Priority assessment targets</div>
        </div>
        <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-4 shadow-sm">
          <div className="text-xs font-mono text-emerald-400 uppercase tracking-wider mb-1">Active Status</div>
          <div className="text-2xl font-bold text-emerald-400">{activeCount}</div>
          <div className="text-xs text-slate-500 mt-1">Live operational assets</div>
        </div>
        <div className={`bg-cyber-850 border rounded-xl p-4 shadow-sm ${ambiguousCount > 0 ? 'border-amber-500/40 bg-amber-950/10' : 'border-cyber-750'}`}>
          <div className="text-xs font-mono text-amber-400 uppercase tracking-wider mb-1 flex items-center gap-1.5">
            <AlertTriangle className="w-3.5 h-3.5" />
            Ambiguous Signals
          </div>
          <div className="text-2xl font-bold text-amber-400">{ambiguousCount}</div>
          <div className="text-xs text-slate-500 mt-1">Conflict or identity ambiguity</div>
        </div>
      </div>

      {error && (
        <div className="p-4 bg-red-950/30 border border-red-500/40 rounded-xl flex items-center gap-3 text-red-300 text-sm">
          <AlertTriangle className="w-5 h-5 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Filter & Search Bar */}
      <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-4 space-y-3">
        <div className="flex flex-col md:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              placeholder="Search by asset name or canonical identifier..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-cyber-900 border border-cyber-700 rounded-lg pl-9 pr-4 py-2 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Asset Types</option>
              {Object.keys(ASSET_TYPE_CONFIG).map((type) => (
                <option key={type} value={type}>
                  {ASSET_TYPE_CONFIG[type as AssetType].label}
                </option>
              ))}
            </select>

            <select
              value={criticalityFilter}
              onChange={(e) => setCriticalityFilter(e.target.value)}
              className="bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Criticalities</option>
              {Object.keys(CRITICALITY_CONFIG).map((c) => (
                <option key={c} value={c}>
                  {CRITICALITY_CONFIG[c as AssetCriticality].label}
                </option>
              ))}
            </select>

            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Statuses</option>
              {Object.keys(STATUS_CONFIG).map((s) => (
                <option key={s} value={s}>
                  {STATUS_CONFIG[s as AssetStatus].label}
                </option>
              ))}
            </select>

            <button
              onClick={() => setOnlyAmbiguous(!onlyAmbiguous)}
              className={`px-3 py-2 text-xs font-mono rounded-lg border transition-colors flex items-center gap-1.5 ${
                onlyAmbiguous
                  ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                  : 'bg-cyber-900 text-slate-400 border-cyber-700 hover:text-slate-200'
              }`}
            >
              <AlertTriangle className="w-3.5 h-3.5" />
              Ambiguous Only
            </button>
          </div>
        </div>
      </div>

      {/* Assets Table */}
      <div className="bg-cyber-850 border border-cyber-750 rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-cyber-750 bg-cyber-900/50 text-[11px] font-mono uppercase text-slate-400">
                <th className="py-3 px-4">Asset & Canonical Identifier</th>
                <th className="py-3 px-4">Type</th>
                <th className="py-3 px-4">Criticality</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Environment</th>
                <th className="py-3 px-4">Ambiguity</th>
                <th className="py-3 px-4">Last Seen</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyber-750 text-sm">
              {loading && assets.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-500 font-mono text-xs">
                    <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-cyan-400" />
                    Querying reconciled asset inventory...
                  </td>
                </tr>
              ) : assets.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-500 font-mono text-xs">
                    No assets matched current query and filters. Ingest a fixture or run an assessment to populate inventory.
                  </td>
                </tr>
              ) : (
                assets.map((asset) => {
                  const typeCfg = ASSET_TYPE_CONFIG[asset.asset_type] || ASSET_TYPE_CONFIG.HOST;
                  const critCfg = CRITICALITY_CONFIG[asset.criticality] || CRITICALITY_CONFIG.MEDIUM;
                  const statCfg = STATUS_CONFIG[asset.status] || STATUS_CONFIG.ACTIVE;
                  const TypeIcon = typeCfg.icon;

                  return (
                    <tr key={asset.id} className="hover:bg-cyber-800/50 transition-colors">
                      <td className="py-3.5 px-4">
                        <div className="font-medium text-slate-100 flex items-center gap-2">
                          {asset.name}
                        </div>
                        <div className="flex items-center gap-1.5 mt-0.5">
                          <span className="font-mono text-xs text-cyan-400 select-all">
                            {asset.canonical_identifier}
                          </span>
                          <button
                            onClick={() => handleCopy(asset.canonical_identifier, asset.id)}
                            className="text-slate-500 hover:text-slate-300 transition-colors p-0.5"
                            title="Copy Canonical Identifier"
                          >
                            {copiedId === asset.id ? (
                              <Check className="w-3 h-3 text-emerald-400" />
                            ) : (
                              <Copy className="w-3 h-3" />
                            )}
                          </button>
                        </div>
                      </td>

                      <td className="py-3.5 px-4">
                        <span
                          className={`inline-flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 rounded border ${typeCfg.bg} ${typeCfg.text} ${typeCfg.border}`}
                        >
                          <TypeIcon className="w-3 h-3" />
                          {typeCfg.label}
                        </span>
                      </td>

                      <td className="py-3.5 px-4">
                        <span
                          className={`inline-block text-[11px] font-mono px-2 py-0.5 rounded border uppercase font-medium ${critCfg.bg} ${critCfg.text} ${critCfg.border}`}
                        >
                          {critCfg.label}
                        </span>
                      </td>

                      <td className="py-3.5 px-4">
                        <span
                          className={`inline-block text-[11px] font-mono px-2 py-0.5 rounded border ${statCfg.bg} ${statCfg.text} ${statCfg.border}`}
                        >
                          {statCfg.label}
                        </span>
                      </td>

                      <td className="py-3.5 px-4 text-xs font-mono text-slate-300">
                        {asset.environment}
                      </td>

                      <td className="py-3.5 px-4">
                        {asset.is_ambiguous ? (
                          <span
                            className="inline-flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/40"
                            title={asset.ambiguity_reason || 'Identity ambiguity detected'}
                          >
                            <AlertTriangle className="w-3 h-3" />
                            Ambiguous
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-[11px] font-mono text-slate-500">
                            <CheckCircle2 className="w-3 h-3 text-emerald-500/70" />
                            Resolved
                          </span>
                        )}
                      </td>

                      <td className="py-3.5 px-4 text-xs font-mono text-slate-400">
                        {new Date(asset.last_seen_at).toLocaleDateString()}
                      </td>

                      <td className="py-3.5 px-4 text-right">
                        <button
                          onClick={() => loadAssetDetail(asset.id)}
                          className="px-2.5 py-1.5 bg-cyber-800 hover:bg-cyan-950/40 text-cyan-400 border border-cyber-700 hover:border-cyan-500/40 rounded text-xs font-mono transition-colors inline-flex items-center gap-1"
                        >
                          <Eye className="w-3.5 h-3.5" />
                          Inspect
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Asset Detail Drawer / Modal */}
      {selectedAssetId && (
        <div className="fixed inset-0 z-50 bg-cyber-950/80 backdrop-blur-sm flex justify-end">
          <div className="w-full max-w-2xl bg-cyber-900 border-l border-cyber-750 h-full overflow-y-auto p-6 space-y-6 shadow-2xl">
            {detailLoading || !assetDetail ? (
              <div className="py-24 text-center text-slate-500 font-mono text-xs">
                <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-3 text-cyan-400" />
                Retrieving asset details, observations, and graph linkage...
              </div>
            ) : (
              <>
                {/* Header */}
                <div className="flex items-start justify-between border-b border-cyber-750 pb-4">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 uppercase font-semibold">
                        {assetDetail.asset_type}
                      </span>
                      <span className="text-xs text-slate-500 font-mono">ID: {assetDetail.id}</span>
                    </div>
                    <h2 className="text-xl font-bold text-slate-100">{assetDetail.name}</h2>
                    <p className="font-mono text-xs text-cyan-400 mt-1 select-all">
                      {assetDetail.canonical_identifier}
                    </p>
                  </div>
                  <button
                    onClick={() => {
                      setSelectedAssetId(null);
                      setAssetDetail(null);
                    }}
                    className="text-slate-400 hover:text-slate-200 text-lg px-2"
                  >
                    ✕
                  </button>
                </div>

                {/* Graph Linkage Banner */}
                <div className="p-4 bg-cyber-850 border border-cyan-500/30 rounded-xl flex items-center justify-between gap-4">
                  <div>
                    <div className="text-xs font-mono text-cyan-400 uppercase tracking-wider mb-0.5 flex items-center gap-1.5">
                      <Network className="w-4 h-4" />
                      Universal Security Knowledge Graph
                    </div>
                    <div className="text-xs text-slate-400">
                      Connected to {assetDetail.related_nodes_count} relationships in the project graph
                    </div>
                  </div>
                  {onNavigateToGraph && assetDetail.graph_node_id && (
                    <button
                      onClick={() => {
                        onNavigateToGraph(assetDetail.graph_node_id!);
                      }}
                      className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-xs font-mono transition-colors flex items-center gap-1.5"
                    >
                      Explore Graph
                      <ArrowRight className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>

                {/* Ambiguity Alert & Resolution Form */}
                {assetDetail.is_ambiguous && (
                  <div className="p-4 bg-amber-950/20 border border-amber-500/40 rounded-xl space-y-3">
                    <div className="flex items-start gap-2.5">
                      <AlertTriangle className="w-5 h-5 text-amber-400 flex-shrink-0 mt-0.5" />
                      <div>
                        <div className="text-sm font-semibold text-amber-300">Identity Ambiguity Detected</div>
                        <div className="text-xs text-amber-200/80 mt-1">
                          {assetDetail.ambiguity_reason || 'Conflicting identifiers or ambiguous endpoint classification recorded.'}
                        </div>
                      </div>
                    </div>

                    <div className="pt-2 border-t border-amber-500/20 space-y-2">
                      <label className="text-xs font-mono text-slate-300 block">
                        Resolution Notes (Required to resolve):
                      </label>
                      <textarea
                        value={resolutionNotes}
                        onChange={(e) => setResolutionNotes(e.target.value)}
                        placeholder="Document verified identity rationale, primary DNS canonical pointer, or architectural owner..."
                        rows={2}
                        className="w-full bg-cyber-900 border border-cyber-700 rounded-lg p-2.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-amber-500 font-mono"
                      />
                      <button
                        onClick={handleResolveAmbiguity}
                        disabled={resolvingAmbiguity || !resolutionNotes.trim()}
                        className="px-3 py-1.5 bg-amber-600 hover:bg-amber-500 disabled:opacity-50 text-white rounded text-xs font-medium transition-colors"
                      >
                        {resolvingAmbiguity ? 'Saving...' : 'Resolve Ambiguity'}
                      </button>
                    </div>
                  </div>
                )}

                {/* Metadata Grid */}
                <div className="grid grid-cols-2 gap-3 text-xs font-mono">
                  <div className="p-3 bg-cyber-850 border border-cyber-750 rounded-lg">
                    <span className="text-slate-500 block mb-1">Environment</span>
                    <span className="text-slate-200">{assetDetail.environment}</span>
                  </div>
                  <div className="p-3 bg-cyber-850 border border-cyber-750 rounded-lg">
                    <span className="text-slate-500 block mb-1">Criticality</span>
                    <span className="text-slate-200">{assetDetail.criticality}</span>
                  </div>
                  <div className="p-3 bg-cyber-850 border border-cyber-750 rounded-lg">
                    <span className="text-slate-500 block mb-1">First Seen</span>
                    <span className="text-slate-200">
                      {new Date(assetDetail.first_seen_at).toLocaleString()}
                    </span>
                  </div>
                  <div className="p-3 bg-cyber-850 border border-cyber-750 rounded-lg">
                    <span className="text-slate-500 block mb-1">Last Observed</span>
                    <span className="text-slate-200">
                      {new Date(assetDetail.last_seen_at).toLocaleString()}
                    </span>
                  </div>
                </div>

                {/* Attributes Viewer */}
                <div className="space-y-2">
                  <h3 className="text-xs font-mono uppercase text-slate-400 tracking-wider flex items-center gap-1.5">
                    <FileText className="w-3.5 h-3.5 text-cyan-400" />
                    Asset Attributes & Metadata
                  </h3>
                  <div className="bg-cyber-950 border border-cyber-800 rounded-lg p-3 font-mono text-xs text-slate-300 overflow-x-auto max-h-48">
                    <pre>{JSON.stringify(assetDetail.attributes, null, 2)}</pre>
                  </div>
                </div>

                {/* Historical Observations */}
                <div className="space-y-3">
                  <h3 className="text-xs font-mono uppercase text-slate-400 tracking-wider flex items-center justify-between">
                    <span className="flex items-center gap-1.5">
                      <Clock className="w-3.5 h-3.5 text-cyan-400" />
                      Historical Observations ({assetObservations.length})
                    </span>
                    <span className="text-[11px] text-slate-500 lowercase">immutable provenance</span>
                  </h3>

                  <div className="space-y-2 max-h-60 overflow-y-auto pr-1">
                    {assetObservations.length === 0 ? (
                      <div className="p-4 bg-cyber-850 border border-cyber-750 rounded-lg text-center text-xs text-slate-500 font-mono">
                        No separate observations logged yet.
                      </div>
                    ) : (
                      assetObservations.map((obs) => (
                        <div
                          key={obs.id}
                          className="p-3 bg-cyber-850 border border-cyber-750 rounded-lg space-y-1.5 text-xs"
                        >
                          <div className="flex items-center justify-between">
                            <span className="font-mono text-cyan-400 font-medium">
                              Source: {obs.observation_source}
                            </span>
                            <span className="font-mono text-slate-500 text-[11px]">
                              {new Date(obs.observed_at).toLocaleString()}
                            </span>
                          </div>
                          <div className="flex items-center gap-3 text-[11px] font-mono text-slate-400">
                            <span>Confidence: {(obs.confidence * 100).toFixed(0)}%</span>
                            <span>Status: {obs.validation_status}</span>
                            {obs.assessment_job_id && (
                              <span className="text-slate-500 truncate max-w-[150px]">
                                Job: {obs.assessment_job_id.slice(0, 8)}...
                              </span>
                            )}
                          </div>
                          {obs.evidence_hash && (
                            <div className="font-mono text-[10px] text-slate-500 truncate">
                              SHA256: {obs.evidence_hash}
                            </div>
                          )}
                        </div>
                      ))
                    )}
                  </div>
                </div>

                {/* Associated Findings */}
                <div className="space-y-3">
                  <h3 className="text-xs font-mono uppercase text-slate-400 tracking-wider flex items-center justify-between">
                    <span className="flex items-center gap-1.5">
                      <Shield className="w-3.5 h-3.5 text-rose-400" />
                      Associated Vulnerability Findings ({assetFindings.length})
                    </span>
                  </h3>

                  <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                    {assetFindings.length === 0 ? (
                      <div className="p-4 bg-cyber-850 border border-cyber-750 rounded-lg text-center text-xs text-slate-500 font-mono">
                        No security findings currently mapped to this asset.
                      </div>
                    ) : (
                      assetFindings.map((finding) => (
                        <div
                          key={finding.id}
                          className="p-3 bg-cyber-850 border border-cyber-750 rounded-lg flex items-center justify-between text-xs"
                        >
                          <div>
                            <div className="font-medium text-slate-200">{finding.title}</div>
                            <div className="text-[11px] font-mono text-slate-400 mt-0.5">
                              Status: {finding.status} • CVSS: {finding.cvss_score || 'N/A'}
                            </div>
                          </div>
                          <span
                            className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase ${
                              CRITICALITY_CONFIG[finding.severity as AssetCriticality]?.bg || 'bg-cyber-800'
                            } ${
                              CRITICALITY_CONFIG[finding.severity as AssetCriticality]?.text || 'text-slate-400'
                            } ${
                              CRITICALITY_CONFIG[finding.severity as AssetCriticality]?.border || 'border-cyber-700'
                            }`}
                          >
                            {finding.severity}
                          </span>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </>
            )}
          </div>
        </div>
      )}

      {/* Ingest Fixture Asset Modal */}
      {isFixtureModalOpen && (
        <div className="fixed inset-0 z-50 bg-cyber-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-xl bg-cyber-900 border border-cyber-750 rounded-2xl p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-cyber-750 pb-3">
              <div>
                <h3 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                  <PlusCircle className="w-5 h-5 text-cyan-400" />
                  Ingest Fixture Asset
                </h3>
                <p className="text-xs text-slate-400">
                  Simulate or register synthetic inventory entity for graph modeling & assessment.
                </p>
              </div>
              <button
                onClick={() => setIsFixtureModalOpen(false)}
                className="text-slate-400 hover:text-slate-200"
              >
                ✕
              </button>
            </div>

            {fixtureError && (
              <div className="p-3 bg-red-950/30 border border-red-500/40 rounded-lg text-xs text-red-300">
                {fixtureError}
              </div>
            )}

            <form onSubmit={handleCreateFixture} className="space-y-4">
              <div className="space-y-1.5">
                <label className="text-xs font-mono text-slate-300 block">
                  Canonical Identifier / Target <span className="text-cyan-400">*</span>
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. https://api.internal.corp:443 or 192.168.1.100"
                  value={fixtureForm.canonical_identifier}
                  onChange={(e) =>
                    setFixtureForm({ ...fixtureForm, canonical_identifier: e.target.value })
                  }
                  className="w-full bg-cyber-950 border border-cyber-700 rounded-lg px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <label className="text-xs font-mono text-slate-300 block">Display Name (Optional)</label>
                  <input
                    type="text"
                    placeholder="e.g. Core Banking Gateway"
                    value={fixtureForm.name || ''}
                    onChange={(e) => setFixtureForm({ ...fixtureForm, name: e.target.value })}
                    className="w-full bg-cyber-950 border border-cyber-700 rounded-lg px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-mono text-slate-300 block">Asset Type</label>
                  <select
                    value={fixtureForm.asset_type}
                    onChange={(e) =>
                      setFixtureForm({ ...fixtureForm, asset_type: e.target.value as AssetType })
                    }
                    className="w-full bg-cyber-950 border border-cyber-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                  >
                    {Object.keys(ASSET_TYPE_CONFIG).map((type) => (
                      <option key={type} value={type}>
                        {ASSET_TYPE_CONFIG[type as AssetType].label}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <label className="text-xs font-mono text-slate-300 block">Criticality</label>
                  <select
                    value={fixtureForm.criticality}
                    onChange={(e) =>
                      setFixtureForm({
                        ...fixtureForm,
                        criticality: e.target.value as AssetCriticality,
                      })
                    }
                    className="w-full bg-cyber-950 border border-cyber-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                  >
                    {Object.keys(CRITICALITY_CONFIG).map((c) => (
                      <option key={c} value={c}>
                        {CRITICALITY_CONFIG[c as AssetCriticality].label}
                      </option>
                    ))}
                  </select>
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-mono text-slate-300 block">Environment</label>
                  <input
                    type="text"
                    value={fixtureForm.environment}
                    onChange={(e) => setFixtureForm({ ...fixtureForm, environment: e.target.value })}
                    className="w-full bg-cyber-950 border border-cyber-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-cyan-500 font-mono"
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-mono text-slate-300 block">Attributes (JSON)</label>
                <textarea
                  rows={3}
                  value={fixtureRawAttrs}
                  onChange={(e) => setFixtureRawAttrs(e.target.value)}
                  className="w-full bg-cyber-950 border border-cyber-700 rounded-lg p-2.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

              <div className="p-3 bg-cyber-950/60 border border-cyber-800 rounded-lg space-y-2">
                <label className="flex items-center gap-2 cursor-pointer text-xs text-slate-300 font-mono">
                  <input
                    type="checkbox"
                    checked={fixtureForm.is_ambiguous}
                    onChange={(e) =>
                      setFixtureForm({ ...fixtureForm, is_ambiguous: e.target.checked })
                    }
                    className="rounded bg-cyber-900 border-cyber-700 text-amber-500 focus:ring-0"
                  />
                  Mark as Ambiguous / Identity Conflict
                </label>

                {fixtureForm.is_ambiguous && (
                  <input
                    type="text"
                    placeholder="Document ambiguity reason (e.g. unverified DNS pointer)..."
                    value={fixtureForm.ambiguity_reason || ''}
                    onChange={(e) =>
                      setFixtureForm({ ...fixtureForm, ambiguity_reason: e.target.value })
                    }
                    className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-1.5 text-xs text-amber-200 placeholder-slate-500 focus:outline-none focus:border-amber-500 font-mono"
                  />
                )}
              </div>

              <div className="flex items-center justify-end gap-3 pt-3 border-t border-cyber-750">
                <button
                  type="button"
                  onClick={() => setIsFixtureModalOpen(false)}
                  className="px-4 py-2 bg-cyber-800 hover:bg-cyber-750 text-slate-300 rounded-lg text-xs font-medium transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={fixtureSubmitting || !fixtureForm.canonical_identifier.trim()}
                  className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white rounded-lg text-xs font-medium shadow-md transition-colors"
                >
                  {fixtureSubmitting ? 'Ingesting...' : 'Ingest Asset'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
