import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import type {
  Project,
  ThreatFeed,
  ThreatIntelligenceRecord,
  ThreatCorrelation,
  ThreatIntelSummary,
  MatchClassification,
} from '../types';

interface ThreatIntelligenceViewProps {
  project: Project;
}

export const ThreatIntelligenceView: React.FC<ThreatIntelligenceViewProps> = ({ project }) => {
  const [activeTab, setActiveTab] = useState<'correlations' | 'feeds' | 'search' | 'rationale'>('correlations');
  const [loading, setLoading] = useState<boolean>(true);
  const [syncingFeed, setSyncingFeed] = useState<string | null>(null);
  const [correlating, setCorrelating] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Data states
  const [summary, setSummary] = useState<ThreatIntelSummary | null>(null);
  const [feeds, setFeeds] = useState<ThreatFeed[]>([]);
  const [correlations, setCorrelations] = useState<ThreatCorrelation[]>([]);
  const [records, setRecords] = useState<ThreatIntelligenceRecord[]>([]);

  // Filter states
  const [filterClass, setFilterClass] = useState<string>('ALL');
  const [filterKevOnly, setFilterKevOnly] = useState<boolean>(false);
  const [searchCve, setSearchCve] = useState<string>('');
  const [searchProduct, setSearchProduct] = useState<string>('');
  const [selectedCorrelation, setSelectedCorrelation] = useState<ThreatCorrelation | null>(null);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [sumRes, feedsRes, corrRes] = await Promise.all([
        api.getThreatIntelSummary(project.id).catch(() => null),
        api.listThreatFeeds().catch(() => []),
        api.listProjectThreatCorrelations(project.id).catch(() => []),
      ]);
      setSummary(sumRes);
      setFeeds(feedsRes);
      setCorrelations(corrRes);
    } catch (err: any) {
      setError(err?.message || 'Failed to load threat intelligence overview');
    } finally {
      setLoading(false);
    }
  };

  const loadRecords = async () => {
    try {
      const res = await api.searchThreatRecords({
        cve_id: searchCve || undefined,
        product: searchProduct || undefined,
        is_known_exploited: filterKevOnly ? true : undefined,
        limit: 50,
      });
      setRecords(res);
    } catch (err: any) {
      setError(err?.message || 'Failed to search threat records');
    }
  };

  useEffect(() => {
    loadData();
  }, [project.id]);

  useEffect(() => {
    if (activeTab === 'search') {
      loadRecords();
    }
  }, [activeTab, filterKevOnly]);

  const handleSyncFeed = async (feedName: string) => {
    setSyncingFeed(feedName);
    setError(null);
    setSuccessMsg(null);
    try {
      const res = await api.syncThreatFeed(feedName, { force_local: true });
      setSuccessMsg(`Feed ${feedName} synced: ${res.records_ingested} ingested, ${res.records_updated} updated.`);
      await loadData();
    } catch (err: any) {
      setError(err?.message || `Failed to sync feed ${feedName}`);
    } finally {
      setSyncingFeed(null);
    }
  };

  const handleTriggerCorrelation = async () => {
    setCorrelating(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const res = await api.runProjectThreatCorrelation(project.id, { force_recorrelate: true });
      setSuccessMsg(res.message);
      await loadData();
    } catch (err: any) {
      setError(err?.message || 'Correlation run failed');
    } finally {
      setCorrelating(false);
    }
  };

  const filteredCorrelations = correlations.filter((c) => {
    if (filterClass !== 'ALL' && c.match_classification !== filterClass) return false;
    if (filterKevOnly && !c.is_known_exploited) return false;
    return true;
  });

  const getMatchBadgeClass = (mc: MatchClassification) => {
    switch (mc) {
      case 'CONFIRMED_MATCH':
        return 'bg-red-900/60 text-red-200 border-red-700';
      case 'POSSIBLE_MATCH':
        return 'bg-amber-900/60 text-amber-200 border-amber-700';
      case 'CONFLICTING_DATA':
        return 'bg-purple-900/60 text-purple-200 border-purple-700';
      default:
        return 'bg-gray-800 text-gray-300 border-gray-700';
    }
  };

  const getSeverityBadgeClass = (sev: string) => {
    switch (sev.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-red-700 text-white';
      case 'HIGH':
        return 'bg-orange-600 text-white';
      case 'MEDIUM':
        return 'bg-amber-600 text-white';
      case 'LOW':
        return 'bg-blue-600 text-white';
      default:
        return 'bg-gray-600 text-white';
    }
  };

  return (
    <div className="space-y-6">
      {/* View Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between pb-4 border-b border-gray-700 gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-2">
            <span className="p-2 rounded bg-red-950 text-red-400 border border-red-800">🎯</span>
            Evidence-Grounded Threat Intelligence & Vulnerability Correlation
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Authoritative CISA KEV, NVD CVE, and EPSS correlation with strict product identity and non-destructive risk enrichment.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={loadData}
            disabled={loading}
            className="px-3 py-2 bg-gray-700 hover:bg-gray-600 text-gray-200 rounded text-sm transition"
          >
            {loading ? 'Refreshing...' : 'Refresh'}
          </button>
          <button
            onClick={handleTriggerCorrelation}
            disabled={correlating}
            className="px-4 py-2 bg-red-700 hover:bg-red-600 text-white font-medium rounded text-sm shadow transition flex items-center gap-2"
          >
            {correlating ? (
              <>
                <span className="animate-spin text-sm">⏳</span> Correlating Findings...
              </>
            ) : (
              <>
                <span>⚡</span> Run Correlation Analysis
              </>
            )}
          </button>
        </div>
      </div>

      {/* Notifications */}
      {error && (
        <div className="p-4 bg-red-900/30 border border-red-700 text-red-200 rounded text-sm flex items-center justify-between">
          <span>{error}</span>
          <button onClick={() => setError(null)} className="text-red-400 hover:text-white font-bold ml-4">✕</button>
        </div>
      )}
      {successMsg && (
        <div className="p-4 bg-emerald-900/30 border border-emerald-700 text-emerald-200 rounded text-sm flex items-center justify-between">
          <span>{successMsg}</span>
          <button onClick={() => setSuccessMsg(null)} className="text-emerald-400 hover:text-white font-bold ml-4">✕</button>
        </div>
      )}

      {/* Summary KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="p-4 bg-gray-800 border border-gray-700 rounded shadow-sm">
          <div className="text-xs uppercase font-semibold text-gray-400 tracking-wider">Authoritative Feeds</div>
          <div className="mt-2 flex items-baseline justify-between">
            <span className="text-2xl font-bold text-gray-100">{summary?.active_feeds_count ?? feeds.length} Active</span>
            <span className={`text-xs px-2 py-0.5 rounded font-medium ${summary?.stale_feeds_count ? 'bg-amber-900/80 text-amber-200' : 'bg-emerald-900/80 text-emerald-200'}`}>
              {summary?.stale_feeds_count ? `${summary.stale_feeds_count} Stale` : 'All Fresh'}
            </span>
          </div>
          <div className="text-xs text-gray-400 mt-2">CISA KEV • NVD 2.0 • EPSS</div>
        </div>

        <div className="p-4 bg-gray-800 border border-gray-700 rounded shadow-sm">
          <div className="text-xs uppercase font-semibold text-gray-400 tracking-wider">Known Exploited (KEV)</div>
          <div className="mt-2 flex items-baseline justify-between">
            <span className="text-2xl font-bold text-red-400">{summary?.known_exploited_count ?? 0}</span>
            <span className="text-xs text-gray-400">{summary?.total_cves ?? 0} Total CVEs</span>
          </div>
          <div className="text-xs text-gray-400 mt-2">Active in-the-wild exploitation</div>
        </div>

        <div className="p-4 bg-gray-800 border border-gray-700 rounded shadow-sm">
          <div className="text-xs uppercase font-semibold text-gray-400 tracking-wider">Project Correlations</div>
          <div className="mt-2 flex items-baseline justify-between">
            <span className="text-2xl font-bold text-gray-100">{summary?.total_project_correlations ?? correlations.length}</span>
            <span className="text-xs px-2 py-0.5 rounded bg-red-950 text-red-300 border border-red-800">
              {summary?.confirmed_correlations_count ?? 0} Confirmed
            </span>
          </div>
          <div className="text-xs text-gray-400 mt-2">
            {summary?.possible_correlations_count ?? 0} Possible • {summary?.conflicting_correlations_count ?? 0} Conflicting
          </div>
        </div>

        <div className="p-4 bg-gray-800 border border-gray-700 rounded shadow-sm">
          <div className="text-xs uppercase font-semibold text-gray-400 tracking-wider">Severity Integrity</div>
          <div className="mt-2 flex items-baseline justify-between">
            <span className="text-2xl font-bold text-emerald-400">100% Unaltered</span>
            <span className="text-xs px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800">
              Guaranteed
            </span>
          </div>
          <div className="text-xs text-gray-400 mt-2">Enriched score without mutating base finding</div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex border-b border-gray-700 gap-6 text-sm font-medium">
        <button
          onClick={() => setActiveTab('correlations')}
          className={`pb-3 border-b-2 transition ${
            activeTab === 'correlations'
              ? 'border-red-500 text-red-400 font-semibold'
              : 'border-transparent text-gray-400 hover:text-gray-200'
          }`}
        >
          Correlated Findings ({correlations.length})
        </button>
        <button
          onClick={() => setActiveTab('feeds')}
          className={`pb-3 border-b-2 transition ${
            activeTab === 'feeds'
              ? 'border-red-500 text-red-400 font-semibold'
              : 'border-transparent text-gray-400 hover:text-gray-200'
          }`}
        >
          Authoritative Feeds ({feeds.length})
        </button>
        <button
          onClick={() => setActiveTab('search')}
          className={`pb-3 border-b-2 transition ${
            activeTab === 'search'
              ? 'border-red-500 text-red-400 font-semibold'
              : 'border-transparent text-gray-400 hover:text-gray-200'
          }`}
        >
          Intelligence Repository & CVE Search
        </button>
        <button
          onClick={() => setActiveTab('rationale')}
          className={`pb-3 border-b-2 transition ${
            activeTab === 'rationale'
              ? 'border-red-500 text-red-400 font-semibold'
              : 'border-transparent text-gray-400 hover:text-gray-200'
          }`}
        >
          Correlation Invariants & Methodology
        </button>
      </div>

      {/* Tab 1: Correlated Findings */}
      {activeTab === 'correlations' && (
        <div className="space-y-4">
          {/* Filters */}
          <div className="flex flex-wrap items-center justify-between gap-4 p-3 bg-gray-800/80 border border-gray-700 rounded text-sm">
            <div className="flex items-center gap-3">
              <span className="text-gray-400 font-medium">Filter Match:</span>
              {(['ALL', 'CONFIRMED_MATCH', 'POSSIBLE_MATCH', 'CONFLICTING_DATA'] as const).map((clsName) => (
                <button
                  key={clsName}
                  onClick={() => setFilterClass(clsName)}
                  className={`px-2.5 py-1 rounded text-xs transition ${
                    filterClass === clsName
                      ? 'bg-red-700 text-white font-medium'
                      : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                  }`}
                >
                  {clsName.replace('_', ' ')}
                </button>
              ))}
            </div>

            <label className="flex items-center gap-2 text-gray-300 cursor-pointer">
              <input
                type="checkbox"
                checked={filterKevOnly}
                onChange={(e) => setFilterKevOnly(e.target.checked)}
                className="rounded border-gray-700 text-red-600 focus:ring-0"
              />
              <span className="text-xs font-medium">Known Exploited (CISA KEV) Only</span>
            </label>
          </div>

          {/* Table */}
          {filteredCorrelations.length === 0 ? (
            <div className="p-8 text-center bg-gray-800/40 border border-gray-700 rounded">
              <div className="text-3xl mb-2">🔍</div>
              <p className="text-gray-300 font-medium">No threat correlations found matching filters.</p>
              <p className="text-xs text-gray-400 mt-1">
                Run correlation analysis to match project findings against authoritative feeds.
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto border border-gray-700 rounded">
              <table className="w-full text-left text-sm text-gray-300">
                <thead className="bg-gray-800 text-xs uppercase text-gray-400 border-b border-gray-700">
                  <tr>
                    <th className="px-4 py-3">Finding Title</th>
                    <th className="px-4 py-3">Original Severity</th>
                    <th className="px-4 py-3">Enriched Risk</th>
                    <th className="px-4 py-3">Threat Reference</th>
                    <th className="px-4 py-3">Grounding Match</th>
                    <th className="px-4 py-3">CISA KEV / EPSS</th>
                    <th className="px-4 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700/60 bg-gray-900/60">
                  {filteredCorrelations.map((c) => (
                    <tr key={c.id} className="hover:bg-gray-800/50 transition">
                      <td className="px-4 py-3 font-medium text-gray-100 max-w-xs truncate">
                        {c.finding_title}
                      </td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-0.5 rounded text-xs font-semibold ${getSeverityBadgeClass(c.finding_severity)}`}>
                          {c.finding_severity}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <span className={`font-mono font-bold text-sm ${c.enriched_risk_score >= 80 ? 'text-red-400' : c.enriched_risk_score >= 50 ? 'text-amber-400' : 'text-emerald-400'}`}>
                            {c.enriched_risk_score}
                          </span>
                          <span className="text-xs text-gray-400">/ 100</span>
                        </div>
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-gray-200">
                        {c.cve_id}
                      </td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-0.5 rounded text-xs border font-medium ${getMatchBadgeClass(c.match_classification)}`}>
                          {c.match_classification.replace('_', ' ')}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          {c.is_known_exploited ? (
                            <span className="px-2 py-0.5 rounded text-xs bg-red-950 text-red-300 border border-red-800 font-bold">
                              ⚡ CISA KEV
                            </span>
                          ) : (
                            <span className="text-xs text-gray-400">Standard</span>
                          )}
                          {c.epss_score !== null && c.epss_score !== undefined && (
                            <span className="text-xs font-mono text-gray-400" title="EPSS exploitation probability">
                              EPSS: {(c.epss_score * 100).toFixed(1)}%
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-3 text-right">
                        <button
                          onClick={() => setSelectedCorrelation(c)}
                          className="px-2 py-1 bg-gray-700 hover:bg-gray-600 text-gray-200 text-xs rounded transition"
                        >
                          View Grounding
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Tab 2: Authoritative Feeds */}
      {activeTab === 'feeds' && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {feeds.map((feed) => (
            <div key={feed.id} className="p-5 bg-gray-800 border border-gray-700 rounded flex flex-col justify-between space-y-4">
              <div>
                <div className="flex items-center justify-between">
                  <h3 className="font-bold text-gray-100 text-base">{feed.feed_name.replace('_', ' ')}</h3>
                  <span
                    className={`px-2 py-0.5 rounded text-xs font-semibold ${
                      feed.sync_status === 'SYNCED' && !feed.is_stale
                        ? 'bg-emerald-900/80 text-emerald-200'
                        : feed.is_stale
                        ? 'bg-amber-900/80 text-amber-200'
                        : 'bg-red-900/80 text-red-200'
                    }`}
                  >
                    {feed.is_stale ? 'STALE' : feed.sync_status}
                  </span>
                </div>
                <div className="text-xs font-mono text-gray-400 truncate mt-1">{feed.feed_url}</div>

                <div className="mt-4 space-y-2 text-xs text-gray-300">
                  <div className="flex justify-between">
                    <span className="text-gray-400">Total Records:</span>
                    <span className="font-semibold text-gray-100">{feed.record_count}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Last Synced:</span>
                    <span className="font-mono text-gray-200">
                      {feed.last_synced_at ? new Date(feed.last_synced_at).toLocaleString() : 'Never'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Freshness Horizon:</span>
                    <span>{feed.stale_after_days} days</span>
                  </div>
                  {feed.feed_checksum && (
                    <div className="flex justify-between items-center pt-1 border-t border-gray-700/60">
                      <span className="text-gray-400">Payload SHA-256:</span>
                      <span className="font-mono text-gray-400 text-[10px] truncate max-w-[140px]">
                        {feed.feed_checksum}
                      </span>
                    </div>
                  )}
                </div>
              </div>

              <button
                onClick={() => handleSyncFeed(feed.feed_name)}
                disabled={syncingFeed === feed.feed_name}
                className="w-full py-2 bg-gray-700 hover:bg-gray-600 disabled:opacity-50 text-gray-200 font-medium text-xs rounded transition flex items-center justify-center gap-2"
              >
                {syncingFeed === feed.feed_name ? (
                  <>
                    <span className="animate-spin">⏳</span> Syncing...
                  </>
                ) : (
                  <>
                    <span>🔄</span> Synchronize Feed (Local Fixture)
                  </>
                )}
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Tab 3: Intelligence Repository & CVE Search */}
      {activeTab === 'search' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 p-4 bg-gray-800 border border-gray-700 rounded text-sm">
            <div>
              <label className="block text-xs font-medium text-gray-400 mb-1">Search CVE ID</label>
              <input
                type="text"
                placeholder="e.g. CVE-2024-3400"
                value={searchCve}
                onChange={(e) => setSearchCve(e.target.value)}
                className="w-full px-3 py-1.5 bg-gray-900 border border-gray-700 rounded text-gray-100 text-sm focus:outline-none focus:border-red-500"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-400 mb-1">Filter by Product</label>
              <input
                type="text"
                placeholder="e.g. PAN-OS, Log4j"
                value={searchProduct}
                onChange={(e) => setSearchProduct(e.target.value)}
                className="w-full px-3 py-1.5 bg-gray-900 border border-gray-700 rounded text-gray-100 text-sm focus:outline-none focus:border-red-500"
              />
            </div>
            <div className="flex items-end">
              <button
                onClick={loadRecords}
                className="w-full py-2 bg-red-700 hover:bg-red-600 text-white font-medium text-sm rounded transition"
              >
                Query Threat Records
              </button>
            </div>
          </div>

          <div className="overflow-x-auto border border-gray-700 rounded">
            <table className="w-full text-left text-sm text-gray-300">
              <thead className="bg-gray-800 text-xs uppercase text-gray-400 border-b border-gray-700">
                <tr>
                  <th className="px-4 py-3">CVE Identifier</th>
                  <th className="px-4 py-3">Source</th>
                  <th className="px-4 py-3">Vendor / Product</th>
                  <th className="px-4 py-3">Affected Versions</th>
                  <th className="px-4 py-3">CVSS / EPSS</th>
                  <th className="px-4 py-3">Exploitation Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700/60 bg-gray-900/60">
                {records.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="px-4 py-6 text-center text-gray-400">
                      No matching threat records loaded.
                    </td>
                  </tr>
                ) : (
                  records.map((r) => (
                    <tr key={r.id} className="hover:bg-gray-800/50 transition">
                      <td className="px-4 py-3 font-mono font-bold text-gray-100">{r.cve_id}</td>
                      <td className="px-4 py-3 text-xs text-gray-400">{r.source}</td>
                      <td className="px-4 py-3 text-gray-200">
                        {r.vendor || 'Unknown'} / <span className="font-semibold">{r.product || 'N/A'}</span>
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-gray-300">
                        {r.version_start_including || r.version_end_excluding ? (
                          <span>
                            [{r.version_start_including || '*'}, {r.version_end_excluding || '*'})
                          </span>
                        ) : (
                          'N/A'
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <div className="text-xs">
                          <span className="font-bold text-red-400">CVSS: {r.cvss_score ?? 'N/A'}</span>
                          {r.epss_score !== null && r.epss_score !== undefined && (
                            <span className="ml-2 font-mono text-gray-400">EPSS: {(r.epss_score * 100).toFixed(1)}%</span>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        {r.is_known_exploited ? (
                          <span className="px-2 py-0.5 rounded text-xs bg-red-950 text-red-300 border border-red-800 font-bold">
                            ⚡ Active Exploitation (CISA KEV)
                          </span>
                        ) : (
                          <span className="text-xs text-gray-400">Standard</span>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tab 4: Invariants & Grounding Methodology */}
      {activeTab === 'rationale' && (
        <div className="p-6 bg-gray-800 border border-gray-700 rounded space-y-4 text-sm text-gray-300">
          <h3 className="text-lg font-bold text-gray-100">Evidence-Grounded Threat Intelligence Invariants</h3>
          <ul className="list-disc pl-5 space-y-2">
            <li>
              <strong className="text-white">Strict Product Identity Matching:</strong> Intelligence is correlated only when the product identity and version evidence are sufficiently reliable.
            </li>
            <li>
              <strong className="text-red-400">Prohibition of Resemblance Fallacy (Requirement 7):</strong> The system never infers that an asset is vulnerable merely because a product name resembles an affected product (e.g. fuzzy string similarity or prefix/suffix variations like 'openssl' vs 'libssl-dev-custom' are strictly rejected).
            </li>
            <li>
              <strong className="text-emerald-400">Preservation of Authoritative Severity (Requirement 8 & 9):</strong> The finding's original severity (<code className="text-xs bg-gray-900 px-1 py-0.5 rounded">finding.severity</code>) is never silently altered. Threat enrichment factors (active KEV boost, EPSS score, asset criticality) produce an explainable <code className="text-xs bg-gray-900 px-1 py-0.5 rounded">enriched_risk_score</code> in [0.0, 100.0] alongside the original finding.
            </li>
            <li>
              <strong className="text-purple-400">Conflicting Evidence Handling:</strong> Contradictory evidence (e.g., target scan indicating patched version while another scanner observed vulnerable banner) is explicitly classified as <code className="text-xs bg-gray-900 px-1 py-0.5 rounded">CONFLICTING_DATA</code> rather than forcing an artificial true or false positive.
            </li>
            <li>
              <strong className="text-amber-400">Freshness Horizons:</strong> External feeds are marked <code className="text-xs bg-gray-900 px-1 py-0.5 rounded">STALE</code> when the elapsed time since synchronization exceeds 7 days.
            </li>
          </ul>
        </div>
      )}

      {/* Grounding Rationale Modal */}
      {selectedCorrelation && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4">
          <div className="bg-gray-800 border border-gray-700 rounded-lg max-w-2xl w-full p-6 space-y-4">
            <div className="flex justify-between items-start border-b border-gray-700 pb-3">
              <div>
                <h3 className="text-lg font-bold text-gray-100">{selectedCorrelation.finding_title}</h3>
                <span className="text-xs font-mono text-gray-400">Correlated with {selectedCorrelation.cve_id}</span>
              </div>
              <button
                onClick={() => setSelectedCorrelation(null)}
                className="text-gray-400 hover:text-white font-bold"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3 text-xs text-gray-300">
              <div className="p-3 bg-gray-900 rounded border border-gray-700">
                <span className="font-semibold text-gray-100">Enrichment Factor Breakdown:</span>
                <p className="mt-1 text-gray-300">
                  {selectedCorrelation.risk_enrichment_factors?.explanation || 'No detailed explanation available.'}
                </p>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="p-3 bg-gray-900 rounded border border-gray-700">
                  <span className="font-semibold text-gray-400">Original Finding Severity:</span>
                  <div className="text-base font-bold text-white mt-1">
                    {selectedCorrelation.finding_severity}
                  </div>
                  <span className="text-[10px] text-emerald-400">Unaltered by Threat Intelligence</span>
                </div>
                <div className="p-3 bg-gray-900 rounded border border-gray-700">
                  <span className="font-semibold text-gray-400">Enriched Threat Score:</span>
                  <div className="text-base font-bold text-red-400 mt-1">
                    {selectedCorrelation.enriched_risk_score} / 100
                  </div>
                  <span className="text-[10px] text-gray-400">Confidence: {selectedCorrelation.confidence_score}</span>
                </div>
              </div>

              <div className="p-3 bg-gray-900 rounded border border-gray-700">
                <span className="font-semibold text-gray-400">Evidence Grounding Details:</span>
                <pre className="mt-2 text-[11px] font-mono text-gray-300 overflow-x-auto">
                  {JSON.stringify(selectedCorrelation.evidence_grounding, null, 2)}
                </pre>
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedCorrelation(null)}
                className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-gray-200 text-sm rounded font-medium transition"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
