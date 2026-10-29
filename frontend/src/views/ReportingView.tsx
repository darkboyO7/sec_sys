import React, { useState, useEffect, useCallback } from 'react';
import {
  FileText,
  Download,
  Plus,
  RefreshCw,
  ShieldCheck,
  AlertTriangle,
  CheckCircle,
  XCircle,
  PackageCheck,
  Upload,
  FileCheck,
  Info,
} from 'lucide-react';
import { api } from '../services/api';
import type {
  Project,
  ReportRecord,
  ReportType,
  ReportFormat,
  AssessmentJob,
  AssessmentReportManifest,
  BundleVerificationResult,
} from '../types';

interface Props {
  currentProject: Project;
}

export const ReportingView: React.FC<Props> = ({ currentProject }) => {
  const [activeTab, setActiveTab] = useState<'generate' | 'preview' | 'verify' | 'ledger'>('generate');
  const [reports, setReports] = useState<ReportRecord[]>([]);
  const [assessments, setAssessments] = useState<AssessmentJob[]>([]);
  const [selectedAssessmentId, setSelectedAssessmentId] = useState<string>('');
  const [canonicalManifest, setCanonicalManifest] = useState<AssessmentReportManifest | null>(null);

  const [loading, setLoading] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [manifestLoading, setManifestLoading] = useState(false);

  const [title, setTitle] = useState(`${currentProject.name} Security Assessment Report`);
  const [reportType, setReportType] = useState<ReportType>('EXECUTIVE');
  const [reportFormat, setReportFormat] = useState<ReportFormat>('JSON');
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  // Verification tab state
  const [bundleBase64, setBundleBase64] = useState<string>('');
  const [bundleFileName, setBundleFileName] = useState<string>('');
  const [verifying, setVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState<BundleVerificationResult | null>(null);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [reportList, assessList] = await Promise.all([
        api.listReports(currentProject.id),
        api.listAssessments(currentProject.id),
      ]);
      setReports(reportList);
      setAssessments(assessList);
      if (assessList.length > 0 && !selectedAssessmentId) {
        setSelectedAssessmentId(assessList[0].id);
      }
    } catch (err: any) {
      console.error('Failed to load reporting data:', err);
    } finally {
      setLoading(false);
    }
  }, [currentProject.id, selectedAssessmentId]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const loadCanonicalReport = useCallback(async (assessmentId: string) => {
    if (!assessmentId) return;
    setManifestLoading(true);
    try {
      const manifest = await api.getCanonicalReport(currentProject.id, assessmentId);
      setCanonicalManifest(manifest);
    } catch (err: any) {
      console.error('Failed to load canonical report manifest:', err);
    } finally {
      setManifestLoading(false);
    }
  }, [currentProject.id]);

  useEffect(() => {
    if (selectedAssessmentId) {
      loadCanonicalReport(selectedAssessmentId);
    }
  }, [selectedAssessmentId, loadCanonicalReport]);

  const handleGenerate = async () => {
    if (!title.trim()) {
      alert('Please enter a report title.');
      return;
    }
    setGenerating(true);
    try {
      const payload: any = {
        report_type: reportType,
        report_format: reportFormat,
        title: title.trim(),
      };
      if (reportType === 'ASSESSMENT_CANONICAL' && selectedAssessmentId) {
        payload.assessment_id = selectedAssessmentId;
      }
      const res = await api.generateReport(currentProject.id, payload);
      const sha = res.record?.report_sha256 || res.content_sha256 || 'verified';
      setStatusMessage(`Report compiled successfully (SHA-256: ${sha.slice(0, 16)}...).`);
      loadData();
    } catch (err: any) {
      alert(err.message || 'Report generation failed');
    } finally {
      setGenerating(false);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setBundleFileName(file.name);
    const reader = new FileReader();
    reader.onload = () => {
      const result = reader.result as string;
      const base64 = result.split(',')[1] || result;
      setBundleBase64(base64);
    };
    reader.readAsDataURL(file);
  };

  const handleVerifyBundle = async () => {
    if (!bundleBase64) {
      alert('Please upload or select an assessment bundle archive first.');
      return;
    }
    setVerifying(true);
    try {
      const res = await api.verifyBundle(currentProject.id, bundleBase64);
      setVerificationResult(res);
      setStatusMessage('Assessment bundle inspection completed (validation-only mode).');
    } catch (err: any) {
      alert(err.message || 'Verification inspection failed');
    } finally {
      setVerifying(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex justify-between items-center bg-cyber-850 p-6 rounded-xl border border-cyber-700 shadow-sm">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <FileText className="w-6 h-6 text-accent-cyan" />
            Reporting, Evidence Export & Verifiable Bundles
          </h2>
          <p className="text-sm text-slate-400 mt-1">
            Defensive security intelligence reports grounded in persisted observations, SHA-256 integrity digests, formula injection protection, and validation-only archive verification (Prompt 32).
          </p>
        </div>
        <button
          onClick={loadData}
          disabled={loading}
          className="px-3.5 py-2 bg-cyber-750 hover:bg-cyber-700 text-slate-200 text-xs rounded-lg flex items-center gap-2 border border-cyber-600 transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {statusMessage && (
        <div className="p-4 bg-accent-cyan/10 border border-accent-cyan/30 text-accent-cyan rounded-lg text-sm flex items-center justify-between">
          <span className="flex items-center gap-2">
            <Info className="w-4 h-4" />
            {statusMessage}
          </span>
          <button onClick={() => setStatusMessage(null)} className="text-xs hover:underline">Dismiss</button>
        </div>
      )}

      {/* Tabs */}
      <div className="flex border-b border-cyber-750 space-x-6 text-sm">
        <button
          onClick={() => setActiveTab('generate')}
          className={`pb-3 font-semibold border-b-2 transition flex items-center gap-2 ${
            activeTab === 'generate'
              ? 'border-accent-cyan text-accent-cyan'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Plus className="w-4 h-4" />
          Generate Reports
        </button>
        <button
          onClick={() => setActiveTab('preview')}
          className={`pb-3 font-semibold border-b-2 transition flex items-center gap-2 ${
            activeTab === 'preview'
              ? 'border-accent-cyan text-accent-cyan'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <ShieldCheck className="w-4 h-4" />
          Canonical Report & Coverage Preview
        </button>
        <button
          onClick={() => setActiveTab('verify')}
          className={`pb-3 font-semibold border-b-2 transition flex items-center gap-2 ${
            activeTab === 'verify'
              ? 'border-accent-cyan text-accent-cyan'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <PackageCheck className="w-4 h-4" />
          Verifiable Bundle Inspector
        </button>
        <button
          onClick={() => setActiveTab('ledger')}
          className={`pb-3 font-semibold border-b-2 transition flex items-center gap-2 ${
            activeTab === 'ledger'
              ? 'border-accent-cyan text-accent-cyan'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <FileCheck className="w-4 h-4" />
          Report Ledger & Cryptographic Proofs ({reports.length})
        </button>
      </div>

      {/* TAB 1: GENERATE REPORT */}
      {activeTab === 'generate' && (
        <div className="bg-cyber-850 p-6 rounded-xl border border-cyber-700 space-y-5">
          <div>
            <h3 className="text-sm font-semibold text-slate-200">Compile Security Report Artifact</h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Exports are cryptographically fingerprinted, project-scoped, and protected against CSV formula execution.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="md:col-span-2">
              <label className="text-xs font-semibold text-slate-400 block mb-1.5">Report Title</label>
              <input
                type="text"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-accent-cyan"
              />
            </div>
            <div>
              <label className="text-xs font-semibold text-slate-400 block mb-1.5">Report Type</label>
              <select
                value={reportType}
                onChange={(e) => setReportType(e.target.value as ReportType)}
                className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-accent-cyan"
              >
                <option value="EXECUTIVE">Executive Summary</option>
                <option value="TECHNICAL">Technical Findings</option>
                <option value="GOVERNANCE">Governance & Compliance</option>
                <option value="ASSESSMENT_CANONICAL">Assessment Canonical (Evidence-Backed)</option>
              </select>
            </div>
            <div>
              <label className="text-xs font-semibold text-slate-400 block mb-1.5">Export Format</label>
              <select
                value={reportFormat}
                onChange={(e) => setReportFormat(e.target.value as ReportFormat)}
                className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-accent-cyan"
              >
                <option value="JSON">Structured JSON (v1.0.0)</option>
                <option value="HTML">Rendered HTML (Safe Escaping)</option>
                <option value="CSV">Sanitized CSV (Formula Injection Safe)</option>
                <option value="BUNDLE">Portable Assessment Bundle (.tar.gz)</option>
              </select>
            </div>
          </div>

          {reportType === 'ASSESSMENT_CANONICAL' && (
            <div>
              <label className="text-xs font-semibold text-slate-400 block mb-1.5">Target Assessment</label>
              <select
                value={selectedAssessmentId}
                onChange={(e) => setSelectedAssessmentId(e.target.value)}
                className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-accent-cyan"
              >
                {assessments.map((a) => (
                  <option key={a.id} value={a.id}>
                    [{a.status}] {a.target_input} (Adapter: {a.adapter_name}) - {new Date(a.created_at).toLocaleString()}
                  </option>
                ))}
              </select>
            </div>
          )}

          <div className="flex justify-end pt-2">
            <button
              onClick={handleGenerate}
              disabled={generating}
              className="px-5 py-2.5 bg-accent-cyan hover:bg-cyan-400 text-cyber-900 font-bold rounded-lg text-xs flex items-center gap-2 transition shadow"
            >
              <Plus className="w-4 h-4" />
              {generating ? 'Compiling Report Artifact...' : 'Compile & Persist Report'}
            </button>
          </div>
        </div>
      )}

      {/* TAB 2: CANONICAL PREVIEW & COVERAGE */}
      {activeTab === 'preview' && (
        <div className="space-y-6">
          <div className="bg-cyber-850 p-6 rounded-xl border border-cyber-700 space-y-4">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div>
                <h3 className="text-sm font-semibold text-slate-200">Grounded Canonical Assessment Report</h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Evaluates scope, coverage gaps, failed checks, and evidence completeness.
                </p>
              </div>
              <div className="w-full md:w-80">
                <select
                  value={selectedAssessmentId}
                  onChange={(e) => setSelectedAssessmentId(e.target.value)}
                  className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-accent-cyan"
                >
                  {assessments.map((a) => (
                    <option key={a.id} value={a.id}>
                      [{a.status}] {a.target_input} ({a.adapter_name})
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {manifestLoading && (
              <div className="p-8 text-center text-slate-400 text-xs flex items-center justify-center gap-2">
                <RefreshCw className="w-4 h-4 animate-spin text-accent-cyan" />
                Retrieving canonical assessment manifest...
              </div>
            )}

            {canonicalManifest && !manifestLoading && (
              <div className="space-y-5 pt-2">
                {/* Coverage & Limitations Warning Banner */}
                {canonicalManifest.coverage_summary.coverage_gap_identified ? (
                  <div className="p-4 bg-amber-500/10 border border-amber-500/30 rounded-lg text-amber-300 text-xs space-y-1.5">
                    <div className="flex items-center gap-2 font-semibold text-amber-200">
                      <AlertTriangle className="w-4 h-4 text-amber-400" />
                      Notice of Assessment Scope & Coverage Limitations
                    </div>
                    <p>
                      Status: <strong>{canonicalManifest.coverage_summary.status}</strong>. Checks Completed: {canonicalManifest.coverage_summary.total_checks_completed}/{canonicalManifest.coverage_summary.total_checks_attempted}. Missing evidence count: {canonicalManifest.coverage_summary.missing_evidence_count}.
                    </p>
                    <p className="text-[11px] text-amber-400/80">
                      {canonicalManifest.coverage_summary.disclaimer}
                    </p>
                  </div>
                ) : (
                  <div className="p-4 bg-emerald-500/10 border border-emerald-500/30 rounded-lg text-emerald-300 text-xs flex items-center gap-2">
                    <CheckCircle className="w-4 h-4 text-emerald-400" />
                    <span>Complete assessment coverage recorded. All executed probes corroborated with cryptographic evidence.</span>
                  </div>
                )}

                {/* KPI Cards */}
                <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                  <div className="p-4 bg-cyber-900 rounded-lg border border-cyber-750">
                    <div className="text-xl font-bold text-slate-100">{canonicalManifest.findings.length}</div>
                    <div className="text-[10px] text-slate-400 uppercase mt-1">Total Findings</div>
                  </div>
                  <div className="p-4 bg-cyber-900 rounded-lg border border-cyber-750">
                    <div className="text-xl font-bold text-red-400">{canonicalManifest.finding_counts_by_severity.CRITICAL || 0}</div>
                    <div className="text-[10px] text-slate-400 uppercase mt-1">Critical</div>
                  </div>
                  <div className="p-4 bg-cyber-900 rounded-lg border border-cyber-750">
                    <div className="text-xl font-bold text-amber-400">{canonicalManifest.finding_counts_by_severity.HIGH || 0}</div>
                    <div className="text-[10px] text-slate-400 uppercase mt-1">High</div>
                  </div>
                  <div className="p-4 bg-cyber-900 rounded-lg border border-cyber-750">
                    <div className="text-xl font-bold text-slate-100">
                      {canonicalManifest.coverage_summary.total_checks_completed}/{canonicalManifest.coverage_summary.total_checks_attempted}
                    </div>
                    <div className="text-[10px] text-slate-400 uppercase mt-1">Probes Completed</div>
                  </div>
                  <div className="p-4 bg-cyber-900 rounded-lg border border-cyber-750">
                    <div className="text-xl font-bold text-accent-cyan">{canonicalManifest.evidence_manifest.length}</div>
                    <div className="text-[10px] text-slate-400 uppercase mt-1">Evidence Artifacts</div>
                  </div>
                </div>

                {/* Export Action Bar */}
                <div className="flex flex-wrap items-center justify-between gap-3 p-4 bg-cyber-900 rounded-lg border border-cyber-750">
                  <div className="text-xs text-slate-300 font-semibold flex items-center gap-2">
                    <Download className="w-4 h-4 text-accent-cyan" />
                    Export Canonical Artifacts:
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    <a
                      href={`/api/v1/projects/${currentProject.id}/assessments/${selectedAssessmentId}/report/export?format=JSON`}
                      target="_blank"
                      rel="noreferrer"
                      className="px-3 py-1.5 bg-cyber-800 hover:bg-cyber-750 text-slate-200 border border-cyber-700 rounded text-xs font-mono transition"
                    >
                      Export JSON
                    </a>
                    <a
                      href={`/api/v1/projects/${currentProject.id}/assessments/${selectedAssessmentId}/report/export?format=HTML`}
                      target="_blank"
                      rel="noreferrer"
                      className="px-3 py-1.5 bg-cyber-800 hover:bg-cyber-750 text-slate-200 border border-cyber-700 rounded text-xs font-mono transition"
                    >
                      Export HTML
                    </a>
                    <a
                      href={`/api/v1/projects/${currentProject.id}/assessments/${selectedAssessmentId}/report/export?format=CSV`}
                      target="_blank"
                      rel="noreferrer"
                      className="px-3 py-1.5 bg-cyber-800 hover:bg-cyber-750 text-slate-200 border border-cyber-700 rounded text-xs font-mono transition"
                    >
                      Export CSV
                    </a>
                    <a
                      href={`/api/v1/projects/${currentProject.id}/assessments/${selectedAssessmentId}/report/export?format=BUNDLE`}
                      target="_blank"
                      rel="noreferrer"
                      className="px-3 py-1.5 bg-accent-cyan/20 hover:bg-accent-cyan/30 text-accent-cyan border border-accent-cyan/40 rounded text-xs font-mono transition font-bold"
                    >
                      Download Bundle (.tar.gz)
                    </a>
                  </div>
                </div>

                {/* Findings Table */}
                <div className="overflow-x-auto">
                  <table className="w-full text-xs text-left">
                    <thead className="bg-cyber-900 text-slate-400 font-semibold uppercase text-[10px] border-b border-cyber-750">
                      <tr>
                        <th className="py-2.5 px-3">Finding / Fingerprint</th>
                        <th className="py-2.5 px-3">Severity</th>
                        <th className="py-2.5 px-3">CVSS</th>
                        <th className="py-2.5 px-3">Status</th>
                        <th className="py-2.5 px-3">Evidence</th>
                        <th className="py-2.5 px-3">Retest Outcome</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-cyber-750 text-slate-200">
                      {canonicalManifest.findings.length === 0 ? (
                        <tr>
                          <td colSpan={6} className="py-6 text-center text-slate-400">
                            No findings detected on this evaluated target.
                          </td>
                        </tr>
                      ) : (
                        canonicalManifest.findings.map((f) => (
                          <tr key={f.id} className="hover:bg-cyber-800/40">
                            <td className="py-2.5 px-3">
                              <div className="font-semibold text-slate-100">{f.title}</div>
                              <div className="text-[10px] text-slate-500 font-mono">{f.fingerprint}</div>
                            </td>
                            <td className="py-2.5 px-3">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                f.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-300 border border-red-500/40' :
                                f.severity === 'HIGH' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' :
                                'bg-blue-500/20 text-blue-300 border border-blue-500/40'
                              }`}>
                                {f.severity}
                              </span>
                            </td>
                            <td className="py-2.5 px-3 font-mono">{f.cvss_score || 'N/A'}</td>
                            <td className="py-2.5 px-3 font-mono text-[11px]">{f.status}</td>
                            <td className="py-2.5 px-3">
                              {f.has_missing_evidence ? (
                                <span className="text-red-400 font-semibold">Missing Payload</span>
                              ) : (
                                <span className="text-emerald-400 font-mono text-[11px]">{f.evidence_refs.length} verified</span>
                              )}
                            </td>
                            <td className="py-2.5 px-3 text-slate-400 text-[11px]">
                              {f.retest_outcome || 'Pending Retest'}
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 3: VERIFY BUNDLE */}
      {activeTab === 'verify' && (
        <div className="bg-cyber-850 p-6 rounded-xl border border-cyber-700 space-y-6">
          <div>
            <h3 className="text-sm font-semibold text-slate-200">Verifiable Assessment Bundle Inspector</h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Inspects exported bundles (.tar.gz) in <strong>validation-only mode</strong>. Checks cryptographic SHA-256 digests, manifest conformity, path traversal safety, and zip bomb limits with zero mutations to live database state.
            </p>
          </div>

          <div className="p-6 bg-cyber-900 border-2 border-dashed border-cyber-700 rounded-xl flex flex-col items-center justify-center text-center space-y-3">
            <Upload className="w-8 h-8 text-accent-cyan" />
            <div className="space-y-1">
              <div className="text-xs font-semibold text-slate-200">Select or drop a portable bundle archive (.tar.gz)</div>
              <div className="text-[11px] text-slate-500">Max size 50 MB. Validates manifest.json, findings.json, sha256sums.txt.</div>
            </div>
            <input
              type="file"
              accept=".tar.gz,.tgz,.tar"
              onChange={handleFileUpload}
              className="text-xs text-slate-400 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-xs file:font-semibold file:bg-cyber-750 file:text-accent-cyan hover:file:bg-cyber-700"
            />
            {bundleFileName && (
              <div className="text-xs text-accent-cyan font-mono">Selected: {bundleFileName}</div>
            )}
          </div>

          <div className="flex justify-end">
            <button
              onClick={handleVerifyBundle}
              disabled={verifying || !bundleBase64}
              className="px-5 py-2.5 bg-accent-cyan hover:bg-cyan-400 disabled:bg-cyber-750 disabled:text-slate-500 text-cyber-900 font-bold rounded-lg text-xs flex items-center gap-2 transition"
            >
              <PackageCheck className="w-4 h-4" />
              {verifying ? 'Inspecting Bundle...' : 'Verify Bundle Integrity (Validation-Only)'}
            </button>
          </div>

          {/* Verification Results Panel */}
          {verificationResult && (
            <div className={`p-6 rounded-xl border space-y-4 ${
              verificationResult.is_valid
                ? 'bg-emerald-500/10 border-emerald-500/30'
                : 'bg-red-500/10 border-red-500/30'
            }`}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  {verificationResult.is_valid ? (
                    <CheckCircle className="w-6 h-6 text-emerald-400" />
                  ) : (
                    <XCircle className="w-6 h-6 text-red-400" />
                  )}
                  <div>
                    <h4 className="text-sm font-bold text-slate-100">
                      {verificationResult.is_valid ? 'Valid Cryptographic Assessment Bundle' : 'Integrity Violations Detected'}
                    </h4>
                    <p className="text-xs text-slate-400 font-mono">
                      Inspection Mode: {verificationResult.inspection_mode} (Guaranteed Zero DB Mutation)
                    </p>
                  </div>
                </div>
                <span className={`px-3 py-1 rounded text-xs font-mono font-bold ${
                  verificationResult.is_valid
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                    : 'bg-red-500/20 text-red-300 border border-red-500/40'
                }`}>
                  {verificationResult.is_valid ? 'QUALIFIED / INTACT' : 'REJECTED / TAMPERED'}
                </span>
              </div>

              {/* Stats */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                <div className="p-3 bg-cyber-900/60 rounded border border-cyber-750">
                  <span className="text-slate-400 block">Manifest Version:</span>
                  <span className="font-mono text-slate-200">{verificationResult.manifest_version || 'N/A'}</span>
                </div>
                <div className="p-3 bg-cyber-900/60 rounded border border-cyber-750">
                  <span className="text-slate-400 block">Member File Count:</span>
                  <span className="font-mono text-slate-200">{verificationResult.file_count}</span>
                </div>
                <div className="p-3 bg-cyber-900/60 rounded border border-cyber-750">
                  <span className="text-slate-400 block">Decompressed Bytes:</span>
                  <span className="font-mono text-slate-200">{(verificationResult.total_decompressed_bytes / 1024).toFixed(1)} KB</span>
                </div>
                <div className="p-3 bg-cyber-900/60 rounded border border-cyber-750">
                  <span className="text-slate-400 block">Verified Files:</span>
                  <span className="font-mono text-emerald-400">{verificationResult.checked_files.length} passed</span>
                </div>
              </div>

              {/* Violations / Corruptions */}
              {verificationResult.violations.length > 0 && (
                <div className="space-y-1">
                  <span className="text-xs font-semibold text-red-300">Safety & Traversal Violations:</span>
                  <ul className="list-disc pl-5 text-xs text-red-400 font-mono space-y-0.5">
                    {verificationResult.violations.map((v, i) => (
                      <li key={i}>{v}</li>
                    ))}
                  </ul>
                </div>
              )}

              {verificationResult.corrupted_files.length > 0 && (
                <div className="space-y-1">
                  <span className="text-xs font-semibold text-red-300">Digest Mismatches (Tampered Files):</span>
                  <div className="flex flex-wrap gap-2">
                    {verificationResult.corrupted_files.map((f, i) => (
                      <span key={i} className="px-2 py-0.5 bg-red-500/20 text-red-300 font-mono text-[11px] rounded border border-red-500/30">
                        {f}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* TAB 4: HISTORICAL LEDGER */}
      {activeTab === 'ledger' && (
        <div className="bg-cyber-850 rounded-xl border border-cyber-700 overflow-hidden">
          <div className="px-6 py-4 border-b border-cyber-750 font-semibold text-sm text-slate-200 flex items-center justify-between">
            <span>Generated Report Ledger & Cryptographic Proofs</span>
            <span className="text-xs text-slate-400 font-mono">Project: {currentProject.id.slice(0, 8)}</span>
          </div>
          <div className="divide-y divide-cyber-750">
            {reports.length === 0 ? (
              <div className="p-8 text-center text-slate-400 text-sm">
                No reports generated for this project yet.
              </div>
            ) : (
              reports.map((rep) => {
                const repFormat = rep.report_format || rep.format || 'JSON';
                const repSha = rep.report_sha256 || rep.content_sha256 || '';
                const repBytes = rep.content_bytes || rep.file_size_bytes || 0;
                const repTime = rep.generated_at || rep.created_at || '';
                return (
                  <div key={rep.id} className="p-6 hover:bg-cyber-800/40 transition flex items-center justify-between">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2.5">
                        <span className="font-semibold text-slate-100 text-sm">{rep.title}</span>
                        <span className="px-2 py-0.5 text-[10px] rounded bg-cyber-750 text-slate-300 font-mono">
                          {rep.report_type}
                        </span>
                        <span className="px-2 py-0.5 text-[10px] rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 font-mono">
                          {repFormat}
                        </span>
                        {rep.assessment_id && (
                          <span className="px-2 py-0.5 text-[10px] rounded bg-accent-cyan/10 text-accent-cyan border border-accent-cyan/30 font-mono">
                            Assessment: {rep.assessment_id.slice(0, 8)}
                          </span>
                        )}
                      </div>
                      <div className="text-xs text-slate-500 font-mono flex flex-wrap items-center gap-4">
                        <span>SHA-256: {repSha}</span>
                        <span>Size: {(repBytes / 1024).toFixed(1)} KB</span>
                        <span>Generated: {repTime ? new Date(repTime).toLocaleString() : 'N/A'}</span>
                      </div>
                    </div>

                    <a
                      href={
                        rep.assessment_id
                          ? `/api/v1/projects/${currentProject.id}/assessments/${rep.assessment_id}/report/export?format=${repFormat}`
                          : `/api/v1/projects/${currentProject.id}/reports/export/${rep.report_type.toLowerCase()}?format=${repFormat}`
                      }
                      target="_blank"
                      rel="noreferrer"
                      className="px-3.5 py-1.5 bg-cyber-750 hover:bg-cyber-700 text-accent-cyan border border-cyber-600 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition shadow"
                    >
                      <Download className="w-3.5 h-3.5" />
                      Export
                    </a>
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}
    </div>
  );
};
