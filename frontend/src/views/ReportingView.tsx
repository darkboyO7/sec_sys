import React, { useState, useEffect, useCallback } from 'react';
import { FileText, Download, Plus, RefreshCw } from 'lucide-react';
import { api } from '../services/api';
import type { Project, ReportRecord, ReportType, ReportFormat } from '../types';

interface Props {
  currentProject: Project;
}

export const ReportingView: React.FC<Props> = ({ currentProject }) => {
  const [reports, setReports] = useState<ReportRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [title, setTitle] = useState(`${currentProject.name} Security Assessment Report`);
  const [reportType, setReportType] = useState<ReportType>('EXECUTIVE');
  const [reportFormat, setReportFormat] = useState<ReportFormat>('JSON');
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  const loadReports = useCallback(async () => {
    setLoading(true);
    try {
      const list = await api.listReports(currentProject.id);
      setReports(list);
    } catch (err: any) {
      console.error('Failed to load reports:', err);
    } finally {
      setLoading(false);
    }
  }, [currentProject.id]);

  useEffect(() => {
    loadReports();
  }, [loadReports]);

  const handleGenerate = async () => {
    if (!title.trim()) {
      alert('Please enter a report title.');
      return;
    }
    setGenerating(true);
    try {
      const res = await api.generateReport(currentProject.id, {
        report_type: reportType,
        format: reportFormat,
        title: title.trim(),
      });
      setStatusMessage(`Report generated successfully (SHA-256: ${res.content_sha256.slice(0, 16)}...).`);
      loadReports();
    } catch (err: any) {
      alert(err.message);
    } finally {
      setGenerating(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center bg-cyber-850 p-6 rounded-xl border border-cyber-700">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <FileText className="w-6 h-6 text-accent-cyan" />
            Reporting & Evidence Export
          </h2>
          <p className="text-sm text-slate-400 mt-1">
            Generates Executive, Technical, and Governance reports with SHA-256 integrity digests and CSV formula sanitization (Phase 15).
          </p>
        </div>
        <button
          onClick={loadReports}
          disabled={loading}
          className="px-3.5 py-2 bg-cyber-750 hover:bg-cyber-700 text-slate-200 text-xs rounded-lg flex items-center gap-2 border border-cyber-600 transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {statusMessage && (
        <div className="p-4 bg-accent-cyan/10 border border-accent-cyan/30 text-accent-cyan rounded-lg text-sm flex items-center justify-between">
          <span>{statusMessage}</span>
          <button onClick={() => setStatusMessage(null)} className="text-xs hover:underline">Dismiss</button>
        </div>
      )}

      {/* Generation Form */}
      <div className="bg-cyber-850 p-6 rounded-xl border border-cyber-700 space-y-4">
        <h3 className="text-sm font-semibold text-slate-200">Generate New Report</h3>
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
            <label className="text-xs font-semibold text-slate-400 block mb-1.5">Type</label>
            <select
              value={reportType}
              onChange={(e) => setReportType(e.target.value as ReportType)}
              className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-accent-cyan"
            >
              <option value="EXECUTIVE">Executive Summary</option>
              <option value="TECHNICAL">Technical Findings</option>
              <option value="GOVERNANCE">Governance & Compliance</option>
            </select>
          </div>
          <div>
            <label className="text-xs font-semibold text-slate-400 block mb-1.5">Format</label>
            <select
              value={reportFormat}
              onChange={(e) => setReportFormat(e.target.value as ReportFormat)}
              className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-accent-cyan"
            >
              <option value="JSON">Structured JSON</option>
              <option value="CSV">Sanitized CSV</option>
              <option value="HTML">Rendered HTML</option>
            </select>
          </div>
        </div>
        <div className="flex justify-end">
          <button
            onClick={handleGenerate}
            disabled={generating}
            className="px-5 py-2 bg-accent-cyan hover:bg-cyan-400 text-cyber-900 font-bold rounded-lg text-xs flex items-center gap-2 transition"
          >
            <Plus className="w-4 h-4" />
            {generating ? 'Compiling Report...' : 'Generate Report'}
          </button>
        </div>
      </div>

      {/* Reports Archive */}
      <div className="bg-cyber-850 rounded-xl border border-cyber-700 overflow-hidden">
        <div className="px-6 py-4 border-b border-cyber-750 font-semibold text-sm text-slate-200">
          Generated Report Ledger & Cryptographic Proofs
        </div>
        <div className="divide-y divide-cyber-750">
          {reports.length === 0 ? (
            <div className="p-8 text-center text-slate-400 text-sm">
              No reports generated for this project yet.
            </div>
          ) : (
            reports.map((rep) => (
              <div key={rep.id} className="p-6 hover:bg-cyber-800/40 transition flex items-center justify-between">
                <div className="space-y-1">
                  <div className="flex items-center gap-2.5">
                    <span className="font-semibold text-slate-100 text-sm">{rep.title}</span>
                    <span className="px-2 py-0.5 text-[10px] rounded bg-cyber-750 text-slate-300 font-mono">
                      {rep.report_type}
                    </span>
                    <span className="px-2 py-0.5 text-[10px] rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 font-mono">
                      {rep.format}
                    </span>
                  </div>
                  <div className="text-xs text-slate-500 font-mono flex items-center gap-4">
                    <span>SHA-256: {rep.content_sha256}</span>
                    <span>Size: {(rep.file_size_bytes / 1024).toFixed(1)} KB</span>
                    <span>Generated: {new Date(rep.created_at).toLocaleString()}</span>
                  </div>
                </div>

                <a
                  href={`/api/v1/projects/${currentProject.id}/reports/export/${rep.report_type.toLowerCase()}?format=${rep.format}`}
                  target="_blank"
                  rel="noreferrer"
                  className="px-3 py-1.5 bg-cyber-750 hover:bg-cyber-700 text-accent-cyan border border-cyber-600 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition"
                >
                  <Download className="w-3.5 h-3.5" />
                  Export
                </a>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
