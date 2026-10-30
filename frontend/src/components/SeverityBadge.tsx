import React from 'react';
import type { FindingSeverity } from '../types';

export type AssessmentObservationType = 'SIMULATED' | 'LIVE' | 'UNRESOLVED' | 'VERIFIED' | 'CONTRADICTORY';

interface SeverityBadgeProps {
  severity: FindingSeverity | string;
  cvssScore?: number | null;
  className?: string;
  showIcon?: boolean;
}

interface ObservationChipProps {
  type: AssessmentObservationType;
  className?: string;
}

export const SEVERITY_METADATA: Record<string, { label: string; icon: string; bg: string; text: string; border: string; ariaText: string }> = {
  CRITICAL: {
    label: 'CRITICAL',
    icon: '🛑',
    bg: 'bg-red-500/10',
    text: 'text-red-400',
    border: 'border-red-500/30',
    ariaText: 'Severity: Critical',
  },
  HIGH: {
    label: 'HIGH',
    icon: '⚠️',
    bg: 'bg-orange-500/10',
    text: 'text-orange-400',
    border: 'border-orange-500/30',
    ariaText: 'Severity: High',
  },
  MEDIUM: {
    label: 'MEDIUM',
    icon: '🔷',
    bg: 'bg-amber-500/10',
    text: 'text-amber-400',
    border: 'border-amber-500/30',
    ariaText: 'Severity: Medium',
  },
  LOW: {
    label: 'LOW',
    icon: 'ℹ️',
    bg: 'bg-blue-500/10',
    text: 'text-blue-400',
    border: 'border-blue-500/30',
    ariaText: 'Severity: Low',
  },
  INFORMATIONAL: {
    label: 'INFO',
    icon: '🔘',
    bg: 'bg-zinc-500/10',
    text: 'text-zinc-400',
    border: 'border-zinc-500/30',
    ariaText: 'Severity: Informational',
  },
  INFO: {
    label: 'INFO',
    icon: '🔘',
    bg: 'bg-zinc-500/10',
    text: 'text-zinc-400',
    border: 'border-zinc-500/30',
    ariaText: 'Severity: Informational',
  },
};

export const OBSERVATION_METADATA: Record<AssessmentObservationType, { label: string; icon: string; bg: string; text: string; border: string; ariaText: string }> = {
  SIMULATED: {
    label: 'SIMULATED SCENARIO',
    icon: '🧪',
    bg: 'bg-purple-500/10',
    text: 'text-purple-300',
    border: 'border-purple-500/40 border-dashed',
    ariaText: 'Observation: Simulated drill scenario, not live traffic',
  },
  LIVE: {
    label: 'LIVE OBSERVATION',
    icon: '🌐',
    bg: 'bg-emerald-500/10',
    text: 'text-emerald-300',
    border: 'border-emerald-500/30',
    ariaText: 'Observation: Verified live network observation',
  },
  UNRESOLVED: {
    label: 'UNRESOLVED FINDING',
    icon: '⚠️',
    bg: 'bg-rose-500/10',
    text: 'text-rose-300',
    border: 'border-rose-500/30',
    ariaText: 'Status: Unresolved security defect',
  },
  VERIFIED: {
    label: 'VERIFIED REMEDIATED',
    icon: '✅',
    bg: 'bg-teal-500/10',
    text: 'text-teal-300',
    border: 'border-teal-500/30',
    ariaText: 'Status: Verified remediated via independent retest',
  },
  CONTRADICTORY: {
    label: 'CONTRADICTORY OBSERVATION',
    icon: '⚡',
    bg: 'bg-yellow-500/10',
    text: 'text-yellow-300',
    border: 'border-yellow-500/30',
    ariaText: 'Status: Contradictory observation preserved in historical chain',
  },
};

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({
  severity,
  cvssScore,
  className = '',
  showIcon = true,
}) => {
  const normalized = (severity || 'INFO').toUpperCase();
  const meta = SEVERITY_METADATA[normalized] || SEVERITY_METADATA.INFO;

  return (
    <span
      role="status"
      aria-label={`${meta.ariaText}${cvssScore != null ? `, CVSS Score ${cvssScore.toFixed(1)}` : ''}`}
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold border ${meta.bg} ${meta.text} ${meta.border} ${className}`}
    >
      {showIcon && <span aria-hidden="true" className="text-[11px] select-none">{meta.icon}</span>}
      <span>{meta.label}</span>
      {cvssScore != null && (
        <span aria-hidden="true" className="ml-1 opacity-80 font-mono text-[10px]">
          ({cvssScore.toFixed(1)})
        </span>
      )}
    </span>
  );
};

export const ObservationChip: React.FC<ObservationChipProps> = ({
  type,
  className = '',
}) => {
  const meta = OBSERVATION_METADATA[type] || OBSERVATION_METADATA.LIVE;

  return (
    <span
      role="status"
      aria-label={meta.ariaText}
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md text-[11px] font-medium border ${meta.bg} ${meta.text} ${meta.border} ${className}`}
    >
      <span aria-hidden="true" className="text-[10px] select-none">{meta.icon}</span>
      <span>{meta.label}</span>
    </span>
  );
};
