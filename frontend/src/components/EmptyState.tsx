import React from 'react';
import type { LucideIcon } from 'lucide-react';

interface EmptyStateProps {
  icon: LucideIcon;
  title: string;
  description: string;
  actionLabel?: string;
  onAction?: () => void;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  icon: Icon,
  title,
  description,
  actionLabel,
  onAction,
}) => {
  return (
    <div
      role="status"
      aria-label={`${title}: ${description}`}
      className="flex flex-col items-center justify-center p-8 bg-cyber-850/60 border border-cyber-750/70 rounded-xl text-center my-4"
    >
      <div
        className="w-12 h-12 rounded-xl bg-cyber-800 border border-cyber-700/80 flex items-center justify-center text-cyber-500 mb-3 shadow-inner"
        aria-hidden="true"
      >
        <Icon className="w-6 h-6" />
      </div>
      <h3 className="text-base font-semibold text-slate-200 mb-1">{title}</h3>
      <p className="text-xs text-slate-400 max-w-sm mb-4 leading-relaxed">{description}</p>
      {actionLabel && onAction && (
        <button
          type="button"
          onClick={onAction}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-accent-blue/20 text-accent-blue border border-accent-blue/30 hover:bg-accent-blue/30 transition-colors shadow-sm focus:outline-none focus:ring-2 focus:ring-accent-blue"
        >
          {actionLabel}
        </button>
      )}
    </div>
  );
};
