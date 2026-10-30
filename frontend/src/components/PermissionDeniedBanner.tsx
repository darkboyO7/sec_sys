import React from 'react';
import { ShieldX, AlertCircle, ArrowLeft } from 'lucide-react';

export interface PermissionDeniedBannerProps {
  requiredRole?: string;
  currentRole?: string;
  actionName?: string;
  onBack?: () => void;
  className?: string;
}

export const PermissionDeniedBanner: React.FC<PermissionDeniedBannerProps> = ({
  requiredRole = 'LEAD or TESTER',
  currentRole = 'VIEWER',
  actionName = 'perform this privileged operation',
  onBack,
  className = '',
}) => {
  return (
    <div
      role="alert"
      aria-live="assertive"
      className={`bg-red-950/40 border border-red-500/40 rounded-xl p-6 text-slate-100 ${className}`}
    >
      <div className="flex items-start gap-4">
        <div className="p-3 bg-red-500/10 text-red-400 rounded-xl border border-red-500/20" aria-hidden="true">
          <ShieldX className="w-8 h-8" />
        </div>
        <div className="flex-1">
          <div className="flex items-center gap-2">
            <h3 className="text-base font-bold text-red-300">
              Access Restricted — Authorization Required
            </h3>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-red-500/20 text-red-400 border border-red-500/30">
              HTTP 403
            </span>
          </div>

          <p className="text-sm text-slate-300 mt-2">
            You do not possess the required permissions to {actionName}.
          </p>

          <div className="mt-4 p-3 bg-cyber-900/80 border border-cyber-800 rounded-lg flex flex-wrap gap-4 text-xs font-mono">
            <div>
              <span className="text-slate-400">Current Role: </span>
              <span className="text-amber-400 font-semibold">{currentRole}</span>
            </div>
            <div>
              <span className="text-slate-400">Required Role: </span>
              <span className="text-emerald-400 font-semibold">{requiredRole}</span>
            </div>
          </div>

          <div className="flex items-center gap-2 mt-4 text-xs text-slate-400">
            <AlertCircle className="w-4 h-4 text-amber-400 flex-shrink-0" aria-hidden="true" />
            <span>
              Contact your Project Security Lead or System Administrator to elevate your membership role.
            </span>
          </div>

          {onBack && (
            <div className="mt-5">
              <button
                type="button"
                onClick={onBack}
                className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold text-white bg-cyber-800 hover:bg-cyber-750 border border-cyber-700 transition focus:outline-none focus:ring-2 focus:ring-accent-cyan"
              >
                <ArrowLeft className="w-4 h-4" aria-hidden="true" />
                <span>Return to Previous View</span>
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
