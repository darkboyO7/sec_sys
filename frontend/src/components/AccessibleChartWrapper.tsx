import React, { useState } from 'react';
import { Table, ChevronDown, ChevronUp } from 'lucide-react';

export interface DataPoint {
  label: string;
  value: number | string;
  secondaryValue?: number | string;
  category?: string;
}

export interface AccessibleChartWrapperProps {
  title: string;
  summary: string;
  data: DataPoint[];
  children: React.ReactNode;
  valueColumnHeader?: string;
  secondaryColumnHeader?: string;
  className?: string;
}

export const AccessibleChartWrapper: React.FC<AccessibleChartWrapperProps> = ({
  title,
  summary,
  data,
  children,
  valueColumnHeader = 'Value',
  secondaryColumnHeader,
  className = '',
}) => {
  const [showTable, setShowTable] = useState(false);
  const tableId = `chart-table-${title.toLowerCase().replace(/[^a-z0-9]/g, '-')}`;

  return (
    <div
      role="region"
      aria-label={`${title} visualization`}
      className={`bg-cyber-900 border border-cyber-750 rounded-xl p-5 ${className}`}
    >
      <div className="flex items-start justify-between mb-4">
        <div>
          <h3 className="text-base font-bold text-white tracking-wide">{title}</h3>
          <p className="text-xs text-slate-400 mt-0.5">{summary}</p>
        </div>
        <button
          type="button"
          onClick={() => setShowTable(!showTable)}
          aria-expanded={showTable}
          aria-controls={tableId}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-accent-cyan bg-accent-cyan/10 hover:bg-accent-cyan/20 border border-accent-cyan/30 transition focus:outline-none focus:ring-2 focus:ring-accent-cyan"
        >
          <Table className="w-3.5 h-3.5" aria-hidden="true" />
          <span>{showTable ? 'Hide Data Table' : 'View Data Table'}</span>
          {showTable ? (
            <ChevronUp className="w-3.5 h-3.5" aria-hidden="true" />
          ) : (
            <ChevronDown className="w-3.5 h-3.5" aria-hidden="true" />
          )}
        </button>
      </div>

      {/* Visual Chart */}
      <div aria-hidden={showTable} className="w-full">
        {children}
      </div>

      {/* Screen Reader & Accessible Fallback Table */}
      {showTable && (
        <div id={tableId} className="mt-4 border-t border-cyber-800 pt-4 animate-in fade-in duration-150">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border border-cyber-750 rounded-lg overflow-hidden">
              <caption className="sr-only">{title} data table summary</caption>
              <thead className="bg-cyber-800/80 text-slate-300 border-b border-cyber-750">
                <tr>
                  <th scope="col" className="py-2.5 px-3 font-semibold">
                    Category / Label
                  </th>
                  <th scope="col" className="py-2.5 px-3 font-semibold text-right">
                    {valueColumnHeader}
                  </th>
                  {secondaryColumnHeader && (
                    <th scope="col" className="py-2.5 px-3 font-semibold text-right">
                      {secondaryColumnHeader}
                    </th>
                  )}
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-800 text-slate-200">
                {data.map((row, idx) => (
                  <tr key={idx} className="hover:bg-cyber-800/40">
                    <th scope="row" className="py-2 px-3 font-normal text-slate-300">
                      {row.label}
                    </th>
                    <td className="py-2 px-3 text-right font-mono text-accent-cyan">
                      {row.value}
                    </td>
                    {secondaryColumnHeader && (
                      <td className="py-2 px-3 text-right font-mono text-slate-400">
                        {row.secondaryValue ?? '—'}
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
