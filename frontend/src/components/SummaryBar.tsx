import type { ScanSummary } from '../lib/api';
import { PATTERN_LABELS } from '../lib/report';

const SEVERITY_STYLES = {
  high: 'text-rose-400',
  medium: 'text-amber-400',
  low: 'text-sky-400',
} as const;

export function SummaryBar({ summary }: { summary: ScanSummary }) {
  return (
    <div className="space-y-3 border-b border-slate-800 p-4">
      <div className="grid grid-cols-4 gap-2 text-center">
        <Stat label="Findings" value={summary.total_findings} className="text-slate-100" />
        {(['high', 'medium', 'low'] as const).map((s) => (
          <Stat key={s} label={s} value={summary.by_severity[s] ?? 0} className={SEVERITY_STYLES[s]} />
        ))}
      </div>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-500">
        <span>
          {summary.files_scanned} file{summary.files_scanned === 1 ? '' : 's'} · {summary.functions_scanned} functions
        </span>
        <span>detector: <b className="font-medium text-slate-300">{summary.detector}</b></span>
        <span>{summary.duration_ms.toFixed(0)} ms</span>
        {Object.entries(summary.by_pattern).map(([p, n]) => (
          <span key={p} className="rounded bg-slate-800 px-1.5 py-0.5 text-slate-400">
            {PATTERN_LABELS[p] ?? p} × {n}
          </span>
        ))}
      </div>
    </div>
  );
}

function Stat({ label, value, className }: { label: string; value: number; className: string }) {
  return (
    <div className="rounded-lg bg-slate-900 py-2">
      <div className={`text-xl font-semibold tabular-nums ${className}`}>{value}</div>
      <div className="text-[11px] uppercase tracking-wide text-slate-500">{label}</div>
    </div>
  );
}
