import type { ScanResponse } from '../lib/api';
import { allFindings, download, toMarkdown } from '../lib/report';
import { FindingCard } from './FindingCard';
import { SummaryBar } from './SummaryBar';

interface Props {
  report: ScanResponse | null;
  mode: 'editor' | 'upload';
  loading: boolean;
  error: string | null;
  onSelectLine: (line: number) => void;
}

export function ResultsPanel({ report, mode, loading, error, onSelectLine }: Props) {
  if (error) {
    return (
      <div className="m-4 rounded-lg border border-rose-500/30 bg-rose-500/10 p-4 text-sm text-rose-300">
        <p className="font-semibold">Scan failed</p>
        <p className="mt-1 text-rose-300/80">{error}</p>
      </div>
    );
  }
  if (loading) {
    return (
      <div className="flex h-full items-center justify-center text-sm text-slate-500">
        <span className="mr-2 h-4 w-4 animate-spin rounded-full border-2 border-slate-600 border-t-cyan-400" />
        Scanning…
      </div>
    );
  }
  if (!report) {
    return (
      <div className="flex h-full flex-col items-center justify-center px-8 text-center text-sm text-slate-500">
        <p className="font-medium text-slate-400">No scan yet</p>
        <p className="mt-1">Paste code or pick a sample, then press Scan.</p>
      </div>
    );
  }

  const findings = allFindings(report);
  const fileErrors = report.files.filter((f) => f.error);

  return (
    <div className="flex h-full flex-col">
      <SummaryBar summary={report.summary} />
      <div className="flex items-center justify-end gap-2 border-b border-slate-800 px-4 py-2">
        <button
          type="button"
          className="rounded-md px-2 py-1 text-xs text-slate-400 hover:bg-slate-800 hover:text-slate-200"
          onClick={() => download('sqli-report.json', JSON.stringify(report, null, 2), 'application/json')}
        >
          Export JSON
        </button>
        <button
          type="button"
          className="rounded-md px-2 py-1 text-xs text-slate-400 hover:bg-slate-800 hover:text-slate-200"
          onClick={() => download('sqli-report.md', toMarkdown(report), 'text/markdown')}
        >
          Export Markdown
        </button>
      </div>
      <div className="flex-1 space-y-3 overflow-auto p-4">
        {fileErrors.map((f) => (
          <p key={f.file} className="rounded-md bg-amber-500/10 px-3 py-2 text-xs text-amber-300">
            {f.file}: {f.error}
          </p>
        ))}
        {findings.length === 0 ? (
          <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-6 text-center">
            <p className="text-sm font-semibold text-emerald-300">No SQL injection findings</p>
            <p className="mt-1 text-xs text-slate-500">
              Nothing at or above the confidence threshold. Lower it to see weaker signals.
            </p>
          </div>
        ) : (
          findings.map((f) => (
            <FindingCard
              key={`${f.id}-${f.file}`}
              finding={f}
              showFile={mode === 'upload'}
              showCode={mode === 'upload'}
              onSelect={mode === 'editor' ? onSelectLine : undefined}
            />
          ))
        )}
      </div>
    </div>
  );
}
