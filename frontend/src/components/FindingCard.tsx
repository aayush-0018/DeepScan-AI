import { useState } from 'react';
import { api, type Explanation, type Finding } from '../lib/api';
import { PATTERN_LABELS, pct } from '../lib/report';
import { ExplanationPanel } from './ExplanationPanel';

const SEVERITY = {
  high: { pill: 'bg-rose-500/15 text-rose-300 ring-rose-500/30', bar: 'bg-rose-500' },
  medium: { pill: 'bg-amber-500/15 text-amber-300 ring-amber-500/30', bar: 'bg-amber-500' },
  low: { pill: 'bg-sky-500/15 text-sky-300 ring-sky-500/30', bar: 'bg-sky-500' },
} as const;

interface Props {
  finding: Finding;
  showFile: boolean;
  showCode: boolean;
  onSelect?: (line: number) => void;
}

export function FindingCard({ finding, showFile, showCode, onSelect }: Props) {
  const [explanation, setExplanation] = useState<Explanation | null>(finding.explanation ?? null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState(Boolean(finding.explanation));
  const style = SEVERITY[finding.severity];

  async function explain() {
    if (explanation) {
      setOpen((o) => !o);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      setExplanation(await api.explain(finding));
      setOpen(true);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }

  const detectorScores = Object.entries(finding.detectors).filter(([, v]) => v !== null);

  return (
    <article className="rounded-xl border border-slate-800 bg-slate-900/60 p-4" data-testid="finding-card">
      <header className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className={`rounded-md px-2 py-0.5 text-xs font-semibold uppercase ring-1 ${style.pill}`}>
              {finding.severity}
            </span>
            <span className="text-sm font-semibold text-slate-100">{PATTERN_LABELS[finding.pattern] ?? finding.pattern}</span>
          </div>
          <button
            type="button"
            onClick={() => onSelect?.(finding.evidence_lines[0] ?? finding.start_line)}
            className="mt-1 block truncate text-left font-mono text-xs text-cyan-300 hover:underline"
            title="Jump to code"
          >
            {finding.function}
            <span className="text-slate-500">
              {' '}
              · {showFile ? `${finding.file}:` : 'L'}
              {finding.start_line}–{finding.end_line}
            </span>
          </button>
        </div>
        <div className="w-24 shrink-0 text-right">
          <div className="text-sm font-semibold tabular-nums text-slate-100">{pct(finding.confidence)}</div>
          <div className="mt-1 h-1.5 rounded-full bg-slate-800">
            <div className={`h-1.5 rounded-full ${style.bar}`} style={{ width: pct(finding.confidence) }} />
          </div>
          <div className="mt-1 text-[10px] uppercase tracking-wide text-slate-500">confidence</div>
        </div>
      </header>

      <p className="mt-3 text-sm text-slate-400">{finding.message}</p>

      <div className="mt-2 flex flex-wrap gap-1.5 text-[11px]">
        {finding.evidence_lines.length > 0 && (
          <span className="rounded bg-slate-800 px-1.5 py-0.5 text-slate-400">
            evidence: line{finding.evidence_lines.length > 1 ? 's' : ''} {finding.evidence_lines.join(', ')}
          </span>
        )}
        {detectorScores.map(([name, score]) => (
          <span key={name} className="rounded bg-slate-800 px-1.5 py-0.5 text-slate-400">
            {name} {pct(score as number)}
          </span>
        ))}
      </div>

      {showCode && (
        <pre className="mt-3 max-h-64 overflow-auto rounded-lg bg-slate-950 p-3 font-mono text-xs leading-relaxed">
          {finding.code.split('\n').map((line, i) => {
            const n = finding.start_line + i;
            const hit = finding.evidence_lines.includes(n);
            return (
              <div key={n} className={hit ? 'bg-rose-500/15' : undefined}>
                <span className="mr-3 inline-block w-8 select-none text-right text-slate-600">{n}</span>
                <span className="text-slate-300">{line}</span>
              </div>
            );
          })}
        </pre>
      )}

      <div className="mt-3">
        <button
          type="button"
          onClick={explain}
          disabled={loading}
          className="rounded-md bg-violet-500/15 px-3 py-1.5 text-xs font-medium text-violet-200 hover:bg-violet-500/25 disabled:opacity-50"
        >
          {loading ? 'Explaining…' : explanation ? (open ? 'Hide explanation' : 'Show explanation') : 'Explain & suggest fix'}
        </button>
        {error && <p className="mt-2 text-xs text-rose-400">{error}</p>}
        {explanation && open && <ExplanationPanel explanation={explanation} />}
      </div>
    </article>
  );
}
