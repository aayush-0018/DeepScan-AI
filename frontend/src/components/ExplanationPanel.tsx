import type { Explanation } from '../lib/api';

const FP_STYLES = {
  low: 'bg-emerald-500/10 text-emerald-300',
  medium: 'bg-amber-500/10 text-amber-300',
  high: 'bg-rose-500/10 text-rose-300',
} as const;

export function ExplanationPanel({ explanation }: { explanation: Explanation }) {
  return (
    <div className="mt-3 space-y-3 rounded-lg border border-slate-800 bg-slate-950/60 p-3 text-sm">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className="rounded bg-violet-500/15 px-1.5 py-0.5 font-medium text-violet-300">
          {explanation.source === 'groq' ? `AI · ${explanation.model ?? 'Groq'}` : 'Offline explanation'}
        </span>
        <span className={`rounded px-1.5 py-0.5 ${FP_STYLES[explanation.false_positive_likelihood]}`}>
          false-positive likelihood: {explanation.false_positive_likelihood}
        </span>
      </div>
      <p className="text-slate-200">{explanation.summary}</p>
      <Section title="Why it is vulnerable">
        <p className="text-slate-400">{explanation.why_vulnerable}</p>
      </Section>
      {explanation.attack_example && (
        <Section title="Example attack">
          <code className="block whitespace-pre-wrap break-words rounded bg-slate-900 p-2 font-mono text-xs text-rose-300">
            {explanation.attack_example}
          </code>
        </Section>
      )}
      {explanation.fix_code && (
        <Section title="Suggested fix">
          <pre className="overflow-x-auto rounded bg-slate-900 p-2 font-mono text-xs text-emerald-300">
            {explanation.fix_code}
          </pre>
        </Section>
      )}
      {explanation.note && <p className="text-xs italic text-slate-500">{explanation.note}</p>}
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h4 className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-slate-500">{title}</h4>
      {children}
    </div>
  );
}
