import { useEffect, useState } from 'react';
import { api, type DetectorName, type Health, type ModelInfo, type ScanResponse } from './lib/api';
import { SAMPLES } from './lib/samples';
import { CodeEditor } from './components/CodeEditor';
import { ResultsPanel } from './components/ResultsPanel';
import { Uploader } from './components/Uploader';

const DETECTOR_LABELS: Record<DetectorName, string> = {
  auto: 'Auto',
  ensemble: 'Ensemble (CodeBERT + AST)',
  codebert: 'CodeBERT',
  ast: 'AST rules',
  regex: 'Regex baseline',
};

export default function App() {
  const [mode, setMode] = useState<'editor' | 'upload'>('editor');
  const [code, setCode] = useState(SAMPLES[0].code);
  const [filename, setFilename] = useState(SAMPLES[0].filename);
  const [files, setFiles] = useState<File[]>([]);
  const [detector, setDetector] = useState<DetectorName>('auto');
  const [threshold, setThreshold] = useState(0.5);
  const [explain, setExplain] = useState(false);
  const [report, setReport] = useState<ScanResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [focus, setFocus] = useState<{ line: number; nonce: number } | null>(null);
  const [health, setHealth] = useState<Health | null>(null);
  const [modelInfo, setModelInfo] = useState<ModelInfo | null>(null);
  const [backendDown, setBackendDown] = useState(false);

  useEffect(() => {
    Promise.all([api.health(), api.modelInfo()])
      .then(([h, m]) => {
        setHealth(h);
        setModelInfo(m);
      })
      .catch(() => setBackendDown(true));
  }, []);

  const language = /\.tsx?$/.test(filename) ? 'typescript' : 'javascript';
  const detectors: DetectorName[] = modelInfo?.detectors ?? ['auto', 'ast', 'regex'];
  const editorReport = mode === 'editor' ? report : null;

  async function scan() {
    setLoading(true);
    setError(null);
    try {
      const opts = { detector, explain, threshold };
      const result =
        mode === 'editor' ? await api.scanCode(code, filename, opts) : await api.scanFiles(files, opts);
      setReport(result);
    } catch (e) {
      setError((e as Error).message);
      setReport(null);
    } finally {
      setLoading(false);
    }
  }

  function loadSample(id: string) {
    const sample = SAMPLES.find((s) => s.id === id);
    if (!sample) return;
    setCode(sample.code);
    setFilename(sample.filename);
    setReport(null);
  }

  const canScan = !loading && (mode === 'editor' ? code.trim().length > 0 : files.length > 0);

  return (
    <div className="flex h-screen flex-col">
      <header className="flex items-center justify-between border-b border-slate-800 px-5 py-3">
        <div className="flex items-center gap-3">
          <img src="/shield.svg" alt="" className="h-7 w-7" />
          <div>
            <h1 className="text-base font-semibold tracking-tight text-slate-100">SQLi Sentinel</h1>
            <p className="text-xs text-slate-500">SQL injection detection for JavaScript & TypeScript</p>
          </div>
        </div>
        <div className="flex items-center gap-2 text-xs">
          {backendDown ? (
            <Badge tone="rose">Backend unreachable</Badge>
          ) : (
            <>
              <Badge tone={health?.model_loaded ? 'emerald' : 'amber'}>
                {health ? (health.model_loaded ? 'CodeBERT loaded' : 'CodeBERT not trained · AST mode') : '…'}
              </Badge>
              <Badge tone={health?.llm_mode === 'groq' ? 'violet' : 'slate'}>
                {health ? (health.llm_mode === 'groq' ? 'Groq LLM' : 'LLM: offline placeholder') : '…'}
              </Badge>
            </>
          )}
        </div>
      </header>

      <div className="flex flex-wrap items-center gap-3 border-b border-slate-800 px-5 py-2.5 text-sm">
        <div className="flex rounded-lg bg-slate-900 p-0.5">
          {(['editor', 'upload'] as const).map((m) => (
            <button
              key={m}
              type="button"
              onClick={() => {
                setMode(m);
                setReport(null);
                setError(null);
              }}
              className={`rounded-md px-3 py-1 text-xs font-medium capitalize ${
                mode === m ? 'bg-slate-700 text-slate-100' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {m === 'editor' ? 'Paste code' : 'Upload files'}
            </button>
          ))}
        </div>

        {mode === 'editor' && (
          <>
            <select
              aria-label="Sample"
              className="rounded-md border border-slate-700 bg-slate-900 px-2 py-1 text-xs"
              defaultValue=""
              onChange={(e) => loadSample(e.target.value)}
            >
              <option value="" disabled>
                Load sample…
              </option>
              {SAMPLES.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.label}
                </option>
              ))}
            </select>
            <input
              aria-label="Filename"
              value={filename}
              onChange={(e) => setFilename(e.target.value)}
              className="w-40 rounded-md border border-slate-700 bg-slate-900 px-2 py-1 font-mono text-xs"
            />
          </>
        )}

        <label className="flex items-center gap-2 text-xs text-slate-400">
          Detector
          <select
            value={detector}
            onChange={(e) => setDetector(e.target.value as DetectorName)}
            className="rounded-md border border-slate-700 bg-slate-900 px-2 py-1 text-xs text-slate-200"
          >
            {detectors.map((d) => (
              <option key={d} value={d}>
                {DETECTOR_LABELS[d]}
              </option>
            ))}
          </select>
        </label>

        <label className="flex items-center gap-2 text-xs text-slate-400">
          Threshold
          <input
            type="range"
            min={0}
            max={0.95}
            step={0.05}
            value={threshold}
            onChange={(e) => setThreshold(Number(e.target.value))}
            className="w-24 accent-cyan-400"
          />
          <span className="w-8 tabular-nums text-slate-300">{Math.round(threshold * 100)}%</span>
        </label>

        <label className="flex cursor-pointer items-center gap-2 text-xs text-slate-400">
          <input
            type="checkbox"
            checked={explain}
            onChange={(e) => setExplain(e.target.checked)}
            className="accent-violet-400"
          />
          Explain with LLM
        </label>

        <button
          type="button"
          onClick={scan}
          disabled={!canScan}
          className="ml-auto rounded-lg bg-cyan-500 px-4 py-1.5 text-sm font-semibold text-slate-950 hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {loading ? 'Scanning…' : 'Scan'}
        </button>
      </div>

      <main className="grid min-h-0 flex-1 grid-cols-1 lg:grid-cols-[minmax(0,1fr)_480px]">
        <section className="min-h-[320px] border-b border-slate-800 lg:border-b-0 lg:border-r">
          {mode === 'editor' ? (
            <CodeEditor
              value={code}
              language={language}
              onChange={setCode}
              findings={editorReport?.files[0]?.findings ?? []}
              focus={focus}
            />
          ) : (
            <Uploader files={files} onChange={setFiles} />
          )}
        </section>
        <aside className="min-h-0 overflow-hidden">
          <ResultsPanel
            report={report}
            mode={mode}
            loading={loading}
            error={error}
            onSelectLine={(line) => setFocus((prev) => ({ line, nonce: (prev?.nonce ?? 0) + 1 }))}
          />
        </aside>
      </main>
    </div>
  );
}

const TONES = {
  emerald: 'bg-emerald-500/10 text-emerald-300 ring-emerald-500/20',
  amber: 'bg-amber-500/10 text-amber-300 ring-amber-500/20',
  rose: 'bg-rose-500/10 text-rose-300 ring-rose-500/20',
  violet: 'bg-violet-500/10 text-violet-300 ring-violet-500/20',
  slate: 'bg-slate-500/10 text-slate-300 ring-slate-500/20',
} as const;

function Badge({ tone, children }: { tone: keyof typeof TONES; children: React.ReactNode }) {
  return <span className={`rounded-full px-2.5 py-1 ring-1 ${TONES[tone]}`}>{children}</span>;
}
