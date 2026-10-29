export type DetectorName = 'auto' | 'ensemble' | 'codebert' | 'ast' | 'regex';
export type Severity = 'high' | 'medium' | 'low';

export interface Explanation {
  summary: string;
  why_vulnerable: string;
  attack_example: string;
  fix_code: string;
  false_positive_likelihood: 'low' | 'medium' | 'high';
  source: 'groq' | 'offline';
  model?: string | null;
  note?: string | null;
}

export interface Finding {
  id: string;
  file: string;
  function: string;
  function_kind: string;
  start_line: number;
  end_line: number;
  pattern: string;
  confidence: number;
  vulnerable_probability: number;
  severity: Severity;
  evidence_lines: number[];
  detectors: Record<string, number | null>;
  message: string;
  code: string;
  explanation?: Explanation | null;
}

export interface FileReport {
  file: string;
  language: string;
  functions_scanned: number;
  findings: Finding[];
  error?: string | null;
}

export interface ScanSummary {
  files_scanned: number;
  functions_scanned: number;
  total_findings: number;
  by_severity: Record<Severity, number>;
  by_pattern: Record<string, number>;
  detector: string;
  model_available: boolean;
  llm_mode: 'groq' | 'offline' | 'disabled';
  duration_ms: number;
}

export interface ScanResponse {
  summary: ScanSummary;
  files: FileReport[];
}

export interface ModelInfo {
  model_loaded: boolean;
  model_dir: string;
  labels: string[];
  device: string | null;
  temperature: number | null;
  metrics: Record<string, unknown> | null;
  load_error: string | null;
  detectors: DetectorName[];
  default_detector: string;
}

export interface Health {
  status: string;
  model_loaded: boolean;
  llm_mode: 'groq' | 'offline';
}

export interface ScanOptions {
  detector: DetectorName;
  explain: boolean;
  threshold: number;
}

const BASE = (import.meta.env.VITE_API_BASE_URL as string | undefined)?.replace(/\/$/, '') ?? '';

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const resp = await fetch(`${BASE}${path}`, init);
  if (!resp.ok) {
    let detail = `${resp.status} ${resp.statusText}`;
    try {
      const body = await resp.json();
      if (body?.detail) detail = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* not JSON */
    }
    throw new Error(detail);
  }
  return resp.json() as Promise<T>;
}

export const api = {
  health: () => request<Health>('/api/health'),
  modelInfo: () => request<ModelInfo>('/api/model-info'),

  scanCode: (code: string, filename: string, opts: ScanOptions) =>
    request<ScanResponse>('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, filename, ...opts }),
    }),

  scanFiles: (files: File[], opts: ScanOptions) => {
    const form = new FormData();
    files.forEach((f) => form.append('files', f, f.name));
    form.append('detector', opts.detector);
    form.append('explain', String(opts.explain));
    form.append('threshold', String(opts.threshold));
    return request<ScanResponse>('/api/scan/files', { method: 'POST', body: form });
  },

  explain: (finding: Finding) =>
    request<Explanation>('/api/explain', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        code: finding.code,
        pattern: finding.pattern,
        function: finding.function,
        confidence: finding.confidence,
        evidence_lines: finding.evidence_lines,
      }),
    }),
};
