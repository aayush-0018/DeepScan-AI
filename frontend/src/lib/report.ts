import type { Finding, ScanResponse, Severity } from './api';

export const SEVERITY_ORDER: Severity[] = ['high', 'medium', 'low'];

export const PATTERN_LABELS: Record<string, string> = {
  STRING_CONCAT: 'String concatenation',
  TEMPLATE_LITERAL: 'Template literal',
  DYNAMIC_IDENTIFIER: 'Dynamic identifier',
  ORM_RAW_QUERY: 'ORM raw query',
  UNSAFE_FORMAT: 'Unsafe formatting',
  SECOND_ORDER: 'Second-order',
};

export function allFindings(report: ScanResponse): Finding[] {
  return report.files
    .flatMap((f) => f.findings)
    .sort(
      (a, b) =>
        SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || b.confidence - a.confidence,
    );
}

export function pct(value: number): string {
  return `${Math.round(value * 100)}%`;
}

export function toMarkdown(report: ScanResponse): string {
  const s = report.summary;
  const lines = [
    '# SQLi Sentinel report',
    '',
    `- Files scanned: ${s.files_scanned}`,
    `- Functions scanned: ${s.functions_scanned}`,
    `- Findings: ${s.total_findings} (high ${s.by_severity.high}, medium ${s.by_severity.medium}, low ${s.by_severity.low})`,
    `- Detector: ${s.detector}`,
    '',
  ];
  for (const f of allFindings(report)) {
    lines.push(
      `## [${f.severity.toUpperCase()}] ${f.pattern} in \`${f.function}\``,
      '',
      `${f.file}:${f.start_line}-${f.end_line} · confidence ${pct(f.confidence)}` +
        (f.evidence_lines.length ? ` · evidence lines ${f.evidence_lines.join(', ')}` : ''),
      '',
      f.message,
      '',
      '```javascript',
      f.code,
      '```',
      '',
    );
    if (f.explanation) {
      lines.push(
        `**Why:** ${f.explanation.why_vulnerable}`,
        '',
        `**Attack:** \`${f.explanation.attack_example}\``,
        '',
        '**Fix:**',
        '',
        '```javascript',
        f.explanation.fix_code,
        '```',
        '',
      );
    }
  }
  return lines.join('\n');
}

export function download(filename: string, content: string, type: string) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
