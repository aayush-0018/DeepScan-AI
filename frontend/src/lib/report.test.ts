import { describe, expect, it } from 'vitest';
import type { ScanResponse } from './api';
import { allFindings, toMarkdown } from './report';

const finding = (id: string, severity: 'high' | 'medium' | 'low', confidence: number) => ({
  id,
  file: 'a.js',
  function: `fn${id}`,
  function_kind: 'function',
  start_line: 1,
  end_line: 3,
  pattern: 'STRING_CONCAT',
  confidence,
  vulnerable_probability: confidence,
  severity,
  evidence_lines: [2],
  detectors: { ast: confidence },
  message: 'msg',
  code: 'function f() {}',
});

const report: ScanResponse = {
  summary: {
    files_scanned: 1,
    functions_scanned: 3,
    total_findings: 3,
    by_severity: { high: 1, medium: 1, low: 1 },
    by_pattern: { STRING_CONCAT: 3 },
    detector: 'ast',
    model_available: false,
    llm_mode: 'disabled',
    duration_ms: 3,
  },
  files: [
    {
      file: 'a.js',
      language: 'javascript',
      functions_scanned: 3,
      findings: [finding('1', 'low', 0.55), finding('2', 'high', 0.9), finding('3', 'medium', 0.7)],
    },
  ],
};

describe('report helpers', () => {
  it('orders findings by severity then confidence', () => {
    expect(allFindings(report).map((f) => f.id)).toEqual(['2', '3', '1']);
  });

  it('renders a markdown report', () => {
    const md = toMarkdown(report);
    expect(md).toContain('# SQLi Sentinel report');
    expect(md).toContain('[HIGH] STRING_CONCAT in `fn2`');
  });
});
