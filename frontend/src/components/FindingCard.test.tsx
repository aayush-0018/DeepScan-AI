import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { FindingCard } from './FindingCard';
import type { Finding } from '../lib/api';

const finding: Finding = {
  id: 'f_1',
  file: 'routes/users.js',
  function: 'getUser',
  function_kind: 'function',
  start_line: 10,
  end_line: 14,
  pattern: 'TEMPLATE_LITERAL',
  confidence: 0.95,
  vulnerable_probability: 0.95,
  severity: 'high',
  evidence_lines: [12],
  detectors: { ast: 0.95 },
  message: 'SQL built from request input reaches pool.query',
  code: 'line10\nline11\nline12\nline13\nline14',
  explanation: null,
};

afterEach(() => vi.restoreAllMocks());

describe('FindingCard', () => {
  it('shows severity, pattern, confidence and highlighted evidence line', () => {
    render(<FindingCard finding={finding} showFile showCode />);
    expect(screen.getByText('high')).toBeInTheDocument();
    expect(screen.getByText('Template literal')).toBeInTheDocument();
    expect(screen.getAllByText('95%').length).toBeGreaterThan(0);
    expect(screen.getByText('line12').parentElement).toHaveClass('bg-rose-500/15');
  });

  it('fetches an explanation on demand', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(
        JSON.stringify({
          summary: 'getUser is injectable',
          why_vulnerable: 'interpolation',
          attack_example: "' OR 1=1 --",
          fix_code: 'db.query(sql, [id])',
          false_positive_likelihood: 'low',
          source: 'offline',
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    );
    render(<FindingCard finding={finding} showFile={false} showCode={false} />);
    fireEvent.click(screen.getByText('Explain & suggest fix'));
    await waitFor(() => expect(screen.getByText('getUser is injectable')).toBeInTheDocument());
    expect(screen.getByText('db.query(sql, [id])')).toBeInTheDocument();
  });
});
