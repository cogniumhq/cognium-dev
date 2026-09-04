import { describe, expect, it } from 'bun:test';
import { dedupeVulnerabilities } from '../src/cli.js';

/**
 * cognium-dev #284 (defect 3) — the CLI maps taint.flows 1:1 to
 * vulnerabilities, so two flows to the same sink (same type + line, different
 * source_line) surfaced the same defect twice. dedupeVulnerabilities collapses
 * by (type, line).
 */
const mk = (over: Partial<any> = {}): any => ({
  type: 'open_redirect', severity: 'medium', message: 'm', line: 4,
  cwe: 'CWE-601', category: 'security', ...over,
});

describe('#284 dedupeVulnerabilities', () => {
  it('collapses two same-(type,line) entries (the res.redirect concat shape) to one', () => {
    const out = dedupeVulnerabilities([
      mk({ message: 'flows from line 3 to line 4' }),
      mk({ message: 'flows from line 4 to line 4' }),
    ]);
    expect(out.length).toBe(1);
    expect(out[0].type).toBe('open_redirect');
    expect(out[0].line).toBe(4);
  });

  it('keeps the highest severity when duplicates disagree', () => {
    const out = dedupeVulnerabilities([mk({ severity: 'medium' }), mk({ severity: 'high' })]);
    expect(out.length).toBe(1);
    expect(out[0].severity).toBe('high');
  });

  it('preserves distinct types at the same line and the same type at different lines', () => {
    const out = dedupeVulnerabilities([
      mk({ type: 'open_redirect', line: 4 }),
      mk({ type: 'crlf', line: 4 }),
      mk({ type: 'open_redirect', line: 9 }),
    ]);
    expect(out.length).toBe(3);
  });

  it('never drops the last entry for a key and preserves order', () => {
    const out = dedupeVulnerabilities([
      mk({ type: 'crlf', line: 4 }),
      mk({ type: 'open_redirect', line: 4 }),
      mk({ type: 'crlf', line: 4 }),
    ]);
    expect(out.map((v: any) => v.type)).toEqual(['crlf', 'open_redirect']);
  });
});
