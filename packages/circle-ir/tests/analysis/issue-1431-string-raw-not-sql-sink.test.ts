import { beforeAll, describe, expect, it } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';
import { generateFindings } from '../../src/analysis/findings.js';

const run = async (code: string, file: string) => {
  const r = await analyze(code, file, 'typescript');
  return {
    sinks: r.taint.sinks.map(s => ({ type: s.type, line: s.line })),
    findings: generateFindings(r.taint.sources, r.taint.sinks, r.dfg).map(f => f.type),
  };
};

describe('issue #1431 — String.raw is not a SQL sink', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('does not register String.raw template tags as sql_injection', async () => {
    const r = await run(
      `
const pattern = String.raw\`\\\\b(?:SHA|MD5)\\\\s*\\\\.\\\\s*HashData\\\\s*\\\\(\`;
export function build() {
  return pattern;
}
`,
      'issue-1431.ts',
    );
    expect(r.sinks.filter(s => s.type === 'sql_injection')).toEqual([]);
    expect(r.findings).not.toContain('sql_injection');
  });

  it('still sinks knex.raw(sql) style calls', async () => {
    const r = await run(
      `
export function q(knex: { raw: (s: string) => unknown }, user: string) {
  return knex.raw("SELECT * FROM t WHERE n = '" + user + "'");
}
`,
      'issue-1431-knex.ts',
    );
    expect(r.sinks.some(s => s.type === 'sql_injection' && s.line === 3)).toBe(true);
  });
});