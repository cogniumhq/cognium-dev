/**
 * cognium-dev#1145 — `new RegExp` built from `escapeRegExp(tainted)` is a literal
 * match pattern, not ReDoS from tainted regex structure.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

async function redos(code: string) {
  const r = await analyze(code, 'probe.js', 'javascript');
  return (r.taint.flows ?? []).filter((f) => f.sink_type === 'redos');
}

const escaperFn = [
  'function escapeRegExp(s) {',
  "  return s.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&');",
  '}',
].join('\n');

describe('cognium-dev#1145 — escapeRegExp before RegExp constructor', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('concat form is clean', async () => {
    const code = [
      escaperFn,
      'const name = process.argv[2];',
      "const re = new RegExp('^' + escapeRegExp(name) + '$');",
      'console.log(re.test(process.argv[3]));',
    ].join('\n');
    expect(await redos(code)).toHaveLength(0);
  });

  it('template form is clean', async () => {
    const code = [
      escaperFn,
      'const name = process.argv[2];',
      'const re = new RegExp(`\\\\b${escapeRegExp(name)}\\\\b`);',
      'console.log(re.test(process.argv[3]));',
    ].join('\n');
    expect(await redos(code)).toHaveLength(0);
  });

  it('still fires when tainted text is concatenated without escaping', async () => {
    const code = [
      'const name = process.argv[2];',
      "const re = new RegExp('^' + name + '$');",
      'console.log(re.test(process.argv[3]));',
    ].join('\n');
    expect((await redos(code)).length).toBeGreaterThanOrEqual(1);
  });
});
