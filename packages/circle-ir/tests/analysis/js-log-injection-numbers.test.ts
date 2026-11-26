/**
 * `log_injection` (CWE-117) on JavaScript / TypeScript, #1305 E2: a value made a
 * number before it is logged (`parseInt`, `parseFloat`, `Number`, `BigInt`, or a
 * local holding `.length`) has no CR/LF and cannot forge a log entry.
 *
 * Fixtures in `tests/fixtures/log-injection/`:
 *   - numbers.ts           — every value logged is a number: zero flows
 *   - numbers-near-miss.ts — a number is computed but the string is logged: still flagged
 *
 * The numeric coercions gain `log_injection` credit only; what they already
 * removed is unchanged, and they still remove nothing for a sink they did not
 * before (a parsed number stays tainted for size-sensitive consumers).
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const FIXTURES = resolve(dirname(fileURLToPath(import.meta.url)), '../fixtures/log-injection');
const fixture = (name: string) => readFileSync(resolve(FIXTURES, name), 'utf8');

type R = Awaited<ReturnType<typeof analyze>>;
const sinkLines = (r: R, type: string) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === type).map(f => f.sink_line).sort((a, b) => a - b);
const flagLines = (code: string) =>
  code.split('\n').flatMap((l, i) => (l.includes('// FLAG') ? [i + 1] : []));

describe('log_injection (CWE-117) on JS/TS: a number cannot forge a log entry (#1305 E2)', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it.each([
    ['numbers.ts', 'typescript'],
    ['numbers.ts', 'javascript'],
  ] as const)('%s as %s: no log_injection flow', async (name, language) => {
    const r = await analyze(fixture(name), name, language);
    expect(sinkLines(r, 'log_injection')).toEqual([]);
  });

  it('numbers-near-miss.ts: the request string logged next to its number is still flagged', async () => {
    const code = fixture('numbers-near-miss.ts');
    const r = await analyze(code, 'numbers-near-miss.ts', 'typescript');
    const flags = flagLines(code);
    expect(flags.length).toBe(2);
    // Distinct lines: the padStart line can carry two flows (two source paths), which is not what this checks.
    expect([...new Set(sinkLines(r, 'log_injection'))]).toEqual(flags);
  });

  it('the same request value logged unchanged is still flagged (positive control)', async () => {
    const code = [
      "import express from 'express';",
      'const app = express();',
      'export function page(req, res) {',
      '  const raw = req.query.page;',
      "  console.log('page ' + raw);",
      "  res.send('ok');",
      '}',
      "app.get('/page', page);",
    ].join('\n');
    const r = await analyze(code, 'raw.ts', 'typescript');
    expect(sinkLines(r, 'log_injection')).toEqual([5]);
  });

  it('the credit is log_injection only: parseFloat still leaves an xss flow, as before', async () => {
    const code = [
      "import express from 'express';",
      'const app = express();',
      'export function show(req, res) {',
      '  const p = parseFloat(req.query.p);',
      "  res.send('<p>' + p + '</p>');",
      '}',
      "app.get('/show', show);",
    ].join('\n');
    const r = await analyze(code, 'float-xss.ts', 'typescript');
    expect(sinkLines(r, 'xss')).toEqual([5]);
  });
});
