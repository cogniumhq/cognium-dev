/**
 * `log_injection` (CWE-117) on JavaScript / TypeScript, #1305 E2: a program's own
 * error, caught after a call that took a request value, is not the request value.
 * A source on the last line of a `try` body used to seed the `catch (e)` binding
 * on the next line by line adjacency, so `(e as Error).message` logged was a flow.
 *
 * Fixtures in `tests/fixtures/log-injection/`:
 *   - caught-error.ts           — only the caught error is logged: zero flows
 *   - caught-error-near-miss.ts — the request value is logged in the catch: still flagged
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
  [...new Set((r.taint.flows ?? []).filter(f => f.sink_type === type).map(f => f.sink_line))].sort((a, b) => a - b);
const flagLines = (code: string) =>
  code.split('\n').flatMap((l, i) => (l.includes('// FLAG') ? [i + 1] : []));

describe('log_injection (CWE-117) on JS/TS: a caught error is not the request value (#1305 E2)', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it.each([
    ['caught-error.ts', 'typescript'],
    ['caught-error.ts', 'javascript'],
  ] as const)('%s as %s: no log_injection flow', async (name, language) => {
    const r = await analyze(fixture(name), name, language);
    expect(sinkLines(r, 'log_injection')).toEqual([]);
  });

  it('caught-error-near-miss.ts: the request value logged in the catch is still flagged', async () => {
    const code = fixture('caught-error-near-miss.ts');
    const r = await analyze(code, 'caught-error-near-miss.ts', 'typescript');
    const flags = flagLines(code);
    expect(flags.length).toBe(2);
    expect(sinkLines(r, 'log_injection')).toEqual(flags);
  });

  it('a local declared on the line after a source is still seeded (adjacency kept outside catch)', async () => {
    const code = [
      "import express from 'express';",
      'const app = express();',
      'export function page(req, res) {',
      '  const raw = req.query',
      '    .page;',
      "  console.log('page ' + raw);",
      "  res.send('ok');",
      '}',
      "app.get('/page', page);",
    ].join('\n');
    const r = await analyze(code, 'wrapped.ts', 'typescript');
    expect(sinkLines(r, 'log_injection')).toEqual([6]);
  });
});
