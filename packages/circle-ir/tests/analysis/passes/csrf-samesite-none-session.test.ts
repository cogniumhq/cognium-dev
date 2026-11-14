/**
 * `csrf-samesite-none-session` (CWE-352) — an Express session cookie sent on
 * cross-site requests (`sameSite: 'none'` / `false`) in a file with
 * state-changing routes and no CSRF token or origin check.
 *
 * Fixtures in `tests/fixtures/csrf-samesite-none-session/`:
 *   - vulnerable.ts   — the FLAG line gives exactly one finding
 *   - fixed.ts        — `sameSite: 'lax'`: zero
 *   - safe-shapes.ts, with-token.ts, origin-check.ts, no-routes.ts — zero
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { analyze, initAnalyzer } from '../../../src/analyzer.js';
import { sameSiteSetting } from '../../../src/analysis/passes/csrf-samesite-none-session-pass.js';

const FIXTURES = resolve(dirname(fileURLToPath(import.meta.url)), '../../fixtures/csrf-samesite-none-session');
const fixture = (name: string) => readFileSync(resolve(FIXTURES, name), 'utf8');

type R = Awaited<ReturnType<typeof analyze>>;
const csrf = (r: R) => (r.findings ?? []).filter(f => f.rule_id === 'csrf-samesite-none-session');

describe('csrf-samesite-none-session: sameSite reading', () => {
  it.each([
    ["{ cookie: { sameSite: 'none' } }", 'none'],
    ['{ cookie: { sameSite: "None", secure: true } }', 'none'],
    ['{ sameSite: false }', 'none'],
    ["{ 'sameSite': 'none' }", 'none'],
    ["{ cookie: { sameSite: 'lax' } }", 'set'],
    ["{ sameSite: 'strict' }", 'set'],
    ['{ sameSite: true }', 'set'],
    ["{ sameSite: x ? 'none' : 'lax' }", 'unknown'],
    ['{ sameSite: mode }', 'unknown'],
    ["{ secret: 's' }", null],
    ["{ notSameSite: 'none' }", null],
  ])('%s → %s', (opts, v) => {
    expect(sameSiteSetting(opts)).toBe(v);
  });
});

describe('csrf-samesite-none-session: fixtures', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('vulnerable.ts: one finding on the FLAG line, CWE-352', async () => {
    const code = fixture('vulnerable.ts');
    const expected = code.split('\n').flatMap((l, i) => (l.includes('// FLAG') ? [i + 1] : []));
    const found = csrf(await analyze(code, 'vulnerable.ts', 'typescript'));
    expect(found.map(f => f.line)).toEqual(expected);
    expect(found[0].cwe).toBe('CWE-352');
  });

  it.each(['fixed.ts', 'safe-shapes.ts', 'with-token.ts', 'origin-check.ts', 'no-routes.ts'])('%s: no finding', async (name) => {
    expect(csrf(await analyze(fixture(name), name, 'typescript'))).toEqual([]);
  });

  it('JavaScript: cookie-session with sameSite none', async () => {
    const code = [
      "const express = require('express');",
      "const cookieSession = require('cookie-session');",
      'const app = express();',
      "app.use(cookieSession({ name: 'sid', keys: [process.env.K], sameSite: 'none', secure: true }));",
      "app.post('/profile', function save(req, res) { res.end(); });",
    ].join('\n');
    expect(csrf(await analyze(code, 'app.js', 'javascript')).map(f => f.line)).toEqual([4]);
  });

  it('can be disabled', async () => {
    const r = await analyze(fixture('vulnerable.ts'), 'vulnerable.ts', 'typescript', { disabledPasses: ['csrf-samesite-none-session'] } as never);
    expect(csrf(r)).toEqual([]);
  });
});
