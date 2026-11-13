/**
 * `missing-auth-middleware` (CWE-862) — a state-changing Express route that
 * addresses a record by a path parameter with no authentication middleware,
 * beside guarded routes of the same resource on the same router.
 *
 * Fixtures in `tests/fixtures/missing-auth-middleware/`:
 *   - vulnerable.ts   — every FLAG line gives exactly one finding
 *   - fixed.ts        — the same routes with the middleware added: zero
 *   - safe-shapes.ts  — near misses: zero
 *   - router-level.ts — a `router.use(<auth>)` in the file: zero
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { analyze, initAnalyzer } from '../../../src/analyzer.js';
import { guardKind, middlewareName, resourceOf } from '../../../src/analysis/passes/missing-auth-middleware-pass.js';

const FIXTURES = resolve(dirname(fileURLToPath(import.meta.url)), '../../fixtures/missing-auth-middleware');
const fixture = (name: string) => readFileSync(resolve(FIXTURES, name), 'utf8');

type R = Awaited<ReturnType<typeof analyze>>;
const authz = (r: R) => (r.findings ?? []).filter(f => f.rule_id === 'missing-auth-middleware');

describe('missing-auth-middleware: middleware names', () => {
  it.each([
    ['requireAuth', 'authn'], ['isAuthenticated', 'authn'], ['ensureLoggedIn()', 'authn'],
    ["passport.authenticate('jwt', { session: false })", 'authn'], ['auth.verifyToken', 'authn'],
    ["jwt({ secret: 'x', algorithms: ['HS256'] })", 'authn'], ['protect', 'authn'], ['require_auth', 'authn'],
    ['requireAdmin', 'authz'], ["authorize('admin')", 'authz'], ['security.denyAll()', 'authz'],
    ['validate', null], ['upload.single("f")', null], ['(req, res) => {}', null], ['authorName', null],
  ])('%s → %s', (expr, kind) => {
    expect(guardKind(expr)).toBe(kind);
  });

  it('reads the last name', () => {
    expect(middlewareName('a.b.c(x, y)')).toBe('c');
    expect(middlewareName('x + y')).toBeNull();
  });

  it.each([
    ['/notes/:id', 'notes'], ['/api/v1/accounts/:id', 'accounts'], ['/:id', ''], ['/api/Products/:id', 'products'],
  ])('resource of %s is %s', (path, res) => {
    expect(resourceOf(path)).toBe(res);
  });
});

describe('missing-auth-middleware: fixtures', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('vulnerable.ts: one finding per FLAG line, CWE-862', async () => {
    const code = fixture('vulnerable.ts');
    const expected = code.split('\n').flatMap((l, i) => (l.includes('// FLAG') ? [i + 1] : []));
    const found = authz(await analyze(code, 'vulnerable.ts', 'typescript'));
    expect(found.map(f => f.line).sort((a, b) => a - b)).toEqual(expected);
    for (const f of found) {
      expect(f.cwe).toBe('CWE-862');
      expect(f.category).toBe('security');
    }
  });

  it.each(['fixed.ts', 'safe-shapes.ts', 'router-level.ts'])('%s: no finding', async (name) => {
    expect(authz(await analyze(fixture(name), name, 'typescript'))).toEqual([]);
  });

  it('JavaScript: an Express app', async () => {
    const code = [
      "const express = require('express');",
      "const { ensureLoggedIn } = require('connect-ensure-login');",
      'const app = express();',
      "app.get('/admin/users/:id', ensureLoggedIn(), function showUser(req, res) { res.json({}); });",
      "app.delete('/admin/users/:id', function deleteUser(req, res) { res.sendStatus(204); });",
    ].join('\n');
    expect(authz(await analyze(code, 'app.js', 'javascript')).map(f => f.line)).toEqual([5]);
  });

  it('other languages are not scanned', async () => {
    const code = 'from flask import Flask\napp = Flask(__name__)\n';
    expect(authz(await analyze(code, 'a.py', 'python'))).toEqual([]);
  });

  it('can be disabled', async () => {
    const r = await analyze(fixture('vulnerable.ts'), 'vulnerable.ts', 'typescript', { disabledPasses: ['missing-auth-middleware'] } as never);
    expect(authz(r)).toEqual([]);
  });
});
