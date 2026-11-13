/**
 * `prototype-pollution` (CWE-1321) — recursive merge, set by path and request-keyed
 * writes on JavaScript / TypeScript.
 *
 * Fixtures in `tests/fixtures/prototype-pollution/`:
 *   - vulnerable.ts — every `// FLAG` line gives exactly one finding
 *   - fixed.ts      — the same helpers with the prototype keys rejected: zero
 *   - near-miss.ts  — shallow copy, deep clone, trie, get-by-path, null-prototype
 *                     target, one request key: zero
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { analyze, initAnalyzer } from '../../../src/analyzer.js';
import { detectPrototypePollution, maskLiterals } from '../../../src/analysis/passes/prototype-pollution-pass.js';

const FIXTURES = resolve(dirname(fileURLToPath(import.meta.url)), '../../fixtures/prototype-pollution');
const fixture = (name: string) => readFileSync(resolve(FIXTURES, name), 'utf8');

type R = Awaited<ReturnType<typeof analyze>>;
const ppFindings = (r: R) => (r.findings ?? []).filter(f => f.rule_id === 'prototype-pollution');
const shapes = (code: string) => detectPrototypePollution(code).map(h => h.shape);

describe('prototype-pollution: detector', () => {
  it('masks strings and comments without moving offsets', () => {
    const code = "const a = '{x}'; // }\nconst b = `}`;";
    const m = maskLiterals(code);
    expect(m.length).toBe(code.length);
    expect(m.includes('}')).toBe(false);
    expect(m.split('\n').length).toBe(2);
  });

  it('recursive merge through Object.entries', () => {
    const code = [
      'function merge(a, b) {',
      '  for (const [k, v] of Object.entries(b)) {',
      "    if (typeof v === 'object') { a[k] = a[k] || {}; merge(a[k], v); } else a[k] = v;",
      '  }',
      '}',
    ].join('\n');
    expect(shapes(code)).toEqual(['recursive-merge']);
  });

  it('recursive merge as a const arrow, recursing in the assignment', () => {
    const code = [
      'const extend = (to, from) => {',
      '  for (const k in from) to[k] = isObj(from[k]) ? extend(to[k] || {}, from[k]) : from[k];',
      '  return to;',
      '};',
    ].join('\n');
    // `extend(to[k] || {}, …)` passes `to[k]` — with `__proto__` that is Object.prototype.
    expect(shapes(code)).toEqual(['recursive-merge']);
  });

  it('set by path with reduce', () => {
    const code = [
      'function setIn(obj, path, value) {',
      "  const keys = path.split('.');",
      '  const last = keys.pop();',
      '  const parent = keys.reduce((o, k) => (o[k] = o[k] || {}), obj);',
      '  parent[last] = value;',
      '}',
    ].join('\n');
    expect(shapes(code)).toEqual(['set-by-path']);
  });

  it('request keys written inline', () => {
    const code = [
      'app.post("/x", function save(req, res) {',
      '  store[req.body.a][req.body.b] = req.body.c;',
      '});',
    ].join('\n');
    expect(shapes(code)).toEqual(['request-keys']);
  });

  it.each([
    ['a guard literal', "function m(t, s) { for (const k in s) { if (k === '__proto__') continue; t[k] = m(t[k], s[k]); } return t; }"],
    ['a membership test', 'function m(t, s) { for (const k in s) { if (DENY.has(k)) continue; t[k] = m(t[k], s[k]); } return t; }'],
    ['a key-check function', 'function m(t, s) { for (const k in s) { if (!isSafeKey(k)) continue; t[k] = m(t[k], s[k]); } return t; }'],
    ['no recursion (shallow)', 'function m(t, s) { for (const k in s) t[k] = s[k]; return t; }'],
    ['recursion on the source only (clone)', 'function c(s) { const o = {}; for (const k in s) o[k] = c(s[k]); return o; }'],
    ['character iteration', 'function ins(n, w) { for (const ch of w.split("")) { n[ch] = n[ch] || {}; n = n[ch]; } }'],
    ['a map filled without walking', "function idx(m, text) { for (const w of text.split(' ')) { m[w] = m[w] || {}; } }"],
    ['a walk whose write key is not from the path', "function f(o, p) { for (const s of p.split('/')) o = o[s]; for (const k in R) o[k] = 1; }"],
    ['a null-prototype target', 'const t = Object.create(null);\nfunction h(req) { const { a, b } = req.body; t[a][b] = 1; }'],
    ['one request key', 'function h(req) { const { a } = req.body; t.x[a] = 1; }'],
    ['request keys compared, not written', 'function h(req) { const { a, b } = req.body; return t[a][b] === 1; }'],
  ])('abstains on %s', (_label, code) => {
    expect(detectPrototypePollution(code)).toEqual([]);
  });
});

describe('prototype-pollution: fixtures', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('vulnerable.ts: one finding per FLAG line, CWE-1321', async () => {
    const code = fixture('vulnerable.ts');
    const expected = code.split('\n').flatMap((l, i) => (l.includes('// FLAG') ? [i + 1] : []));
    const f = ppFindings(await analyze(code, 'vulnerable.ts', 'typescript'));
    expect(f.map(x => x.line).sort((a, b) => a - b)).toEqual(expected);
    expect(expected.length).toBe(4);
    for (const x of f) {
      expect(x.cwe).toBe('CWE-1321');
      expect(x.category).toBe('security');
    }
    expect(f.find(x => (x.evidence as { shape: string }).shape === 'request-keys')?.severity).toBe('high');
    expect(f.filter(x => x.severity === 'medium').length).toBe(3);
  });

  it('fixed.ts: no finding', async () => {
    expect(ppFindings(await analyze(fixture('fixed.ts'), 'fixed.ts', 'typescript'))).toEqual([]);
  });

  it('near-miss.ts: no finding', async () => {
    expect(ppFindings(await analyze(fixture('near-miss.ts'), 'near-miss.ts', 'typescript'))).toEqual([]);
  });

  it('JavaScript is covered too', async () => {
    const code = "function setPref(req, res) {\n  const { section, key, value } = req.body;\n  prefs[section][key] = value;\n}\n";
    expect(ppFindings(await analyze(code, 'a.js', 'javascript')).map(x => x.line)).toEqual([3]);
  });

  it('other languages are out of scope', async () => {
    const code = 'def merge(a, b):\n    for k in b:\n        a[k] = merge(a[k], b[k])\n';
    expect(ppFindings(await analyze(code, 'a.py', 'python'))).toEqual([]);
  });

  it('can be disabled', async () => {
    const r = await analyze(fixture('vulnerable.ts'), 'vulnerable.ts', 'typescript', {
      disabledPasses: ['prototype-pollution'],
    } as never);
    expect(ppFindings(r)).toEqual([]);
  });
});
