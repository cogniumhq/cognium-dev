/**
 * `prototype-pollution` (CWE-1321) from browser input: nested computed writes
 * whose keys come from the page URL, the referrer or a window `message`
 * event, directly or through a lazily initialised first level, and recursive
 * merges that a same-file call hands browser input.
 *
 * Fixtures in `tests/fixtures/prototype-pollution/`:
 *   - browser-vulnerable.js — every line marked FLAG gives exactly one finding
 *   - browser-safe.js       — guards, null-prototype roots, `Map`,
 *                             `Object.hasOwn`, allow-lists, constant tables,
 *                             one key, other event sources: zero
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { analyze, initAnalyzer } from '../../../src/analyzer.js';
import { detectPrototypePollution } from '../../../src/analysis/passes/prototype-pollution-pass.js';

const FIXTURES = resolve(dirname(fileURLToPath(import.meta.url)), '../../fixtures/prototype-pollution');
const fixture = (name: string) => readFileSync(resolve(FIXTURES, name), 'utf8');
const hits = (code: string) => detectPrototypePollution(code).map((h) => [h.line, h.shape]);

describe('prototype-pollution: browser input', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('browser-vulnerable.js: one high finding per FLAG line', async () => {
    const code = fixture('browser-vulnerable.js');
    const expected = code.split('\n').flatMap((l, i) => (l.includes('// FLAG') ? [i + 1] : []));
    const r = await analyze(code, 'browser-vulnerable.js', 'javascript');
    const found = (r.findings ?? []).filter((f) => f.rule_id === 'prototype-pollution');
    expect(found.map((f) => f.line)).toEqual(expected);
    expect(found.every((f) => f.cwe === 'CWE-1321' && f.severity === 'high' && f.level === 'error')).toBe(true);
  });

  it('browser-safe.js: no finding', async () => {
    const r = await analyze(fixture('browser-safe.js'), 'browser-safe.js', 'javascript');
    expect((r.findings ?? []).filter((f) => f.rule_id === 'prototype-pollution')).toEqual([]);
  });

  it('TypeScript: annotated bindings and casts', () => {
    const code = [
      'const prefs: Record<string, Record<string, string>> = {};',
      'export function apply(): void {',
      '  const params: URLSearchParams = new URLSearchParams(window.location.search);',
      "  const section = params.get('s') as string;",
      "  const key = params.get('k')!;",
      "  prefs[section] ??= {};",
      "  prefs[section][key] = params.get('v') ?? '';",
      '}',
    ].join('\n');
    expect(hits(code)).toEqual([[7, 'browser-keys']]);
  });

  it('the message names the keys and the browser input', () => {
    const code = [
      "window.addEventListener('message', (event) => {",
      '  const { a, b } = event.data;',
      '  store[a][b] = 1;',
      '});',
    ].join('\n');
    const [h] = detectPrototypePollution(code);
    expect(h).toMatchObject({ line: 3, shape: 'browser-keys', target: 'store', key: 'a, b' });
  });

  it('a recursive merge says where it is handed browser input', () => {
    const code = [
      'function deepMerge(dst, src) {',
      '  for (const [k, v] of Object.entries(src)) {',
      "    if (v && typeof v === 'object') { dst[k] = dst[k] || {}; deepMerge(dst[k], v); } else dst[k] = v;",
      '  }',
      '}',
      'export function load(config) {',
      '  const raw = new URLSearchParams(location.search).get("config");',
      '  deepMerge(config, JSON.parse(raw));',
      '}',
    ].join('\n');
    const [h] = detectPrototypePollution(code);
    expect(h).toMatchObject({ line: 3, shape: 'recursive-merge', inputLine: 8 });
  });

  it('a recursive merge with no untrusted caller stays medium', async () => {
    const code = [
      'export function merge(a, b) {',
      '  for (const k in b) { if (isObj(b[k])) { a[k] = a[k] || {}; merge(a[k], b[k]); } else a[k] = b[k]; }',
      '}',
      'merge(defaults, { theme: { color: "red" } });',
    ].join('\n');
    const r = await analyze(code, 'merge.js', 'javascript');
    const [f] = (r.findings ?? []).filter((x) => x.rule_id === 'prototype-pollution');
    expect(f).toMatchObject({ line: 2, severity: 'medium' });
  });

  it.each([
    ['a guard on the first key', "const p = new URLSearchParams(location.search); const a = p.get('a'); if (a === '__proto__') throw 0; o[a][p.get('b')] = 1;"],
    ['Object.hasOwn on the first key', "function f() { const [a, b] = location.hash.split('/'); if (!Object.hasOwn(o, a)) return; o[a][b] = 1; }"],
    ['a key from a checking function', "function f() { const p = new URLSearchParams(location.search); o[clean(p.get('a'))][p.get('b')] = 1; }"],
    ['navigator input is not page input', 'function f() { const a = navigator.language; const b = navigator.userAgent; o[a][b] = 1; }'],
    ['a click event is not a message', "el.addEventListener('click', (e) => { const { a, b } = e.data; o[a][b] = 1; });"],
    ['a worker port message is not a window message', "port.addEventListener('message', (e) => { const { a, b } = e.data; o[a][b] = 1; });"],
    ['a key rewritten by replace', "function f() { const k = location.hash.slice(1).replace(/[^a-z.]/g, ''); const [a, b] = k.split('.'); o[a][b] = 1; }"],
    ['a value looked up in a cache', "function f() { const p = new URLSearchParams(location.search); const a = cache.get(p.get('a')); o[a][p.get('b')] = 1; }"],
    ['a key rebound to a constant', "function f() { let a = location.hash.slice(1); a = 'theme'; o[a][location.search.slice(1)] = 1; }"],
  ])('%s: no finding', (_label, code) => {
    expect(hits(code)).toEqual([]);
  });
});
