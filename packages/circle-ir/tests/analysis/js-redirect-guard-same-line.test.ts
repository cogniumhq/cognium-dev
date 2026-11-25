/**
 * Stage 8a (sink-filter, JS/TS open_redirect and crlf) looked for the guard only
 * on the lines above the sink, so the one-line form
 * `if (ALLOWED_PREFIXES.some(p => nxt.startsWith(p))) res.redirect(nxt);` kept
 * both findings. A host allow-list on `new URL(nxt, base).hostname` was missed
 * too: the guard tests `host`, a value read from the redirected one.
 * (taint-coverage safe mirrors v09_guard_in_variable / v10_allowlist_set, #1246)
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';
import { jsSameLineIfCondition, jsUrlHostOf } from '../../src/analysis/passes/sink-filter-pass.js';

const flows = (r: Awaited<ReturnType<typeof analyze>>, t: string) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === t);

const route = (...body: string[]) => [
  'const express = require("express");',
  'const ALLOWED_PREFIXES = ["https://app.example.com/", "https://cdn.example.com/"];',
  'const ALLOWED_HOSTS = new Set(["app.example.com", "cdn.example.com"]);',
  'const app = express();',
  'app.get("/go", (req, res) => {',
  '  const nxt = String(req.query.next || "");',
  ...body.map(l => `  ${l}`),
  '});',
  'module.exports = app;',
].join('\n');

const langs: Array<[string, 'javascript' | 'typescript']> = [
  ['app.js', 'javascript'],
  ['app.ts', 'typescript'],
];

describe('stage 8a: a guard on the sink line, or on a host read from the value', () => {
  beforeAll(async () => { await initAnalyzer(); });

  const safe: Array<[string, string[]]> = [
    ['a one-line prefix allow-list', [
      'if (ALLOWED_PREFIXES.some(p => nxt.startsWith(p))) res.redirect(nxt);',
      'else res.redirect("/home");',
    ]],
    ['a one-line guard with a brace', [
      'if (ALLOWED_PREFIXES.includes(nxt)) { res.redirect(nxt); }',
    ]],
    ['a host allow-list on new URL(value).hostname', [
      'const host = new URL(nxt, "https://x").hostname;',
      'if (ALLOWED_HOSTS.has(host)) res.redirect(nxt);',
      'else res.redirect("/home");',
    ]],
    ['a host allow-list on the line above the sink', [
      'const host = new URL(nxt).host;',
      'if (ALLOWED_HOSTS.has(host)) {',
      '  res.redirect(nxt);',
      '}',
    ]],
  ];
  for (const [label, body] of safe) {
    for (const [file, lang] of langs) {
      it(`${label} drops open_redirect and crlf (${lang})`, async () => {
        const r = await analyze(route(...body), file, lang);
        expect(flows(r, 'open_redirect')).toEqual([]);
        expect(flows(r, 'crlf')).toEqual([]);
      });
    }
  }

  const unsafe: Array<[string, string[]]> = [
    ['a negated one-line guard', [
      'if (!ALLOWED_PREFIXES.some(p => nxt.startsWith(p))) res.redirect(nxt);',
    ]],
    ['a one-line guard on another value', [
      'if (ALLOWED_HOSTS.has(req.query.lang)) res.redirect(nxt);',
    ]],
    ['a one-line guard whose branch ends before the sink', [
      'if (ALLOWED_PREFIXES.includes(nxt)) res.locals.ok = true; res.redirect(nxt);',
    ]],
    ['a host read from another value', [
      'const host = new URL(String(req.query.other), "https://x").hostname;',
      'if (ALLOWED_HOSTS.has(host)) res.redirect(nxt);',
    ]],
  ];
  for (const [label, body] of unsafe) {
    for (const [file, lang] of langs) {
      it(`${label} still reports open_redirect (${lang})`, async () => {
        const r = await analyze(route(...body), file, lang);
        expect(flows(r, 'open_redirect').length).toBeGreaterThan(0);
      });
    }
  }
});

describe('jsSameLineIfCondition', () => {
  it('returns the condition when it leads straight into the call', () => {
    expect(jsSameLineIfCondition('  if (A.some(p => n.startsWith(p))) res.redirect(n);', 'redirect'))
      .toBe('A.some(p => n.startsWith(p))');
    expect(jsSameLineIfCondition('if (ok(n)) { return res.redirect(n); }', 'redirect')).toBe('ok(n)');
    expect(jsSameLineIfCondition('} else if (A.has(n)) res.redirect(n);', 'redirect')).toBe('A.has(n)');
  });
  it('is undefined for any other shape', () => {
    expect(jsSameLineIfCondition('if (A.has(n)) x = 1; res.redirect(n);', 'redirect')).toBeUndefined();
    expect(jsSameLineIfCondition('res.redirect(n);', 'redirect')).toBeUndefined();
    expect(jsSameLineIfCondition('if (A.has(n) res.redirect(n);', 'redirect')).toBeUndefined();
    expect(jsSameLineIfCondition('if (A.has(n)) res.redirect(n);', undefined)).toBeUndefined();
  });
});

describe('jsUrlHostOf', () => {
  it('reads the host name and the value it is read from', () => {
    expect(jsUrlHostOf('  const host = new URL(nxt, "https://x").hostname;')).toEqual({ name: 'host', of: 'nxt' });
    expect(jsUrlHostOf('let h: string = new URL(req.query.u).host')).toEqual({ name: 'h', of: 'req.query.u' });
    expect(jsUrlHostOf('var o = new URL(u).origin;')).toEqual({ name: 'o', of: 'u' });
  });
  it('is undefined for other reads', () => {
    expect(jsUrlHostOf('const p = new URL(u).pathname;')).toBeUndefined();
    expect(jsUrlHostOf('const h = new URL(String(u)).hostname;')).toBeUndefined();
  });
});
