/**
 * Stage 8a (sink-filter, JS/TS open_redirect and crlf) dropped the sink when ANY
 * `if (… includes|startsWith|endsWith|indexOf|test|match|has (…))` stood within six
 * lines above it, whatever value the check tested. A check on an unrelated value
 * (a user name, a header, a flag) hid a real redirect of raw input.
 *
 * Now the guard must test a value the sink call reads (a dotted name in its
 * argument list). Guards on that value still drop the sink, as before.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';
import { jsSinkArgumentValues } from '../../src/analysis/passes/sink-filter-pass.js';

const flows = (r: Awaited<ReturnType<typeof analyze>>, t: string) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === t);

const route = (...body: string[]) => [
  'const express = require("express");',
  'const app = express();',
  'const ALLOWED = ["/home", "/account"];',
  'app.get("/r", (req, res) => {',
  ...body.map(l => `  ${l}`),
  '});',
].join('\n');

describe('stage 8a: the guard must test the redirected value', () => {
  beforeAll(async () => { await initAnalyzer(); });

  const unrelated: Array<[string, string[]]> = [
    ['a check on another query field', [
      'const next = req.query.next;',
      'if (req.query.lang.startsWith("en")) { res.locals.en = true; }',
      'res.redirect(next);',
    ]],
    ['a check on a header', [
      'const target = req.query.target;',
      'if (req.headers["user-agent"].includes("bot")) { res.status(403); }',
      'res.redirect(target);',
    ]],
    ['an allow-list check on a different variable', [
      'const page = req.query.page;',
      'const next = req.query.next;',
      'if (ALLOWED.includes(page)) { res.locals.page = page; }',
      'res.redirect(next);',
    ]],
  ];
  for (const [label, body] of unrelated) {
    it(`${label} no longer drops open_redirect (JS)`, async () => {
      const r = await analyze(route(...body), 'app.js', 'javascript');
      expect(flows(r, 'open_redirect').length).toBeGreaterThan(0);
    });
    it(`${label} no longer drops open_redirect (TS)`, async () => {
      const r = await analyze(route(...body), 'app.ts', 'typescript');
      expect(flows(r, 'open_redirect').length).toBeGreaterThan(0);
    });
  }

  const related: Array<[string, string[]]> = [
    ['an allow-list on the target', [
      'const target = req.query.target;',
      'if (ALLOWED.includes(target)) {',
      '  res.redirect(target);',
      '}',
    ]],
    ['a Set allow-list on the target', [
      'const target = req.query.target;',
      'if (new Set(ALLOWED).has(target)) {',
      '  res.redirect(target);',
      '}',
    ]],
    ['a reject guard on the target', [
      'const url = req.query.url;',
      'if (!ALLOWED.includes(url)) { return res.status(400).end(); }',
      'res.redirect(url);',
    ]],
    ['a guard on the member path the sink reads', [
      'if (ALLOWED.indexOf(req.query.next) >= 0) {',
      '  res.redirect(req.query.next);',
      '}',
    ]],
  ];
  for (const [label, body] of related) {
    it(`${label} still drops open_redirect (unchanged)`, async () => {
      const r = await analyze(route(...body), 'app.js', 'javascript');
      expect(flows(r, 'open_redirect')).toEqual([]);
    });
  }

  it('recall: a bare redirect of raw input still fires', async () => {
    const r = await analyze(route('res.redirect(req.query.next);'), 'app.js', 'javascript');
    expect(flows(r, 'open_redirect').length).toBeGreaterThan(0);
  });
});

describe('jsSinkArgumentValues', () => {
  it('reads dotted names in the call arguments, not callees or literals', () => {
    expect(jsSinkArgumentValues('  res.redirect(req.query.next.trim());', 'redirect')).toEqual(['req.query.next']);
    expect(jsSinkArgumentValues('res.redirect(302, "/a?x=" + target)', 'redirect')).toEqual(['target']);
    expect(jsSinkArgumentValues('res.setHeader("Location", encodeURI(u))', 'setHeader')).toEqual(['u']);
  });
  it('is empty when the call is not on the line or no method is known', () => {
    expect(jsSinkArgumentValues('res.redirect(x)', undefined)).toEqual([]);
    expect(jsSinkArgumentValues('foo(x)', 'redirect')).toEqual([]);
  });
});
