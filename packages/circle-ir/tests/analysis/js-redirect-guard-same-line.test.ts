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
import { jsPositiveMembershipTest, jsReassigns, jsSameLineIfCondition, jsUrlHostOf } from '../../src/analysis/passes/sink-filter-pass.js';

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
    ['a one-line exact-match callback', [
      'if (ALLOWED_PREFIXES.some(p => nxt === p)) res.redirect(nxt);',
    ]],
    ['a one-line indexOf allow-list', [
      'if (ALLOWED_PREFIXES.indexOf(nxt) !== -1) res.redirect(nxt);',
    ]],
    ['a one-line host allow-list on a let alias that is not reassigned', [
      'let host = new URL(nxt, "https://x").hostname;',
      'if (ALLOWED_HOSTS.has(host)) res.redirect(nxt);',
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
    ['a one-line guard negated by indexOf === -1', [
      'if (ALLOWED_PREFIXES.indexOf(nxt) === -1) res.redirect(nxt);',
    ]],
    ['a one-line guard negated by === false', [
      'if (ALLOWED_PREFIXES.includes(nxt) === false) res.redirect(nxt);',
    ]],
    ['a parenthesised negated one-line guard', [
      'if ((!ALLOWED_PREFIXES.includes(nxt))) res.redirect(nxt);',
    ]],
    ['a one-line guard that || can bypass', [
      'if (req.query.force || ALLOWED_PREFIXES.includes(nxt)) res.redirect(nxt);',
    ]],
    ['a callback negated by startsWith === false', [
      'if (ALLOWED_PREFIXES.some(p => nxt.startsWith(p) === false)) res.redirect(nxt);',
    ]],
    ['a callback negated by startsWith == false', [
      'if (ALLOWED_PREFIXES.some(p => nxt.startsWith(p) == false)) res.redirect(nxt);',
    ]],
    ['a callback negated by indexOf === -1', [
      'if (ALLOWED_PREFIXES.some(p => nxt.indexOf(p) === -1)) res.redirect(nxt);',
    ]],
    ['a callback negated by indexOf < 0', [
      'if (ALLOWED_PREFIXES.some(p => nxt.indexOf(p) < 0)) res.redirect(nxt);',
    ]],
    ['a callback that compares with !==', [
      'if (ALLOWED_PREFIXES.some(p => nxt !== p)) res.redirect(nxt);',
    ]],
    ['a callback that is always true', [
      'if (ALLOWED_PREFIXES.some(p => true)) res.redirect(nxt);',
    ]],
    ['a one-line "/" prefix test on the value', [
      'if (nxt.startsWith("/")) res.redirect(nxt);',
    ]],
    ['a one-line origin prefix test on the value', [
      'if (nxt.startsWith("https://app.example.com")) res.redirect(nxt);',
    ]],
    ['a one-line substring test on the value', [
      'if (nxt.includes("example.com")) res.redirect(nxt);',
    ]],
    ['a one-line indexOf substring test on the value', [
      'if (nxt.indexOf("example.com") !== -1) res.redirect(nxt);',
    ]],
    ['a one-line match on the value', [
      'if (nxt.match(/example\\.com/)) res.redirect(nxt);',
    ]],
    ['a one-line regex test of the value', [
      'if (/^\\//.test(nxt)) res.redirect(nxt);',
    ]],
    ['a host alias reassigned on its own line', [
      'let host = new URL(nxt, "https://x").hostname;',
      'host = "app.example.com";',
      'if (ALLOWED_HOSTS.has(host)) res.redirect(nxt);',
    ]],
    ['a host alias reassigned on the let line', [
      'let host = new URL(nxt, "https://x").hostname; host = "app.example.com";',
      'if (ALLOWED_HOSTS.has(host)) res.redirect(nxt);',
    ]],
    ['a host endsWith test', [
      'const host = new URL(nxt, "https://x").hostname;',
      'if (host.endsWith("example.com")) res.redirect(nxt);',
    ]],
  ];
  for (const [label, body] of unsafe) {
    for (const [file, lang] of langs) {
      it(`${label} still reports open_redirect and crlf (${lang})`, async () => {
        const r = await analyze(route(...body), file, lang);
        expect(flows(r, 'open_redirect').length).toBeGreaterThan(0);
        expect(flows(r, 'crlf').length).toBeGreaterThan(0);
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

describe('jsPositiveMembershipTest', () => {
  it('accepts one positive membership test', () => {
    for (const c of [
      'ALLOWED.includes(nxt)',
      'ALLOWED_HOSTS.has(host)',
      'A.some(p => nxt.startsWith(p))',
      'A.some((p) => nxt.startsWith(p))',
      'A.some(p => nxt === p)',
      'A.some(p => p === nxt)',
      'A.some(o => new URL(nxt, "https://x").origin === o)',
      'A.indexOf(nxt) !== -1',
      'A.indexOf(nxt) >= 0',
      '(A.includes(nxt))',
      'cfg?.allowed.has(nxt)',
    ]) expect(jsPositiveMembershipTest(c), c).toBe(true);
  });
  it('rejects a negated, compared, or combined condition', () => {
    for (const c of [
      '!A.includes(nxt)',
      '(!A.includes(nxt))',
      'A.indexOf(nxt) === -1',
      'A.indexOf(nxt) < 0',
      'A.indexOf(nxt)',
      'A.includes(nxt) === false',
      'A.includes(nxt) == false',
      'A.includes(nxt) !== true',
      'force || A.includes(nxt)',
      'A.includes(nxt) || force',
      'A.includes(nxt) && ok',
      'A.includes(nxt) ? 1 : 0',
      'A.some(p => !nxt.startsWith(p))',
      'A.includes(nxt) ?? true',
      'ok(nxt)',
      'A.some(p => nxt.startsWith(p) === false)',
      'A.some(p => nxt.startsWith(p) == false)',
      'A.some(p => nxt.indexOf(p) === -1)',
      'A.some(p => nxt.indexOf(p) < 0)',
      'A.some(p => nxt.indexOf(p) >= 0 || true)',
      'A.some(p => nxt !== p)',
      'A.some(p => nxt != p)',
      'A.some(p => true)',
      'A.some(p => nxt.startsWith(q))',
      'A.some(p => nxt.endsWith(p))',
      'A.some(isOk)',
      'A.includes(String(nxt))',
      'A.includes("x")',
    ]) expect(jsPositiveMembershipTest(c), c).toBe(false);
  });
  it('rejects a prefix, substring or regex test on the value itself', () => {
    for (const c of [
      'nxt.startsWith("/")',
      'nxt.startsWith("https://app.example.com")',
      'nxt.includes("example.com")',
      'nxt.indexOf("example.com") !== -1',
      'nxt.match(/example\\.com/)',
      '/^\\//.test(nxt)',
      '/^\\/[a-z]/.test(nxt)',
    ]) expect(jsPositiveMembershipTest(c, ['nxt']), c).toBe(false);
  });
  it('rejects a test whose receiver is the value, given the values', () => {
    expect(jsPositiveMembershipTest('nxt.includes(nxt)', ['nxt'])).toBe(false);
    expect(jsPositiveMembershipTest('req.query.next.includes(other)', ['req.query.next'])).toBe(false);
    expect(jsPositiveMembershipTest('A.includes(other)', ['nxt'])).toBe(false);
    expect(jsPositiveMembershipTest('A.includes(nxt)', ['nxt'])).toBe(true);
    expect(jsPositiveMembershipTest('A.some(p => host.startsWith(p))', ['nxt', 'host'])).toBe(true);
  });
});

describe('jsReassigns', () => {
  it('sees a plain or compound assignment to the name', () => {
    expect(jsReassigns('  host = "x";', 'host')).toBe(true);
    expect(jsReassigns('host += ".evil";', 'host')).toBe(true);
    expect(jsReassigns('x = 1; host = y;', 'host')).toBe(true);
    expect(jsReassigns('host++;', 'host')).toBe(true);
    expect(jsReassigns('[host] = parts;', 'host')).toBe(true);
  });
  it('ignores comparisons, properties and other names', () => {
    expect(jsReassigns('if (host === "x") ok();', 'host')).toBe(false);
    expect(jsReassigns('url.host = "x";', 'host')).toBe(false);
    expect(jsReassigns('hostname = "x";', 'host')).toBe(false);
    expect(jsReassigns('const o = { host: 1 };', 'host')).toBe(false);
    expect(jsReassigns('f(host => host);', 'host')).toBe(false);
  });
});
