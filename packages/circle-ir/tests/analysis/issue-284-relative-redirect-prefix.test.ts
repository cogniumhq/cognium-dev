/**
 * cognium-dev #284 defect 1 — `open_redirect` ignored a same-origin literal
 * prefix.
 *
 * `res.redirect('/landing?from=' + tainted)` cannot leave the origin: the
 * literal fixes scheme and host, and the tainted value lands in the query
 * string. The ticket's expected verdict for this shape is "crlf only" — a raw
 * newline in a query value still splits the response header, so `crlf` stays.
 *
 * The rule is deliberately narrow. Two neighbouring shapes are genuinely
 * unsafe and must keep firing: `'//' + x` is protocol-relative, and `'/' + x`
 * can produce `//evil.com` when x itself begins with a slash.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const types = (r: Awaited<ReturnType<typeof analyze>>, t: string) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === t);

const route = (body: string) => [
  'const app = require("express")();',
  'app.get("/r", (req, res) => {',
  `  ${body}`,
  '});',
].join('\n');

describe('#284 open_redirect and a same-origin literal prefix', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('a relative literal prefix with a query drops open_redirect but keeps crlf', async () => {
    const r = await analyze(route('res.redirect("/landing?from=" + req.query.next);'), 'a.js', 'javascript');
    expect(types(r, 'open_redirect')).toEqual([]);
    expect(types(r, 'crlf').length).toBeGreaterThan(0);
  });

  for (const [label, body] of [
    ['a bare tainted target', 'res.redirect(req.query.next);'],
    ['a protocol-relative prefix', 'res.redirect("//" + req.query.next);'],
    ['a bare slash prefix (x may start with /)', 'res.redirect("/" + req.query.next);'],
    ['an absolute prefix', 'res.redirect("https://x.example.com/" + req.query.next);'],
  ] as const) {
    it(`${label} STILL fires open_redirect (recall)`, async () => {
      const r = await analyze(route(body), 'a.js', 'javascript');
      expect(types(r, 'open_redirect').length).toBeGreaterThan(0);
    });
  }

  it('encodeURIComponent on the sink line stays clean for both types', async () => {
    const r = await analyze(
      route('res.redirect("/landing?from=" + encodeURIComponent(req.query.next || ""));'),
      'a.js', 'javascript',
    );
    expect(types(r, 'open_redirect')).toEqual([]);
    expect(types(r, 'crlf')).toEqual([]);
  });
});
