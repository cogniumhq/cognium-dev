/**
 * Tests for cognium-dev #213 — sixth slice: JS/Node + Go sanitizer coverage.
 *
 * Parallel to the 3.185.0 Python sanitizer slice. Adds common JS/Node
 * sanitizer packages (he, sanitize-html, xss, sqlstring, pg-format,
 * xss-filters, entities, crypto.randomUUID) and Go sanitizers
 * (regexp.QuoteMeta, bluemonday, net.ParseIP, sql.Named).
 *
 * Each entry includes `external_taint_escape` in its `removes` list —
 * the CWE-668 fallback fires on any call receiving tainted data that
 * the engine does not otherwise recognize, so a `res.send(sanitizer(x))`
 * flow would otherwise report an external-taint-escape at the sanitizer
 * call site itself.
 */

import { describe, it, beforeAll, expect } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

describe('cognium-dev #213 sixth slice — JS/Node + Go sanitizer coverage', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const hasXssFlow = (r: Awaited<ReturnType<typeof analyze>>) =>
    (r.taint.flows ?? []).some(f => f.sink_type === 'xss');

  const hasSqlFlow = (r: Awaited<ReturnType<typeof analyze>>) =>
    (r.taint.flows ?? []).some(f => f.sink_type === 'sql_injection');

  const hasSanitizerAtLine = (r: Awaited<ReturnType<typeof analyze>>, method: string) =>
    (r.taint.sanitizers ?? []).some(s => s.method?.includes(method));

  // ── JS/Node ──────────────────────────────────────────────────────────

  it('JS — `he.encode(x)` sanitizes xss', async () => {
    const code = `const he = require('he');
const app = require('express')();
app.get('/', (req, res) => {
  const name = req.query.name;
  res.send('<h1>' + he.encode(name) + '</h1>');
});`;
    const r = await analyze(code, 'he.js', 'javascript');
    expect(hasXssFlow(r)).toBe(false);
    expect(hasSanitizerAtLine(r, 'encode')).toBe(true);
  });

  it('JS — bare `sanitizeHtml(x)` sanitizes xss', async () => {
    const code = `const sanitizeHtml = require('sanitize-html');
const app = require('express')();
app.get('/', (req, res) => {
  const html = req.query.html;
  res.send(sanitizeHtml(html));
});`;
    const r = await analyze(code, 'sh.js', 'javascript');
    expect(hasXssFlow(r)).toBe(false);
    expect(hasSanitizerAtLine(r, 'sanitizeHtml')).toBe(true);
  });

  it('JS — bare `xss(x)` (`xss` npm package) sanitizes xss', async () => {
    const code = `const xss = require('xss');
const app = require('express')();
app.get('/', (req, res) => {
  const html = req.query.html;
  res.send(xss(html));
});`;
    const r = await analyze(code, 'xss.js', 'javascript');
    expect(hasXssFlow(r)).toBe(false);
    expect(hasSanitizerAtLine(r, 'xss')).toBe(true);
  });

  it('JS — `SqlString.escape(x)` sanitizes sql_injection', async () => {
    const code = `const SqlString = require('sqlstring');
const mysql = require('mysql');
const conn = mysql.createConnection({});
function h(req) {
  const id = req.query.id;
  conn.query('SELECT * FROM t WHERE id = ' + SqlString.escape(id));
}`;
    const r = await analyze(code, 'sql.js', 'javascript');
    expect(hasSqlFlow(r)).toBe(false);
    expect(hasSanitizerAtLine(r, 'escape')).toBe(true);
  });

  it('JS — `xssFilters.inHTMLData(x)` sanitizes xss', async () => {
    const code = `const xssFilters = require('xss-filters');
const app = require('express')();
app.get('/', (req, res) => {
  const name = req.query.name;
  res.send('<h1>' + xssFilters.inHTMLData(name) + '</h1>');
});`;
    const r = await analyze(code, 'xf.js', 'javascript');
    expect(hasXssFlow(r)).toBe(false);
    expect(hasSanitizerAtLine(r, 'inHTMLData')).toBe(true);
  });

  // ── Go ───────────────────────────────────────────────────────────────

  it('Go — `regexp.QuoteMeta(x)` sanitizes redos + code_injection', async () => {
    const code = `package main
import (
  "regexp"
  "net/http"
)
func h(w http.ResponseWriter, r *http.Request) {
  pat := r.URL.Query().Get("pat")
  regexp.MustCompile(regexp.QuoteMeta(pat)).MatchString("abc")
}`;
    const r = await analyze(code, 'q.go', 'go');
    const bad = (r.taint.flows ?? []).filter(
      f => f.sink_type === 'redos' || f.sink_type === 'code_injection',
    );
    expect(bad.length).toBe(0);
  });

  it('Go — `bluemonday.UGCPolicy().Sanitize(x)` sanitizes xss', async () => {
    const code = `package main
import (
  "net/http"
  "github.com/microcosm-cc/bluemonday"
)
func h(w http.ResponseWriter, r *http.Request) {
  raw := r.URL.Query().Get("html")
  p := bluemonday.UGCPolicy()
  clean := p.Sanitize(raw)
  w.Write([]byte(clean))
}`;
    const r = await analyze(code, 'bm.go', 'go');
    expect(hasXssFlow(r)).toBe(false);
    expect(hasSanitizerAtLine(r, 'Sanitize')).toBe(true);
  });

  it('Go — `net.ParseIP(x)` sanitizes ssrf', async () => {
    const code = `package main
import (
  "net"
  "net/http"
)
func h(w http.ResponseWriter, r *http.Request) {
  ip := r.URL.Query().Get("ip")
  parsed := net.ParseIP(ip)
  http.Get("https://" + parsed.String())
}`;
    const r = await analyze(code, 'ip.go', 'go');
    const ssrf = (r.taint.flows ?? []).filter(f => f.sink_type === 'ssrf');
    expect(ssrf.length).toBe(0);
  });
});
