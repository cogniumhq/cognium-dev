/**
 * cognium-dev #241 (non-Java) — real-world sink signatures FN.
 *
 * Java rows (MyBatis ${} + Apache HttpClient factory-receiver SSRF)
 * shipped in 3.160.0. This test suite covers the remaining four rows:
 *
 *   1. asyncpg %-format SQL injection (Python)
 *   2. httpx.get SSRF (Python)
 *   3. Go net/http.Redirect open_redirect
 *   4. Go fasthttp.Get SSRF
 *
 * All four are pure DEFAULT_SINKS gaps closed by additive entries in
 * `config-loader.ts`. This suite pins the sink-firing shape (positive)
 * and the literal-argument guard (negative).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

const countFindingsOfType = (r: any, ruleId: string): number =>
  (r.findings ?? []).filter((f: any) => f.rule_id === ruleId).length;

const hasFlowOfType = (r: any, sinkType: string): boolean =>
  ((r.taint?.flows ?? []) as any[]).some((f) => f.sink_type === sinkType);

const hasSignal = (r: any, ruleId: string, sinkType: string): boolean =>
  hasFlowOfType(r, sinkType) || countFindingsOfType(r, ruleId) > 0;

describe('#241 non-Java sink signatures — 3.161.0', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // ==========================================================================
  // Part 1 — Python asyncpg %-format SQL injection
  // ==========================================================================

  describe('Python asyncpg — Connection.fetchrow with %-format', () => {
    it('TP — HTTP-tainted `name` reaches `conn.fetchrow(query)` as sql_injection', async () => {
      const code = [
        'from fastapi import Request',
        'import asyncpg',
        '',
        'async def get_user(request: Request, conn):',
        '    name = request.query_params["name"]',
        '    query = "SELECT * FROM users WHERE name = \'%s\'" % name',
        '    return await conn.fetchrow(query)',
        '',
      ].join('\n');
      const r = await analyze(code, 'v81_asyncpg_format.py', 'python');
      expect(hasSignal(r, 'sql_injection', 'sql_injection')).toBe(true);
    });

    it('TP — asyncpg `Connection.execute(query)` with tainted format fires sql_injection', async () => {
      const code = [
        'from flask import request',
        'import asyncpg',
        '',
        'async def run(conn):',
        '    uid = request.args["id"]',
        '    q = "DELETE FROM users WHERE id = " + uid',
        '    await conn.execute(q)',
        '',
      ].join('\n');
      const r = await analyze(code, 'asyncpg_execute.py', 'python');
      expect(hasSignal(r, 'sql_injection', 'sql_injection')).toBe(true);
    });

    it('TN — constant SQL literal does NOT fire sql_injection', async () => {
      const code = [
        'import asyncpg',
        '',
        'async def healthcheck(conn):',
        '    return await conn.fetchrow("SELECT 1")',
        '',
      ].join('\n');
      const r = await analyze(code, 'asyncpg_const.py', 'python');
      expect(hasFlowOfType(r, 'sql_injection')).toBe(false);
    });
  });

  // ==========================================================================
  // Part 2 — Python httpx SSRF
  // ==========================================================================

  describe('Python httpx — SSRF sink', () => {
    it('TP — HTTP-tainted `url` reaches `httpx.get(url)` as ssrf', async () => {
      const code = [
        'from flask import request',
        'import httpx',
        '',
        'def fetch():',
        '    url = request.args["url"]',
        '    return httpx.get(url).text',
        '',
      ].join('\n');
      const r = await analyze(code, 'v51_httpx_get.py', 'python');
      expect(hasSignal(r, 'ssrf', 'ssrf')).toBe(true);
    });

    it('TP — HTTP-tainted `url` reaches `httpx.post(url, ...)` as ssrf', async () => {
      const code = [
        'from flask import request',
        'import httpx',
        '',
        'def push():',
        '    url = request.args["url"]',
        '    return httpx.post(url, json={"a": 1})',
        '',
      ].join('\n');
      const r = await analyze(code, 'httpx_post.py', 'python');
      expect(hasSignal(r, 'ssrf', 'ssrf')).toBe(true);
    });

    it('TN — constant URL does NOT fire ssrf', async () => {
      const code = [
        'import httpx',
        '',
        'def health():',
        '    return httpx.get("https://example.com/health").text',
        '',
      ].join('\n');
      const r = await analyze(code, 'httpx_const.py', 'python');
      expect(hasFlowOfType(r, 'ssrf')).toBe(false);
    });
  });

  // ==========================================================================
  // Part 3 — Go net/http.Redirect open_redirect
  // ==========================================================================

  describe('Go net/http.Redirect — open_redirect sink', () => {
    it('TP — HTTP-tainted `next` reaches `http.Redirect(w, r, next, ...)` as open_redirect', async () => {
      const code = [
        'package main',
        '',
        'import "net/http"',
        '',
        'func handler(w http.ResponseWriter, r *http.Request) {',
        '    next := r.URL.Query().Get("next")',
        '    http.Redirect(w, r, next, http.StatusFound)',
        '}',
        '',
      ].join('\n');
      const r = await analyze(code, 'v51_go_http_redirect.go', 'go');
      expect(hasSignal(r, 'open_redirect', 'open_redirect')).toBe(true);
    });

    it('TN — constant redirect target does NOT fire open_redirect', async () => {
      const code = [
        'package main',
        '',
        'import "net/http"',
        '',
        'func handler(w http.ResponseWriter, r *http.Request) {',
        '    http.Redirect(w, r, "/dashboard", http.StatusFound)',
        '}',
        '',
      ].join('\n');
      const r = await analyze(code, 'go_redirect_const.go', 'go');
      expect(hasFlowOfType(r, 'open_redirect')).toBe(false);
    });
  });

  // ==========================================================================
  // Part 4 — Go fasthttp SSRF
  // ==========================================================================

  describe('Go fasthttp — SSRF sink', () => {
    it('TP — HTTP-tainted `url` reaches `fasthttp.Get(nil, url)` as ssrf', async () => {
      const code = [
        'package main',
        '',
        'import (',
        '    "net/http"',
        '    "github.com/valyala/fasthttp"',
        ')',
        '',
        'func handler(w http.ResponseWriter, r *http.Request) {',
        '    url := r.URL.Query().Get("url")',
        '    fasthttp.Get(nil, url)',
        '}',
        '',
      ].join('\n');
      const r = await analyze(code, 'v82_fasthttp_get.go', 'go');
      expect(hasSignal(r, 'ssrf', 'ssrf')).toBe(true);
    });

    it('TN — constant URL does NOT fire fasthttp ssrf', async () => {
      const code = [
        'package main',
        '',
        'import "github.com/valyala/fasthttp"',
        '',
        'func healthcheck() {',
        '    fasthttp.Get(nil, "https://health-check.internal")',
        '}',
        '',
      ].join('\n');
      const r = await analyze(code, 'fasthttp_const.go', 'go');
      expect(hasFlowOfType(r, 'ssrf')).toBe(false);
    });
  });

  // ==========================================================================
  // Recall guards — existing SSRF/SQLi patterns unchanged
  // ==========================================================================

  describe('Recall guards — existing patterns unchanged', () => {
    it('TP retained — Python `requests.get(taint)` still fires ssrf', async () => {
      const code = [
        'from flask import request',
        'import requests',
        '',
        'def fetch():',
        '    url = request.args["url"]',
        '    return requests.get(url).text',
        '',
      ].join('\n');
      const r = await analyze(code, 'requests_get.py', 'python');
      expect(hasSignal(r, 'ssrf', 'ssrf')).toBe(true);
    });

    it('TP retained — Go `http.Get(taint)` still fires ssrf', async () => {
      const code = [
        'package main',
        '',
        'import ("net/http")',
        'func handler(w http.ResponseWriter, r *http.Request) {',
        '  url := r.URL.Query().Get("u")',
        '  _, _ = http.Get(url)',
        '}',
        '',
      ].join('\n');
      const r = await analyze(code, 'http_get.go', 'go');
      expect(hasSignal(r, 'ssrf', 'ssrf')).toBe(true);
    });
  });
});
