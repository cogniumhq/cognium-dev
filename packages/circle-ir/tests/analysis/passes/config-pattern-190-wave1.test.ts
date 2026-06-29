/**
 * Sprint 71 — #190 wave 1: 5 of 14 config-pattern misconfig cells.
 *
 * Closes the simplest 5 cells whose fix surface is a single regex pattern
 * in `language-sources-pass.ts`:
 *
 *   1. py  `cors-wildcard-origin`  — subscript-assignment shape:
 *          `resp.headers['Access-Control-Allow-Origin'] = '*'`
 *      (the existing pass keys off `setHeader`/`addHeader` method calls,
 *      which Python apps don't use.)
 *
 *   2. py  `xfo-csp-mismatch`      — correlated subscript assignments:
 *          XFO='DENY'|'SAMEORIGIN' AND CSP `frame-ancestors *|http*`.
 *
 *   3. py  `tls-verify-disabled`   — context-assignment shape:
 *          `ctx.verify_mode = ssl.CERT_NONE` / `ctx.check_hostname = False`.
 *      (the existing detector handles `requests(verify=False)` and
 *      `ssl._create_unverified_context()`, but NOT the post-create
 *      mutation form used by `urllib`.)
 *
 *   4. bash `weak-hash`            — bare `md5` / `sha1` / `md5sum` /
 *          `sha1sum` command in a pipeline (`echo -n "$x" | md5`).
 *
 *   5. rust `tls-verify-disabled`  — `.danger_accept_invalid_certs(true)`
 *          on `reqwest::Client::builder()` (and the hostname variant).
 *
 * Remaining 9 cells stay on #190 for follow-up (Rust hardcoded-credential
 * needs a Rust pattern-finding bootstrap; Java JWT `JWT.decode(...)` needs
 * "no .verify() follow-up" cross-call reasoning; Rust/Go ECB needs cipher
 * mode reasoning; etc.).
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/analyzer.js';

describe('#190 Sprint 71 wave 1 — config-pattern misconfig cells', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const matches = (r: Awaited<ReturnType<typeof analyze>>, rule: string) =>
    (r.findings ?? []).filter(f => f.rule_id === rule);

  // ── 1. Python cors-wildcard-origin (subscript-assignment shape) ─────────

  it('TP — py cors-wildcard-origin via resp.headers[...] = "*"', async () => {
    const code = [
      'from flask import Flask, jsonify',
      'app = Flask(__name__)',
      "@app.route('/api/public')",
      'def public():',
      "    resp = jsonify({'ok': True})",
      "    resp.headers['Access-Control-Allow-Origin'] = '*'",
      '    return resp',
    ].join('\n');
    const r = await analyze(code, 'cors.py', 'python');
    expect(matches(r, 'cors-wildcard-origin').length).toBeGreaterThanOrEqual(1);
  });

  it('TN — py cors with explicit origin does NOT fire', async () => {
    const code = [
      'from flask import Flask, jsonify',
      'app = Flask(__name__)',
      'def public():',
      "    resp = jsonify({'ok': True})",
      "    resp.headers['Access-Control-Allow-Origin'] = 'https://app.example.com'",
      '    return resp',
    ].join('\n');
    const r = await analyze(code, 'cors_ok.py', 'python');
    expect(matches(r, 'cors-wildcard-origin').length).toBe(0);
  });

  // ── 2. Python xfo-csp-mismatch (correlated assignments) ─────────────────

  it('TP — py xfo-csp-mismatch when XFO=DENY and CSP frame-ancestors *', async () => {
    const code = [
      'from flask import Flask',
      'app = Flask(__name__)',
      '@app.after_request',
      'def headers(resp):',
      "    resp.headers['X-Frame-Options'] = 'DENY'",
      "    resp.headers['Content-Security-Policy'] = 'frame-ancestors *'",
      '    return resp',
    ].join('\n');
    const r = await analyze(code, 'xfo.py', 'python');
    expect(matches(r, 'xfo-csp-mismatch').length).toBeGreaterThanOrEqual(1);
  });

  it('TN — py XFO=DENY alone (no CSP frame-ancestors) does NOT fire', async () => {
    const code = [
      'from flask import Flask',
      'app = Flask(__name__)',
      '@app.after_request',
      'def headers(resp):',
      "    resp.headers['X-Frame-Options'] = 'DENY'",
      '    return resp',
    ].join('\n');
    const r = await analyze(code, 'xfo_ok.py', 'python');
    expect(matches(r, 'xfo-csp-mismatch').length).toBe(0);
  });

  // ── 3. Python tls-verify-disabled (ssl context assignment) ──────────────

  it('TP — py tls-verify-disabled via ctx.verify_mode = ssl.CERT_NONE', async () => {
    const code = [
      'import ssl, urllib.request',
      'def fetch(url):',
      '    ctx = ssl.create_default_context()',
      '    ctx.check_hostname = False',
      '    ctx.verify_mode = ssl.CERT_NONE',
      '    return urllib.request.urlopen(url, context=ctx).read()',
    ].join('\n');
    const r = await analyze(code, 'tls.py', 'python');
    expect(matches(r, 'tls-verify-disabled').length).toBeGreaterThanOrEqual(1);
  });

  it('TN — py ssl context with CERT_REQUIRED does NOT fire', async () => {
    const code = [
      'import ssl, urllib.request',
      'def fetch(url):',
      '    ctx = ssl.create_default_context()',
      '    ctx.verify_mode = ssl.CERT_REQUIRED',
      '    return urllib.request.urlopen(url, context=ctx).read()',
    ].join('\n');
    const r = await analyze(code, 'tls_ok.py', 'python');
    expect(matches(r, 'tls-verify-disabled').length).toBe(0);
  });

  // ── 4. Bash weak-hash (md5/sha1 command) ────────────────────────────────

  it('TP — bash weak-hash via md5 command in pipeline', async () => {
    const code = ['#!/bin/bash', 'echo -n "$1" | md5'].join('\n');
    const r = await analyze(code, 'h.sh', 'bash');
    expect(matches(r, 'weak-hash').length).toBeGreaterThanOrEqual(1);
  });

  it('TP — bash weak-hash via sha1sum command', async () => {
    const code = ['#!/bin/bash', 'sha1sum "$1"'].join('\n');
    const r = await analyze(code, 's.sh', 'bash');
    expect(matches(r, 'weak-hash').length).toBeGreaterThanOrEqual(1);
  });

  it('TN — bash sha256sum does NOT fire weak-hash', async () => {
    const code = ['#!/bin/bash', 'sha256sum "$1"'].join('\n');
    const r = await analyze(code, 's2.sh', 'bash');
    expect(matches(r, 'weak-hash').length).toBe(0);
  });

  // ── 5. Rust tls-verify-disabled (reqwest builder) ───────────────────────

  it('TP — rust tls-verify-disabled via danger_accept_invalid_certs(true)', async () => {
    const code = [
      'pub fn client() -> reqwest::Client {',
      '    reqwest::Client::builder().danger_accept_invalid_certs(true).build().unwrap()',
      '}',
    ].join('\n');
    const r = await analyze(code, 'c.rs', 'rust');
    expect(matches(r, 'tls-verify-disabled').length).toBeGreaterThanOrEqual(1);
  });

  it('TN — rust reqwest builder without danger_* does NOT fire', async () => {
    const code = [
      'pub fn client() -> reqwest::Client {',
      '    reqwest::Client::builder().build().unwrap()',
      '}',
    ].join('\n');
    const r = await analyze(code, 'c_ok.rs', 'rust');
    expect(matches(r, 'tls-verify-disabled').length).toBe(0);
  });
});
