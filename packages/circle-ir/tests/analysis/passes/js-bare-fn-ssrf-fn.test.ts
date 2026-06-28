import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

/**
 * Sprint 55 — #185 SSRF: `got(taint)` and `request(taint)` bare-function
 * shape produces no ssrf finding. The class-receiver shapes (axios.get,
 * http.get, https.request, etc.) already fire; the FN is restricted to
 * the no-receiver call form for libraries whose default export is a
 * function (`got`, `request`).
 *
 * Recall lock: `request.get(taint)` (member-call form) and `axios.get(taint)`
 * — already-working shapes must keep firing after the bare-fn entries land.
 */
describe('Sprint 55 — #185 bare-fn SSRF', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const countFlows = (r: Awaited<ReturnType<typeof analyze>>, type: string) =>
    (r.taint?.flows ?? []).filter(f => f.sink_type === type).length;

  it('FN — got(req.query.url) bare function must fire ssrf', async () => {
    const code = `const express = require('express');
const got = require('got');
const app = express();
app.get('/p', (req, res) => {
  got(req.query.url);
  res.end();
});`;
    const r = await analyze(code, 'got-bare.js', 'javascript');
    expect(countFlows(r, 'ssrf')).toBeGreaterThanOrEqual(1);
  });

  it('FN — request(req.query.url, cb) bare function must fire ssrf', async () => {
    const code = `const express = require('express');
const request = require('request');
const app = express();
app.get('/p', (req, res) => {
  request(req.query.url, () => res.end());
});`;
    const r = await analyze(code, 'request-bare.js', 'javascript');
    expect(countFlows(r, 'ssrf')).toBeGreaterThanOrEqual(1);
  });

  it('recall — axios.get(req.query.url) member call still fires', async () => {
    const code = `const express = require('express');
const axios = require('axios');
const app = express();
app.get('/p', (req, res) => {
  axios.get(req.query.url);
  res.end();
});`;
    const r = await analyze(code, 'axios.js', 'javascript');
    expect(countFlows(r, 'ssrf')).toBeGreaterThanOrEqual(1);
  });

  it('recall — http.get(req.query.url) core module still fires', async () => {
    const code = `const express = require('express');
const http = require('http');
const app = express();
app.get('/p', (req, res) => {
  http.get(req.query.url, () => res.end());
});`;
    const r = await analyze(code, 'http-get.js', 'javascript');
    expect(countFlows(r, 'ssrf')).toBeGreaterThanOrEqual(1);
  });
});
