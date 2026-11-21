/**
 * cognium-dev#1326 — supertest `request(app)` is in-process, not SSRF.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const SUPER_REPRO = `
var request = require('supertest');
var app = require('./app');
it('x', function (done) {
  request(app)
    .post('/login')
    .expect(302, done);
});
`;

const AXIOS_REPRO = `
const axios = require('axios');
const express = require('express');
const app = express();
app.get('/u', async (req, res) => {
  const r = await axios.request(req.query.url);
  res.json(r.data);
});
`;

async function ssrfFlows(code: string, file = 't.js') {
  const r = await analyze(code, file, 'javascript');
  return (r.taint?.flows ?? []).filter((f) => f.sink_type === 'ssrf');
}

describe('cognium-dev#1326 — supertest request(app) is not SSRF', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('supertest request(app) produces no ssrf flow', async () => {
    expect(await ssrfFlows(SUPER_REPRO)).toHaveLength(0);
  });

  it('axios.request(url) still reports ssrf', async () => {
    expect(await ssrfFlows(AXIOS_REPRO).then((f) => f.length)).toBeGreaterThan(0);
  });
});