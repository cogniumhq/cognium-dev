/**
 * cognium-dev #1148 — variant stored XSS: module `let store` on the same line as
 * other top-level declarations (v12_stored one-liner layout).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const V12_STORED =
  "// XSS variant: stored — persist then render without escaping.\n" +
  "const express = require('express'); const app = express(); let store = '';\n" +
  "app.post('/c', (req, res) => { store = req.body.comment; res.end(); });\n" +
  "app.get('/c', (req, res) => { res.send('<div>' + store + '</div>'); });";

describe('#1148 variant stored xss (js one-liner module let)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('module let store on a shared top-level line reaches res.send xss', async () => {
    const r = await analyze(V12_STORED, 'v12_stored.js', 'javascript');
    const xss = (r.taint.flows ?? []).filter(f => f.sink_type === 'xss');
    expect(xss.length).toBeGreaterThan(0);
    expect(xss.some(f => f.sink_line === 4)).toBe(true);
  });
});
