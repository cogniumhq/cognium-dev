/**
 * cognium-dev #1244 — flow-combo c08 js custom-wrapper SSRF (expect clean).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/index.js';

const ssrfFlows = (ir: Awaited<ReturnType<typeof analyze>>) =>
  (ir.taint.flows ?? []).filter((f) => f.sink_type === 'ssrf' && !f.sanitized);

const safeMirror = `'use strict';
const express = require('express');
const http = require('http');
const app = express();
const ALLOWED = new Set(['api.internal.example.com']);
function checkedUrl(u) {
  const host = new URL(u).hostname;
  if (!ALLOWED.has(host)) throw new Error('bad host');
  return u;
}
app.get('/wrapped', (req, res) => {
  http.get(checkedUrl(String(req.query.url || '')));
  res.end('ok');
});
module.exports = app;
`;

const noopWrapper = `'use strict';
const http = require('http');
function checkedUrl(u) {
  return u;
}
module.exports = (req) => {
  http.get(checkedUrl(String(req.query.url || '')));
};
`;

const directTp = `'use strict';
const http = require('http');
module.exports = (req) => {
  http.get(String(req.query.url || ''));
};
`;

describe('#1244 flow-combo c08 js SSRF custom-wrapper', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('custom allow-list URL wrapper suppresses ssrf', async () => {
    const ir = await analyze(safeMirror, 'safe_sanitizer_wrapped_ssrf.js', 'javascript');
    expect(ssrfFlows(ir)).toEqual([]);
  });

  it('no-op wrapper still fires ssrf', async () => {
    const ir = await analyze(noopWrapper, 'noop_wrapper_ssrf.js', 'javascript');
    expect(ssrfFlows(ir).length).toBeGreaterThan(0);
  });

  it('direct http.get without wrapper still fires ssrf', async () => {
    const ir = await analyze(directTp, 'direct_ssrf.js', 'javascript');
    expect(ssrfFlows(ir).length).toBeGreaterThan(0);
  });
});