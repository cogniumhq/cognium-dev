/**
 * cognium-dev #947 — flow-sanitize `log_injection` / `custom_wrapper` / js safe
 * mirror (nightly gates-nightly regression). CRLF-stripping helper must suppress
 * log_injection; partial strip and raw echo still fire.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const logInj = (ir: Awaited<ReturnType<typeof analyze>>) =>
  (ir.taint.flows ?? []).filter((f) => f.sink_type === 'log_injection' && !f.sanitized);

const safeMirror = `const express = require('express');

function stripLogChars(s) {
  return s.replace(/\\r/g, '_').replace(/\\n/g, '_').replace(/\\t/g, '_');
}

const app = express();
app.get('/audit', (req, res) => {
  const user = String(req.query.user ?? '');
  console.log('user=' + stripLogChars(user));
  res.end('ok');
});

module.exports = app;
`;

const partialStrip = `const express = require('express');

function stripSpaces(s) {
  return s.replace(/ /g, '-');
}

const app = express();
app.get('/audit', (req, res) => {
  const user = String(req.query.user ?? '');
  console.log('user=' + stripSpaces(user));
  res.end('ok');
});

module.exports = app;
`;

const tpMirror = `const express = require('express');

const app = express();
app.get('/audit', (req, res) => {
  const user = String(req.query.user ?? '');
  console.log('user=' + user);
  res.end('ok');
});

module.exports = app;
`;

describe('#947 JS custom_wrapper log_injection safe mirror', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('custom_wrapper CRLF strip stays clean for log_injection', async () => {
    const ir = await analyze(safeMirror, 'V06CustomWrapperSafe.js', 'javascript');
    expect(logInj(ir)).toEqual([]);
  });

  it('helper that only strips spaces still fires log_injection', async () => {
    const ir = await analyze(partialStrip, 'V06PartialWrapper.js', 'javascript');
    expect(logInj(ir).length).toBeGreaterThan(0);
  });

  it('recall: raw query in console.log still emits log_injection', async () => {
    const ir = await analyze(tpMirror, 'V01BaselineTp.js', 'javascript');
    expect(logInj(ir).length).toBeGreaterThan(0);
  });
});
