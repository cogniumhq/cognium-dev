/**
 * cognium-dev #1151 — static gates-nightly #107 js: `log_injection` must fire on the
 * canonical string-concat pattern (`user=' + user`), not report clean.
 *
 * Mirrors the sast-validation manifest path
 * `javascript-vuln-demo/fpcorpus/log_injection_tp.js` (not vendored here).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const logInj = (ir: Awaited<ReturnType<typeof analyze>>) =>
  (ir.taint.flows ?? []).filter((f) => f.sink_type === 'log_injection' && !f.sanitized);

/** Minimal shape aligned with gates static #107 js (express handler + concat into console.log). */
const static107JsShape = `const express = require('express');

const app = express();
app.get('/audit', (req, res) => {
  const user = String(req.query.user ?? '');
  console.log('user=' + user);
  res.end('ok');
});

module.exports = app;
`;

/** Minimal shape aligned with static-parity py (`python-vuln-demo/fpcorpus/log_injection_tp.py`). */
const static107PyShape = `from flask import Flask, request
import logging

app = Flask(__name__)

@app.route('/audit')
def audit():
    user = str(request.args.get('user', ''))
    logging.info('user=' + user)
    return 'ok'
`;

describe('#1151 static #107 log_injection regression (static-parity js/py)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('reports log_injection for tainted value concatenated into console.log (js)', async () => {
    const ir = await analyze(static107JsShape, 'Static107LogInjection.js', 'javascript');
    expect(logInj(ir).length).toBeGreaterThan(0);
  });

  it('reports log_injection for tainted value concatenated into logging.info (py)', async () => {
    const ir = await analyze(static107PyShape, 'app.py', 'python');
    expect(logInj(ir).length).toBeGreaterThan(0);
  });
});
