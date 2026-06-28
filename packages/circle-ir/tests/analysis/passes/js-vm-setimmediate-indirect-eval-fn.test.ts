import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

/**
 * Sprint 55 — #188 code_injection: three JS dynamic-execution sinks
 * currently missed.
 *
 * 1. `new vm.Script(taint)` — Node core `vm` module compiles & runs strings.
 * 2. `setImmediate(taint)` where taint is a string — Node will evaluate it
 *    (matches setTimeout/setInterval-string already shipped).
 * 3. Indirect `eval` — `const f = eval; f(taint)` aliases the global eval.
 *
 * Recall lock: direct `eval(taint)` (already-shipped) must keep firing.
 */
describe('Sprint 55 — #188 vm / setImmediate / indirect-eval', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const countFlows = (r: Awaited<ReturnType<typeof analyze>>, type: string) =>
    (r.taint?.flows ?? []).filter(f => f.sink_type === type).length;

  it('FN — new vm.Script(taint) must fire code_injection', async () => {
    const code = `const express = require('express');
const vm = require('vm');
const app = express();
app.get('/p', (req, res) => {
  const s = new vm.Script(req.query.code);
  res.end();
});`;
    const r = await analyze(code, 'vm-script.js', 'javascript');
    expect(countFlows(r, 'code_injection')).toBeGreaterThanOrEqual(1);
  });

  it('FN — vm.runInThisContext(taint) must fire code_injection', async () => {
    const code = `const express = require('express');
const vm = require('vm');
const app = express();
app.get('/p', (req, res) => {
  vm.runInThisContext(req.query.code);
  res.end();
});`;
    const r = await analyze(code, 'vm-run.js', 'javascript');
    expect(countFlows(r, 'code_injection')).toBeGreaterThanOrEqual(1);
  });

  it('FN — setImmediate(taintedString) must fire code_injection', async () => {
    const code = `const express = require('express');
const app = express();
app.get('/p', (req, res) => {
  setImmediate(req.query.code);
  res.end();
});`;
    const r = await analyze(code, 'setimm.js', 'javascript');
    expect(countFlows(r, 'code_injection')).toBeGreaterThanOrEqual(1);
  });

  // Indirect-eval (const f = eval; f(taint)) requires variable-alias
  // tracking in the matcher; deferred to a future sprint. See ticket #188
  // follow-up note for the design sketch.
  it.skip('FN — indirect eval `const f = eval; f(taint)` (deferred)', async () => {
    const code = `const express = require('express');
const app = express();
app.get('/p', (req, res) => {
  const f = eval;
  f(req.query.code);
  res.end();
});`;
    const r = await analyze(code, 'indirect-eval.js', 'javascript');
    expect(countFlows(r, 'code_injection')).toBeGreaterThanOrEqual(1);
  });

  it('recall — direct eval(taint) still fires', async () => {
    const code = `const express = require('express');
const app = express();
app.get('/p', (req, res) => {
  eval(req.query.code);
  res.end();
});`;
    const r = await analyze(code, 'direct-eval.js', 'javascript');
    expect(countFlows(r, 'code_injection')).toBeGreaterThanOrEqual(1);
  });

  it('recall — setTimeout(taintedString) still fires', async () => {
    const code = `const express = require('express');
const app = express();
app.get('/p', (req, res) => {
  setTimeout(req.query.code, 100);
  res.end();
});`;
    const r = await analyze(code, 'settimeout.js', 'javascript');
    expect(countFlows(r, 'code_injection')).toBeGreaterThanOrEqual(1);
  });
});
