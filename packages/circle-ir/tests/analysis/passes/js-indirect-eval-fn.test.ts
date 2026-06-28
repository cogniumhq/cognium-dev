import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

/**
 * Sprint 58 — #188 (final): indirect-eval alias detection.
 *
 * Closes the last remaining gap from the #188 batch (Sprint 55 shipped
 * `new vm.Script(taint)`, `setImmediate(taint)`, `vm.runInThisContext`
 * and explicitly deferred `const f = eval; f(taint)` to a future sprint
 * pending alias tracking — see `js-vm-setimmediate-indirect-eval-fn.test.ts:58-71`).
 *
 * Strategy: extend the existing config-level alias expansion pattern
 * (precedent: `expandPromisifyAliases` in `taint-matcher.ts:71-118`,
 * Sprint 54 #187 for `util.promisify(exec)`). Source-line regex detects
 * `(?:const|let|var) <name> = (eval|Function)` (without a call paren)
 * and synthesizes a classless `code_injection` sink pattern with
 * `method: <name>`. Downstream matcher / sanitizer logic unchanged.
 *
 * Coverage:
 * - Direct eval alias: `const f = eval`
 * - Direct Function-ctor alias: `const F = Function`
 * - `let`/`var` keywords
 * - Transitive aliases (`const g = eval; const f = g`) — out of scope
 *   for line-regex approach; documented as `it.skip`.
 */
describe('Sprint 58 — #188 indirect eval alias', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const countFlows = (r: Awaited<ReturnType<typeof analyze>>, type: string) =>
    (r.taint?.flows ?? []).filter(f => f.sink_type === type).length;

  it('FN — `const f = eval; f(taint)` fires code_injection', async () => {
    const code = `const express = require('express');
const app = express();
app.get('/p', (req, res) => {
  const f = eval;
  f(req.query.code);
  res.end();
});`;
    const r = await analyze(code, 'a.js', 'javascript');
    expect(countFlows(r, 'code_injection')).toBeGreaterThanOrEqual(1);
  });

  it('FN — `let f = eval; f(taint)` fires code_injection', async () => {
    const code = `const express = require('express');
const app = express();
app.get('/p', (req, res) => {
  let f = eval;
  f(req.query.code);
  res.end();
});`;
    const r = await analyze(code, 'b.js', 'javascript');
    expect(countFlows(r, 'code_injection')).toBeGreaterThanOrEqual(1);
  });

  it('FN — `var f = eval; f(taint)` fires code_injection', async () => {
    const code = `const express = require('express');
const app = express();
app.get('/p', (req, res) => {
  var f = eval;
  f(req.query.code);
  res.end();
});`;
    const r = await analyze(code, 'c.js', 'javascript');
    expect(countFlows(r, 'code_injection')).toBeGreaterThanOrEqual(1);
  });

  it('FN — `const F = Function; new F(taint)()` fires code_injection', async () => {
    // Function-ctor alias: F(taint) is equivalent to new Function(taint)()
    // and Function's first arg is a body string. Same CWE-94 risk shape.
    const code = `const express = require('express');
const app = express();
app.get('/p', (req, res) => {
  const F = Function;
  F(req.query.code);
  res.end();
});`;
    const r = await analyze(code, 'd.js', 'javascript');
    expect(countFlows(r, 'code_injection')).toBeGreaterThanOrEqual(1);
  });

  it('FN — TypeScript `const f = eval` form fires code_injection', async () => {
    const code = `import express from 'express';
const app = express();
app.get('/p', (req: any, res: any) => {
  const f: any = eval;
  f(req.query.code);
  res.end();
});`;
    const r = await analyze(code, 'e.ts', 'typescript');
    expect(countFlows(r, 'code_injection')).toBeGreaterThanOrEqual(1);
  });

  it('recall — direct `eval(taint)` still fires (no regression)', async () => {
    const code = `const express = require('express');
const app = express();
app.get('/p', (req, res) => {
  eval(req.query.code);
  res.end();
});`;
    const r = await analyze(code, 'f.js', 'javascript');
    expect(countFlows(r, 'code_injection')).toBeGreaterThanOrEqual(1);
  });

  it('recall — `util.promisify(exec)` alias still fires command_injection', async () => {
    // Regression lock for the precedent pattern (Sprint 54 #187) — extending
    // the alias-expansion family must not break the existing promisify case.
    const code = `const { exec } = require('child_process');
const util = require('util');
const execAsync = util.promisify(exec);
async function handler(req) {
  await execAsync(req.query.cmd);
}`;
    const r = await analyze(code, 'g.js', 'javascript');
    expect(countFlows(r, 'command_injection')).toBeGreaterThanOrEqual(1);
  });

  it('TN — `const x = evaluator` (different identifier) fires nothing', async () => {
    // Word-boundary discipline: alias regex must require exact `eval` token,
    // not a prefix-match against `evaluator`, `Function2`, etc.
    const code = `const express = require('express');
const app = express();
const evaluator = (x) => x;
app.get('/p', (req, res) => {
  const x = evaluator;
  x(req.query.code);
  res.end();
});`;
    const r = await analyze(code, 'h.js', 'javascript');
    expect(countFlows(r, 'code_injection')).toBe(0);
  });

  // Transitive aliases (`const g = eval; const f = g; f(taint)`) require
  // multi-pass resolution which is out of scope for line-regex expansion.
  // Documented limitation — would need DFG-based alias propagation.
  it.skip('FN (deferred) — transitive alias `const g = eval; const f = g; f(taint)`', async () => {
    const code = `const express = require('express');
const app = express();
app.get('/p', (req, res) => {
  const g = eval;
  const f = g;
  f(req.query.code);
  res.end();
});`;
    const r = await analyze(code, 'i.js', 'javascript');
    expect(countFlows(r, 'code_injection')).toBeGreaterThanOrEqual(1);
  });
});
