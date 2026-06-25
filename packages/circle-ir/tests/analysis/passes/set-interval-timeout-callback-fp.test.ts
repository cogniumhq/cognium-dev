/**
 * Tests for cognium-dev #152 — `setInterval` / `setTimeout` CWE-94
 * (code_injection) sink emission must be gated by arg[0] kind.
 *
 * The eval-style semantics of `setInterval` / `setTimeout` only fires
 * when arg[0] is a string (e.g. `setInterval("alert(1)", 100)`). The far
 * more common callback form — `setInterval(() => tick(), 80)` — has no
 * code-injection semantics and was over-firing CWE-94 in 3.x, including
 * on benign self-scans (e.g. `cognium-ai/src/utils/spinner.ts:28`).
 *
 * The fix is in `taint-matcher.ts` `isFunctionCallbackArgument()` +
 * a guard at the `findSinks()` emission point. This suite locks both
 * directions:
 *
 *  - FP-suppression: callback arg[0] forms (arrow / async arrow / named
 *    arrow / function expression / named function expression) must not
 *    emit a `code_injection` sink.
 *  - Recall: identifier references at arg[0] must still emit a sink
 *    (conservative — taint flow decides whether the variable carries
 *    a string), and a tainted variable reaching arg[0] still produces
 *    a taint flow.
 *  - Cross-method: both `setInterval` and `setTimeout` honour the gate.
 *  - Non-target methods: `eval(x)` is unaffected.
 *
 * Note on string-literal calls: `setInterval("alert(1)", 100)` does not
 * emit a sink in the current engine because Stage 3 of `SinkFilterPass`
 * (`filterCleanVariableSinks`) drops sinks whose only argument is a
 * pure literal — no taint can reach them. That is unrelated to this
 * patch and is asserted elsewhere; tests below focus on the new gate.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const countCodeInjectionSinksAt = (
  sinks: Array<{ type?: string; line?: number; method?: string }> | undefined,
  method: string,
) =>
  (sinks ?? []).filter((s) => s.type === 'code_injection' && s.method === method).length;

const countCodeInjectionSinks = (sinks: Array<{ type?: string }> | undefined) =>
  (sinks ?? []).filter((s) => s.type === 'code_injection').length;

describe('cognium-dev #152 — setInterval/setTimeout callback FP suppression', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // -------------------------------------------------------------------------
  // FP-suppression: callback arg[0] forms must NOT emit code_injection sink
  // -------------------------------------------------------------------------

  it('setInterval with arrow function callback: no code_injection sink', async () => {
    const code = `
const id = setInterval(() => {
  console.log('tick');
}, 80);
`;
    const r = await analyze(code, 'arrow.js', 'javascript');
    expect(countCodeInjectionSinksAt(r.taint.sinks, 'setInterval')).toBe(0);
  });

  it('setInterval with async arrow function callback: no code_injection sink', async () => {
    const code = `
setInterval(async () => {
  await save();
}, 1000);
`;
    const r = await analyze(code, 'async-arrow.js', 'javascript');
    expect(countCodeInjectionSinksAt(r.taint.sinks, 'setInterval')).toBe(0);
  });

  it('setInterval with parameterised arrow function callback: no code_injection sink', async () => {
    const code = `
setInterval((tickCount) => {
  doWork(tickCount);
}, 50);
`;
    const r = await analyze(code, 'parm-arrow.js', 'javascript');
    expect(countCodeInjectionSinksAt(r.taint.sinks, 'setInterval')).toBe(0);
  });

  it('setInterval with anonymous function expression callback: no code_injection sink', async () => {
    const code = `
setInterval(function () {
  poll();
}, 200);
`;
    const r = await analyze(code, 'fn-expr.js', 'javascript');
    expect(countCodeInjectionSinksAt(r.taint.sinks, 'setInterval')).toBe(0);
  });

  it('setInterval with named function expression callback: no code_injection sink', async () => {
    const code = `
setInterval(function poll() {
  doPoll();
}, 200);
`;
    const r = await analyze(code, 'named-fn-expr.js', 'javascript');
    expect(countCodeInjectionSinksAt(r.taint.sinks, 'setInterval')).toBe(0);
  });

  it('setTimeout with arrow function callback: no code_injection sink', async () => {
    const code = `
setTimeout(() => {
  flush();
}, 1000);
`;
    const r = await analyze(code, 'timeout-arrow.js', 'javascript');
    expect(countCodeInjectionSinksAt(r.taint.sinks, 'setTimeout')).toBe(0);
  });

  it('setTimeout with function expression callback: no code_injection sink', async () => {
    const code = `
setTimeout(function () { retry(); }, 500);
`;
    const r = await analyze(code, 'timeout-fn-expr.js', 'javascript');
    expect(countCodeInjectionSinksAt(r.taint.sinks, 'setTimeout')).toBe(0);
  });

  // Repro of the exact spinner.ts:28 shape from the issue body.
  it('issue #152 repro — spinner.ts:28 setInterval arrow with closure body', async () => {
    const code = `
const SPINNER_FRAMES = ['|', '/', '-', '\\\\'];
class Spinner {
  start() {
    this.intervalId = setInterval(() => {
      const frame = SPINNER_FRAMES[this.frameIndex];
      this.frameIndex = (this.frameIndex + 1) % SPINNER_FRAMES.length;
      process.stdout.write(frame);
    }, 80);
  }
}
`;
    const r = await analyze(code, 'spinner.ts', 'typescript');
    expect(countCodeInjectionSinks(r.taint.sinks)).toBe(0);
  });

  // -------------------------------------------------------------------------
  // Recall locks: identifier arg[0] keeps sink; tainted var still flows
  // -------------------------------------------------------------------------

  it('setInterval with identifier arg[0]: sink kept (conservative — taint flow decides)', async () => {
    // A bare identifier could resolve to a string at runtime; the sink
    // must be kept so taint propagation can decide whether to emit a flow.
    // We exercise the keep-path by routing a known-tainted value through
    // the identifier — the sink stays + a flow appears.
    const code = `
function handle(req) {
  const handler = req.query.code;
  setInterval(handler, 100);
}
`;
    const r = await analyze(code, 'identifier-tainted.js', 'javascript');
    expect(countCodeInjectionSinksAt(r.taint.sinks, 'setInterval')).toBeGreaterThanOrEqual(1);
  });

  it('setTimeout with tainted identifier arg[0]: sink + flow preserved', async () => {
    const code = `
function handle(req) {
  const handler = req.body.callback;
  setTimeout(handler, 50);
}
`;
    const r = await analyze(code, 'timeout-identifier-tainted.js', 'javascript');
    expect(countCodeInjectionSinksAt(r.taint.sinks, 'setTimeout')).toBeGreaterThanOrEqual(1);
  });

  // -------------------------------------------------------------------------
  // Gate scoping: only setInterval/setTimeout are affected
  // -------------------------------------------------------------------------

  it('eval(...) is unaffected by the setInterval/setTimeout gate', async () => {
    const code = `
function run(code) {
  eval(code);
}
`;
    const r = await analyze(code, 'eval.js', 'javascript');
    expect(countCodeInjectionSinksAt(r.taint.sinks, 'eval')).toBeGreaterThanOrEqual(1);
  });

  // -------------------------------------------------------------------------
  // #152 reopen — interprocedural_param → code_injection flow on
  // setInterval/setTimeout must be suppressed. Untyped JS function
  // parameters cannot be proven to carry strings; callers commonly pass
  // function references, which is the benign callback shape. The earlier
  // 3.96.0 matcher gate only handled inline function literals; a bare
  // identifier resolving to a function-typed param slipped through and
  // produced a critical code_injection flow.
  // -------------------------------------------------------------------------

  it('reopen repro — setTimeout(cb, 1000) on function param emits no flow', async () => {
    const code = `
function schedule(cb) {
  setTimeout(cb, 1000);
}
`;
    const r = await analyze(code, 'schedule-timeout.js', 'javascript');
    const codeInjFlows = (r.taint.flows ?? []).filter(f => f.sink_type === 'code_injection');
    expect(codeInjFlows).toEqual([]);
  });

  it('reopen repro — setInterval(cb, 5000) on function param emits no flow', async () => {
    const code = `
function schedule(cb) {
  setInterval(cb, 5000);
}
`;
    const r = await analyze(code, 'schedule-interval.js', 'javascript');
    const codeInjFlows = (r.taint.flows ?? []).filter(f => f.sink_type === 'code_injection');
    expect(codeInjFlows).toEqual([]);
  });

  it('recall — tainted HTTP string reaching setTimeout still flows', async () => {
    // The gate must be source-type-specific: only `interprocedural_param`
    // (untyped function parameter) is suppressed. A genuine HTTP-sourced
    // string flowing to setTimeout is a real CWE-94 and must still emit.
    const code = `
function handle(req) {
  const payload = req.query.code;
  setTimeout(payload, 100);
}
`;
    const r = await analyze(code, 'real-rce-timeout.js', 'javascript');
    const codeInjFlows = (r.taint.flows ?? []).filter(f => f.sink_type === 'code_injection');
    expect(codeInjFlows.length).toBeGreaterThanOrEqual(1);
  });

  it('recall — eval(param) on a function parameter still flows', async () => {
    // The gate is scoped to setInterval/setTimeout only. eval has true
    // code-injection semantics on any argument kind, so the gate must
    // not suppress its interprocedural_param flow.
    const code = `
function run(code) {
  eval(code);
}
`;
    const r = await analyze(code, 'eval-param.js', 'javascript');
    const codeInjFlows = (r.taint.flows ?? []).filter(f => f.sink_type === 'code_injection');
    expect(codeInjFlows.length).toBeGreaterThanOrEqual(1);
  });
});
