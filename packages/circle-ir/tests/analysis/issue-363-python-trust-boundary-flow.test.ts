/**
 * cognium-dev #363 — OWASP BenchmarkPython scored the `trustbound` (CWE-501)
 * category 0%, ~18 false negatives.
 *
 * The issue's diagnosis — "no CWE-501 sink model for Python" — is not what is
 * wrong. The model exists and fires: `LanguageSourcesPass` detects
 * `session[<tainted>] = …` via `findPythonTrustBoundaryViolations` and
 * synthesises a `trust_boundary` sink for it. On `BenchmarkTest00072` that
 * sink is present and `generateFindings` even reports it.
 *
 * What was missing is a FLOW. The synthesised sink has no `method` and no
 * arguments, because a subscript assignment is not a call — and every flow
 * builder in `taint-propagation-pass` matches a source against a sink's
 * ARGUMENTS. So nothing could ever connect to it: the sink was reported while
 * `taint.flows` stayed empty for every one of these cases, including the
 * trivial `flask.session[param] = '12345'`.
 *
 * That is invisible unless you look at flows specifically, and it is exactly
 * what the benchmark runner looks at — post-#265 it requires an unsanitised
 * flow of the expected sink type rather than source+sink co-occurrence:
 *
 *     const hasFlow = (result.taint.flows ?? []).some(
 *       (f) => f.sink_type === expectedSinkType && f.sanitized !== true);
 *     const detected = hasFlow && !isSanitized;
 *
 * Hence 0%: sink yes, flow no, detected no.
 *
 * The detector already computes both ends of the flow (`{sourceLine,
 * sinkLine}`), so the fix emits it there rather than teaching the argument
 * matchers about subscript assignment, and reuses the same exported detector
 * so the sink and the flow can never disagree about what qualifies.
 *
 * Measured on the real corpus after the fix: trustbound recall 0% -> 94.4%
 * (TP=17, FN=1) at 0% FPR (FP=0, TN=19). The single residual FN
 * (`BenchmarkTest00499`) is a different gap — taint on the VALUE side under a
 * constant key, where `bar`'s derivation is not tracked by
 * `buildPythonTaintedVars` — deliberately not papered over here.
 *
 * Note also that the issue's quoted repro is not what the fixture does: it
 * shows `response.set_cookie(..., path=request.path)`, while
 * `BenchmarkTest00072` actually writes `flask.session[bar] = '12345'`.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const tb = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === 'trust_boundary' && !f.sanitized);

const py = (body: string[]) =>
  analyze(
    ['from flask import request', 'import flask', 'def f():', ...body.map(l => '    ' + l)].join('\n'),
    'x.py',
    'python'
  );

describe('#363 Python trust-boundary sinks produce a taint flow', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('flows for a tainted session KEY', async () => {
    const r = await py(['param = request.cookies.get("c", "")', "flask.session[param] = '12345'"]);
    expect(tb(r).length).toBeGreaterThan(0);
  });

  it('flows for a tainted session VALUE', async () => {
    const r = await py(['param = request.cookies.get("c", "")', 'flask.session["k"] = param']);
    expect(tb(r).length).toBeGreaterThan(0);
  });

  it('flows through an intermediate variable', async () => {
    const r = await py([
      'param = request.cookies.get("c", "")',
      'bar = param',
      "flask.session[bar] = '12345'",
    ]);
    expect(tb(r).length).toBeGreaterThan(0);
  });

  it('flows through the benchmark if/else shape', async () => {
    // BenchmarkTest00072: the condition is always false, so `bar = param`.
    const r = await py([
      'param = request.cookies.get("c", "")',
      'TestParam = "This should never happen"',
      "if 'should' not in TestParam:",
      '    bar = "Ifnot case passed"',
      'else:',
      '    bar = param',
      "flask.session[bar] = '12345'",
    ]);
    expect(tb(r).length).toBeGreaterThan(0);
  });

  it('emits the sink AND the flow, not one without the other', async () => {
    // The precise regression: a sink with no matching flow is what scored 0%.
    const r = await py(['param = request.cookies.get("c", "")', "flask.session[param] = '1'"]);
    const sinks = (r.taint.sinks ?? []).filter(s => s.type === 'trust_boundary');
    expect(sinks.length).toBeGreaterThan(0);
    expect(tb(r).length).toBeGreaterThan(0);
    expect(tb(r)[0].sink_line).toBe(sinks[0].line);
  });

  it('does not fire without a tainted value', async () => {
    const r = await py(['userid = "constant"', "flask.session['userid'] = userid"]);
    expect(tb(r)).toHaveLength(0);
  });

  it('does not fire on a session READ', async () => {
    const r = await py(['param = request.cookies.get("c", "")', 'v = flask.session.get(param)']);
    expect(tb(r)).toHaveLength(0);
  });
});
