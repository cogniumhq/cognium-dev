/**
 * cognium-dev#372 — the four reporting surfaces disagreed.
 *
 * `taint.flows`, `generateFindings(...)`, `ir.findings` and the CLI output can
 * all answer the same question differently. The gap that matters here: the
 * taint layer can prove a flow with a precise source line, while
 * `generateFindings` — which is what `scan` and the CLI report from — rebuilt
 * its own source/sink pairs from scratch and never consulted those flows. So
 * a correctly-computed flow could be reported against the wrong source line,
 * or a pairing could exist with no corresponding flow at all.
 *
 * `generateFindings` now takes the flows as a trailing parameter and derives
 * findings from them directly.
 *
 * WHY THE SOURCE LINE IS THE POINT. This does not change WHAT is detected —
 * measured across BenchmarkPython (1230 files) the sink-level detection set is
 * identical, 915 findings rows before and after, and on SecuriBench Micro it
 * gains two. What changes is WHERE the source is reported, and that is what
 * downstream vulnerability-localization scoring keys on. On BenchmarkPython it
 * re-attributes 75 findings and cuts the number whose reported source line
 * sits AFTER its own sink from 23 to 10.
 *
 * BACKWARD COMPATIBLE BY CONSTRUCTION: `flows` is optional and trailing. A
 * caller that omits it keeps the previous pairing behaviour exactly — which is
 * also what the second assertion below pins, so the two paths cannot silently
 * converge and make this test vacuous.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';
import { generateFindings } from '../../src/analysis/findings.js';

describe('#372 — findings derived from taint.flows', () => {
  beforeAll(async () => { await initAnalyzer(); });

  // Reduced from the BenchmarkPython shape: a Flask handler nested inside
  // `def init(app)`. Pairing alone credits the source to the enclosing `init`
  // line; the flow knows better.
  const code = [
    'from flask import request',                       // 1
    'import subprocess',                               // 2
    '',                                                // 3
    'def init(app):',                                  // 4
    '',                                                // 5
    '    @app.route("/x", methods=["POST"])',          // 6
    '    def handler():',                              // 7
    '        param = ""',                              // 8
    '        for name in request.form.keys():',        // 9
    '            param = name',                        // 10
    '        cmd = "echo " + param',                   // 11
    '        subprocess.check_output(cmd, shell=True)',// 12
    '        return ""',                               // 13
  ].join('\n');

  it('attributes the finding to the flow source, not the enclosing def', async () => {
    const r = await analyze(code, 'app.py', 'python');
    expect(r.taint.flows.length).toBeGreaterThan(0);

    const withFlows = generateFindings(
      r.taint.sources, r.taint.sinks, r.dfg, 'app.py', code, 'python',
      r.taint.sanitizers, r.types, r.taint.flows,
    );
    const ci = withFlows.filter((f) => f.type === 'command_injection');
    expect(ci).toHaveLength(1);
    expect(ci[0].line).toBe(12);
    // Line 9 is `for name in request.form.keys():` — the actual untrusted
    // read. This was 11 (`cmd = "echo " + param`, where the command is built)
    // until #493 made a `for` target bound from a tainted iterable emit a
    // source; before that no source existed at line 9 for the flow to point
    // at. 9 is the more accurate attribution, so the expectation moved rather
    // than the mechanism regressing.
    expect(ci[0].source?.line).toBe(9);
  });

  // NON-VACUITY. Before #493 this pinned `source.line === 4` on the no-flows
  // path — the enclosing `def init(app):` — against 11 on the flow path, which
  // proved the two paths were distinct. Once a `for` target bound from a
  // tainted iterable emits a real source at line 9, BOTH paths credit line 9:
  // the pairing path now has the correct source available to choose, so the
  // paths agree because the source model improved, not because the #372
  // mechanism stopped working.
  //
  // A two-source fixture was tried as a replacement and rejected: with
  // `unused = request.args.get(...)` on line 5 and the real `param =
  // request.form.get(...)` on line 6, the FLOW itself reports line 5 — the
  // decoy that reaches nothing. That misattribution reproduces identically on
  // main, so it is a pre-existing defect and not a basis for this assertion.
  //
  // What is still worth pinning is that the no-flows path remains live and
  // still produces the finding, so a caller on the 8-argument signature is not
  // silently getting nothing.
  it('still reports on the no-flows path (the 8-argument signature stays live)', async () => {
    const r = await analyze(code, 'app.py', 'python');
    const noFlows = generateFindings(
      r.taint.sources, r.taint.sinks, r.dfg, 'app.py', code, 'python',
      r.taint.sanitizers, r.types,
    );
    const ci = noFlows.filter((f) => f.type === 'command_injection');
    expect(ci).toHaveLength(1);
    expect(ci[0].line).toBe(12);
  });

  it('does not invent findings for a file with no flows', async () => {
    const clean = [
      'import subprocess',
      'def run():',
      '    subprocess.check_output("echo hello", shell=True)',
    ].join('\n');
    const r = await analyze(clean, 'clean.py', 'python');
    const fs = generateFindings(
      r.taint.sources, r.taint.sinks, r.dfg, 'clean.py', clean, 'python',
      r.taint.sanitizers, r.types, r.taint.flows,
    );
    expect(fs.filter((f) => f.type === 'command_injection')).toHaveLength(0);
  });
});
