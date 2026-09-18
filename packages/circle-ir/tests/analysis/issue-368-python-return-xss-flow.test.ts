/**
 * cognium-dev #368 — Python Flask return-XSS sinks produced no taint flow.
 *
 * The SAME wiring gap as #363, on a different detector. `LanguageSourcesPass`
 * synthesises an `xss` sink for `return f"<div>{taint}</div>"` and
 * `return "<div>" + taint` via `findPythonReturnXSSSinks`, but the sink has no
 * `method` and no arguments, so no argument matcher can connect a source to
 * it. The sink was reported while `taint.flows` stayed empty — invisible to
 * every flow-gated consumer, which is most of them.
 *
 * Returning interpolated request data from a Flask view is real reflected XSS:
 * a `str` return gets `text/html`.
 *
 * SANITIZER AWARENESS IS THE LOAD-BEARING PART, and the suite proved it. The
 * first cut checked for an xss-covering sanitizer only at the SINK line, which
 * passes for `html.escape` on the return line but misses
 *
 *     n = int(request.args.get('n', '0'))   # sanitises here
 *     return f"<p>count={n}</p>"            # renders on the next line
 *
 * (`repro-sprint18.test.ts` #100.2). That test had passed before this change
 * only because no flow existed at all — so emitting flows turned a vacuous
 * pass into a real false positive. The check now covers the whole
 * source -> sink line range. That is deliberately coarse: for an ADDITIVE
 * emitter the safe direction is to emit fewer flows, so an unrelated in-range
 * sanitizer costs a missed finding rather than a false positive.
 *
 * SCOPE, measured and stated because it is the reason this does not move the
 * benchmark: OWASP BenchmarkPython's `xss` category is unchanged at TP=0 FN=31
 * FP=0 TN=58. All 89 of its fixtures use `RESPONSE += f'…{bar}'; return
 * RESPONSE`, and all 58 expect-clean ones are safe via `escape_for_html` — a
 * hand-rolled character-by-character entity encoder defined in the benchmark's
 * own `helpers/utils.py`, cross-file, with no recognisable `html.escape` call
 * in its body. Detecting that accumulator shape without cross-file credit for
 * user-defined escapers would report all 89: 31 TP and 58 FP. Registering the
 * helper's NAME would score the benchmark rather than fix the engine, so
 * neither is done here. The accumulator shape stays undetected on purpose;
 * what this fixes is the direct-return shape in ordinary Flask code.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const xss = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === 'xss' && !f.sanitized);

const py = (code: string) => analyze(code, 'view.py', 'python');

describe('#368 Python return-XSS sinks produce a taint flow', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('flows for an f-string return', async () => {
    const r = await py(
      'from flask import request\ndef f():\n    p = request.form.get("x")\n    return f"<div>{p}</div>"'
    );
    expect(xss(r).length).toBeGreaterThan(0);
  });

  it('flows for a concatenated return', async () => {
    const r = await py(
      'from flask import request\ndef f():\n    p = request.form.get("x")\n    return "<div>" + p'
    );
    expect(xss(r).length).toBeGreaterThan(0);
  });

  it('emits the sink AND the flow, not one without the other', async () => {
    const r = await py(
      'from flask import request\ndef f():\n    p = request.form.get("x")\n    return f"<div>{p}</div>"'
    );
    const sinks = (r.taint.sinks ?? []).filter(s => s.type === 'xss');
    expect(sinks.length).toBeGreaterThan(0);
    expect(xss(r)[0].sink_line).toBe(sinks[0].line);
  });

  describe('sanitizers must suppress it', () => {
    it('html.escape on the return line', async () => {
      const r = await py(
        'import html\nfrom flask import request\ndef f():\n    p = request.form.get("x")\n    return f"<div>{html.escape(p)}</div>"'
      );
      expect(xss(r)).toHaveLength(0);
    });

    it('markupsafe escape on the return line', async () => {
      const r = await py(
        'from markupsafe import escape\nfrom flask import request\ndef f():\n    p = request.form.get("x")\n    return f"<div>{escape(p)}</div>"'
      );
      expect(xss(r)).toHaveLength(0);
    });

    it('an int() cast on an EARLIER line — the case the suite caught', async () => {
      const r = await py(
        "from flask import request\ndef view():\n    n = int(request.args.get('n', '0'))\n    return f\"<p>count={n}</p>\""
      );
      expect(xss(r)).toHaveLength(0);
    });
  });

  it('does not fire when the return has no tainted value', async () => {
    const r = await py('from flask import request\ndef f():\n    return "<div>static</div>"');
    expect(xss(r)).toHaveLength(0);
  });

  it('leaves the benchmark accumulator shape undetected, as documented', async () => {
    // Pinned so the scope of this fix is explicit rather than assumed. Moving
    // this requires cross-file credit for user-defined escapers (#293 family);
    // firing on it without that would add 58 false positives on
    // BenchmarkPython.
    const r = await py(
      'from flask import request\ndef f():\n    RESPONSE = ""\n    p = request.form.get("x")\n    RESPONSE += f"<div>{p}</div>"\n    return RESPONSE'
    );
    expect(xss(r)).toHaveLength(0);
  });
});
