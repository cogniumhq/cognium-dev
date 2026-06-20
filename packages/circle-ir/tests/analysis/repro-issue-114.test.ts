/**
 * Repro for issue #114 — Python safe-handler FP reduction.
 *
 * Two false positives shipped pre-3.84.0:
 *
 *   1. open_redirect: `if urlparse(target).netloc not in ALLOWED_HOSTS: return ...;
 *      redirect(target)` — guarded netloc allow-list is safe but flagged.
 *      Fix: new `findPythonNetlocAllowlistGuardSanitizers` per-line guard
 *      recognizer (language-sources-pass.ts).
 *
 *   2. xss: `qty = int(request.args["qty"]); return "total=" + str(qty * 10)`
 *      — `int()` strips xss taint, but downstream `str(qty * N)` re-taints via
 *      arithmetic→string concat. Phase-A empirical repro confirmed: `int()`
 *      sanitizer fires but xss still emits.
 *      Fix: new `findPythonRangeCheckGuardSanitizers` per-line guard
 *      recognizer (language-sources-pass.ts).
 *
 * Recall locks below verify the substring-check open-redirect and the
 * unguarded string-concat xss still match their SINK patterns (engine flow
 * connection through Flask return-strings is incomplete; sink-level
 * assertion is the canonical signal for unguarded matches).
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';
import type { CircleIR } from '../../src/types/index.js';

const flowsByType = (ir: CircleIR, t: string) =>
  (ir.taint?.flows ?? []).filter((f) => f.sink_type === t);

const sinksByType = (ir: CircleIR, t: string) =>
  (ir.taint?.sinks ?? []).filter((s) => (s as { type?: string }).type === t);

describe('Issue #114 — Python safe-handler negative locks', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('py_netloc_allowlist_guard — urlparse(target).netloc allow-list does NOT emit open_redirect', async () => {
    const code = `
from urllib.parse import urlparse
from flask import Flask, request, redirect

ALLOWED_HOSTS = {"example.com", "trusted.org"}
app = Flask(__name__)

@app.route("/go")
def go():
    target = request.args.get("target", "")
    if urlparse(target).netloc not in ALLOWED_HOSTS:
        return "forbidden", 403
    return redirect(target)
`;
    const ir = await analyze(code, 'netloc_guard.py', 'python');
    expect(flowsByType(ir, 'open_redirect')).toHaveLength(0);
  });

  it('py_int_range_check_guard — range-checked int does NOT emit xss', async () => {
    const code = `
from flask import Flask, request

app = Flask(__name__)

@app.route("/buy")
def buy():
    qty = int(request.args["qty"])
    if qty < 1 or qty > 100:
        return "bad qty", 400
    total = qty * 10
    return "total=" + str(total)
`;
    const ir = await analyze(code, 'int_range.py', 'python');
    expect(flowsByType(ir, 'xss')).toHaveLength(0);
  });
});

describe('Issue #114 — Python safe-handler recall locks', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('py_substring_check_open_redirect — substring check is NOT a real allow-list', async () => {
    const code = `
from flask import Flask, request, redirect

app = Flask(__name__)

@app.route("/go")
def go():
    target = request.args.get("target", "")
    if "trusted.com" in target:
        return redirect(target)
    return "forbidden", 403
`;
    const ir = await analyze(code, 'substring_redirect.py', 'python');
    // Substring containment is not equivalent to host allow-list. The
    // guard recognizer must NOT trigger (no allow-list name), so the flow
    // still reaches redirect(...).
    expect(flowsByType(ir, 'open_redirect').length).toBeGreaterThan(0);
  });

  it('py_str_concat_xss — unguarded concat keeps xss sink', async () => {
    const code = `
from flask import Flask, request

app = Flask(__name__)

@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return "<h1>" + name + "</h1>"
`;
    const ir = await analyze(code, 'str_concat_xss.py', 'python');
    // Sink-level lock — Flask return-string flow tracking is partial,
    // so we assert that the xss sink itself is still matched (the
    // range-check guard recognizer must NOT spuriously fire here).
    expect(sinksByType(ir, 'xss').length).toBeGreaterThan(0);
  });
});
