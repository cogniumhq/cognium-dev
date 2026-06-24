/**
 * Tests for cognium-dev #147 — Python Jinja2 safe render-context FP
 * suppression for XSS (CWE-79) and code-injection (CWE-94) sinks.
 *
 * Jinja2 auto-escapes context values passed via render(**ctx) /
 * render_template_string("template", **ctx) by default. When the
 * template SOURCE is a string literal, tainted context values are
 * harmless: the only XSS/SSTI shapes are those where the template
 * source itself carries tainted data (concat, identifier, call,
 * f-string).
 *
 * The fix has two parts, both matching the conservative-bias principle:
 *
 *   1. `taint-matcher.ts: isSafeJinjaRenderCall()` — gates the
 *      config-driven sink emission in `findSinks()` for three call
 *      shapes:
 *        - render_template_string("lit", **ctx)
 *        - Template("lit") / Template("lit").from_string variant
 *        - Template("lit").render(**ctx)
 *
 *   2. `language-sources-pass.ts: isSafeJinjaReturnExpr()` — gates the
 *      regex-fallback `findPythonReturnXSSSinks` emitter that fires on
 *      `return <html-ish expr containing tainted var>`. Without this
 *      mirror, the RTS shape would still leak through because the
 *      tainted kwarg keeps the regex sink alive past Stage 3 cleanness
 *      filtering in SinkFilterPass.
 *
 * Recall lock: any tainted-template-source variant (string concat,
 * identifier reference, function-call result, f-string interpolation)
 * keeps the sink because the gate matches only single quoted literal
 * arg[0] / receiver shapes.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const countJinjaSinks = (
  sinks: Array<{ type?: string }> | undefined,
) =>
  (sinks ?? []).filter(
    (s) => s.type === 'xss' || s.type === 'code_injection',
  ).length;

describe('cognium-dev #147 — Jinja2 safe render-context FP suppression', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // -------------------------------------------------------------------------
  // FP-suppression: literal-template safe shapes must NOT emit sinks
  // -------------------------------------------------------------------------

  it('Template("literal").render(**ctx) — double-quoted literal: no sink', async () => {
    const code = `from flask import Flask, request
from jinja2 import Template
app = Flask(__name__)

@app.route("/h")
def h():
    name = request.args.get("name", "")
    return Template("<h1>{{ name }}</h1>").render(name=name)
`;
    const r = await analyze(code, 't.py', 'python');
    expect(countJinjaSinks(r.taint.sinks)).toBe(0);
  });

  it('Template(\'literal\').render(**ctx) — single-quoted literal: no sink', async () => {
    const code = `from flask import Flask, request
from jinja2 import Template
app = Flask(__name__)

@app.route("/h")
def h():
    name = request.args.get("name", "")
    return Template('<h1>{{ name }}</h1>').render(name=name)
`;
    const r = await analyze(code, 't.py', 'python');
    expect(countJinjaSinks(r.taint.sinks)).toBe(0);
  });

  it('render_template_string("literal", **ctx): no sink', async () => {
    const code = `from flask import Flask, render_template_string, request
app = Flask(__name__)

@app.route("/h3")
def h3():
    name = request.args.get("name", "")
    return render_template_string("<h1>{{ name }}</h1>", name=name)
`;
    const r = await analyze(code, 't.py', 'python');
    expect(countJinjaSinks(r.taint.sinks)).toBe(0);
  });

  it('bare Template("literal") constructor without .render: no sink', async () => {
    const code = `from flask import Flask, request
from jinja2 import Template
app = Flask(__name__)

@app.route("/h")
def h():
    name = request.args.get("name", "")
    return Template("<h1>{{ name }}</h1>")
`;
    const r = await analyze(code, 't.py', 'python');
    expect(countJinjaSinks(r.taint.sinks)).toBe(0);
  });

  it('Template("literal").render() with no context: no sink', async () => {
    const code = `from flask import Flask, request
from jinja2 import Template
app = Flask(__name__)

@app.route("/h")
def h():
    name = request.args.get("name", "")
    if name:
        return Template("<h1>static</h1>").render()
    return ""
`;
    const r = await analyze(code, 't.py', 'python');
    expect(countJinjaSinks(r.taint.sinks)).toBe(0);
  });

  // -------------------------------------------------------------------------
  // Recall: tainted-template-source variants MUST still emit sinks
  // -------------------------------------------------------------------------

  it('Template("..." + name + "...").render() — string-concat template source: sink kept', async () => {
    const code = `from flask import Flask, request
from jinja2 import Template
app = Flask(__name__)

@app.route("/h")
def h():
    name = request.args.get("name", "")
    return Template("<h1>" + name + "</h1>").render()
`;
    const r = await analyze(code, 't.py', 'python');
    expect(countJinjaSinks(r.taint.sinks)).toBeGreaterThanOrEqual(1);
  });

  it('render_template_string("..." + name + "...") — string-concat template source: sink kept', async () => {
    const code = `from flask import Flask, render_template_string, request
app = Flask(__name__)

@app.route("/h")
def h():
    name = request.args.get("name", "")
    return render_template_string("<h1>" + name + "</h1>")
`;
    const r = await analyze(code, 't.py', 'python');
    expect(countJinjaSinks(r.taint.sinks)).toBeGreaterThanOrEqual(1);
  });

  it('Template(tainted_var).render() — identifier template source: sink kept', async () => {
    const code = `from flask import Flask, request
from jinja2 import Template
app = Flask(__name__)

@app.route("/h")
def h():
    name = request.args.get("name", "")
    return Template(name).render()
`;
    const r = await analyze(code, 't.py', 'python');
    expect(countJinjaSinks(r.taint.sinks)).toBeGreaterThanOrEqual(1);
  });

  it('render_template_string(call_result(), **ctx) — call-result template source: sink kept', async () => {
    const code = `from flask import Flask, render_template_string, request

def load_template():
    return "<h1>{{name}}</h1>"

app = Flask(__name__)

@app.route("/h")
def h():
    name = request.args.get("name", "")
    return render_template_string(load_template(), name=name)
`;
    const r = await analyze(code, 't.py', 'python');
    expect(countJinjaSinks(r.taint.sinks)).toBeGreaterThanOrEqual(1);
  });

  // -------------------------------------------------------------------------
  // Issue body repro + control
  // -------------------------------------------------------------------------

  it('issue #147 repro — Template render-context safe vs concat-source TP control', async () => {
    // Safe shape — Jinja2 auto-escapes the kwarg `name`; no sink should fire.
    const safe = `from flask import Flask, request
from jinja2 import Template
app = Flask(__name__)

@app.route("/h")
def h():
    name = request.args.get("name", "")
    return Template("<h1>{{ name }}</h1>").render(name=name)
`;
    const rSafe = await analyze(safe, 'safe.py', 'python');
    expect(countJinjaSinks(rSafe.taint.sinks)).toBe(0);

    // Same shape but template SOURCE is built by concat — real SSTI/XSS.
    const tp = `from flask import Flask, request
from jinja2 import Template
app = Flask(__name__)

@app.route("/h")
def h():
    name = request.args.get("name", "")
    return Template("<h1>" + name + "</h1>").render()
`;
    const rTp = await analyze(tp, 'tp.py', 'python');
    expect(countJinjaSinks(rTp.taint.sinks)).toBeGreaterThanOrEqual(1);
  });
});
