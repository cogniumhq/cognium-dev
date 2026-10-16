/**
 * cognium-dev #563 — Python rejecting membership guard credits the guarded
 * variable for trust_boundary (PAT-TRUST-01 python safe shape).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const prefsRoute = `from flask import Flask, session, request, abort

app = Flask(__name__)
app.secret_key = "dev"
THEMES = {"light", "dark"}


@app.route("/theme")
def set_theme():
    theme = request.args.get("theme")
    if theme not in THEMES:
        abort(400)
    session["theme"] = theme
    return "ok"


@app.route("/theme-raw")
def set_theme_raw():
    theme = request.args.get("theme")
    session["theme"] = theme
    return "ok"
`;

const guardLogsOnly = `from flask import Flask, session, request

app = Flask(__name__)
app.secret_key = "dev"
THEMES = {"light", "dark"}


@app.route("/theme")
def set_theme():
    theme = request.args.get("theme")
    if theme not in THEMES:
        print("bad theme")
    session["theme"] = theme
    return "ok"
`;

const mutatedSet = `from flask import Flask, session, request, abort

app = Flask(__name__)
app.secret_key = "dev"
THEMES = {"light", "dark"}
THEMES.add("neon")


@app.route("/theme")
def set_theme():
    theme = request.args.get("theme")
    if theme not in THEMES:
        abort(400)
    session["theme"] = theme
    return "ok"
`;

const otherVarGuarded = `from flask import Flask, session, request, abort

app = Flask(__name__)
app.secret_key = "dev"
THEMES = {"light", "dark"}


@app.route("/theme")
def set_theme():
    theme = request.args.get("theme")
    other = request.args.get("other")
    if other not in THEMES:
        abort(400)
    session["theme"] = theme
    return "ok"
`;

describe('#563 Python literal membership guard', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('credits guarded theme after aborting membership reject', async () => {
    const r = await analyze(prefsRoute, 'prefs_route.py', 'python');
    const tb = (r.taint?.flows ?? []).filter((f: { sink_type: string }) => f.sink_type === 'trust_boundary');
    const lines = tb.map((f: { sink_line: number }) => f.sink_line);
    expect(lines).not.toContain(13);
    expect(lines).toContain(20);
  });

  it('does not credit when the guard body only logs', async () => {
    const r = await analyze(guardLogsOnly, 'guard_logs_only.py', 'python');
    const tb = (r.taint?.flows ?? []).filter((f: { sink_type: string }) => f.sink_type === 'trust_boundary');
    expect(tb.length).toBeGreaterThan(0);
  });

  it('does not credit a mutated module-level set', async () => {
    const r = await analyze(mutatedSet, 'mutated_set.py', 'python');
    const tb = (r.taint?.flows ?? []).filter((f: { sink_type: string }) => f.sink_type === 'trust_boundary');
    expect(tb.length).toBeGreaterThan(0);
  });

  it('does not credit when a different variable is guarded', async () => {
    const r = await analyze(otherVarGuarded, 'other_var_guarded.py', 'python');
    const tb = (r.taint?.flows ?? []).filter((f: { sink_type: string }) => f.sink_type === 'trust_boundary');
    expect(tb.length).toBeGreaterThan(0);
  });
});
