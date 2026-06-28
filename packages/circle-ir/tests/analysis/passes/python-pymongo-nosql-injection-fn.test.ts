/**
 * Sprint 54 — cognium-dev #194: Python pymongo `col.find({"name": tainted})`
 * dict-value `nosql_injection` FN.
 *
 * `col.find({"name": q})` with tainted `q` does not flag CWE-943. Sinks
 * are registered (`config-loader.ts:1720` Collection.find Python +
 * classless variants at :1730), `arg_positions: [0]` correctly targets
 * the filter dict. Hypothesis: nested dict-value taint is not surfaced
 * to the sink matcher — the engine's expression-scan only inspects the
 * top-level argument text or fails to descend into `{"key": value}`
 * literals to extract per-value variables.
 *
 * Recall lock: literal-only `col.find({"name": "alice"})` produces zero
 * flows. Direct `col.find(tainted_dict)` whole-arg form must keep firing.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const countNosqlFlows = (flows: Array<{ sink_type?: string }> | undefined) =>
  (flows ?? []).filter(f => f.sink_type === 'nosql_injection').length;
const countNosqlSinks = (sinks: Array<{ type?: string }> | undefined) =>
  (sinks ?? []).filter(s => s.type === 'nosql_injection').length;

describe('cognium-dev #194 — Python pymongo dict-value nosql_injection FN', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('FN — col.find({"name": q}) inline dict-value taint fires nosql_injection', async () => {
    const code = `from flask import Flask, request
from pymongo import MongoClient
app = Flask(__name__)
col = MongoClient().db.u

@app.route("/lookup")
def lookup():
    q = request.args.get("q", "")
    list(col.find({"name": q}))
    return "ok"
`;
    const r = await analyze(code, 'lookup.py', 'python');
    expect(countNosqlSinks(r.taint?.sinks)).toBeGreaterThan(0);
    expect(countNosqlFlows(r.taint?.flows)).toBeGreaterThan(0);
  });

  it('FN — query = {"name": q}; col.find(query) aliased dict-value fires', async () => {
    const code = `from flask import Flask, request
from pymongo import MongoClient
app = Flask(__name__)
col = MongoClient().db.u

@app.route("/lookup2")
def lookup2():
    q = request.args.get("q", "")
    query = {"name": q}
    list(col.find(query))
    return "ok"
`;
    const r = await analyze(code, 'lookup2.py', 'python');
    expect(countNosqlFlows(r.taint?.flows)).toBeGreaterThan(0);
  });

  it('recall — col.find({"name": "alice"}) literal-only produces zero flows', async () => {
    const code = `from pymongo import MongoClient
col = MongoClient().db.u
list(col.find({"name": "alice"}))
`;
    const r = await analyze(code, 'noop.py', 'python');
    expect(countNosqlFlows(r.taint?.flows)).toBe(0);
  });
});
