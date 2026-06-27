/**
 * Sprint 53 — cognium-dev #215: Python `safe_sql_identifier_quote` FP
 * (Stage 19, Python port of Java Stage 15).
 *
 * A Python helper that validates an identifier with an inline regex
 * allowlist + `raise` and returns it, used in an f-string SQL query
 * with a `?` placeholder for values, is flagged as `sql_injection`.
 *
 * Canonical shape:
 *
 *   def safe_col(name: str) -> str:
 *       if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
 *           raise ValueError("bad identifier")
 *       return name
 *
 *   col = safe_col(col_name)
 *   cur.execute(f"SELECT * FROM t WHERE {col} = ?", (value,))
 *
 * The `safe_col` helper is the sanitizer; the `?` placeholder proves
 * values flow through bind args rather than concat. Stage 19 mirrors
 * Stage 15 (Java) gates a-e but with Python tokens:
 *   (a) exec method: cursor.execute / executemany
 *   (b) sink first arg is an f-string with interpolations
 *   (c) interpolations are literals or in-file helper calls
 *   (d) string contains a `?` / `%s` / `:name` placeholder
 *   (e) helper body contains `re.fullmatch(allowlist, ...)` + `raise`
 *
 * Recall locks ensure each gate-removal scenario continues to fire:
 *   - helper missing `raise` → fire
 *   - no `?` placeholder, value interpolated → fire
 *   - helper regex is wildcard `.*` → fire
 *   - value interpolated directly without helper → fire
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const countSqlFlows = (flows: Array<{ sink_type?: string }> | undefined) =>
  (flows ?? []).filter(f => f.sink_type === 'sql_injection').length;

describe('cognium-dev #215 — Python safe_sql_identifier_quote FP suppression', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('FP — safe_col helper + ? placeholder for values produces zero sql_injection', async () => {
    const code = `import re, sqlite3
from flask import Flask, request
app = Flask(__name__)

def safe_col(name: str) -> str:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        raise ValueError("bad identifier")
    return name

@app.route("/lookup")
def lookup():
    col_name = request.args.get("col", "id")
    value = request.args.get("v", "")
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    col = safe_col(col_name)
    cur.execute(f"SELECT * FROM t WHERE {col} = ?", (value,))
    return "ok"
`;
    const r = await analyze(code, 'lookup.py', 'python');
    expect(countSqlFlows(r.taint?.flows)).toBe(0);
  });

  it('recall — helper missing raise still fires sql_injection', async () => {
    const code = `import re, sqlite3
from flask import Flask, request
app = Flask(__name__)

def unsafe_col(name: str) -> str:
    # No raise — pattern check is advisory only
    re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name)
    return name

@app.route("/lookup")
def lookup():
    col_name = request.args.get("col", "id")
    value = request.args.get("v", "")
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    col = unsafe_col(col_name)
    cur.execute(f"SELECT * FROM t WHERE {col} = ?", (value,))
    return "ok"
`;
    const r = await analyze(code, 'lookup_no_raise.py', 'python');
    expect(countSqlFlows(r.taint?.flows)).toBeGreaterThan(0);
  });

  it('recall — value concatenated (no ? placeholder) still fires sql_injection', async () => {
    const code = `import re, sqlite3
from flask import Flask, request
app = Flask(__name__)

def safe_col(name: str) -> str:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        raise ValueError("bad identifier")
    return name

@app.route("/lookup")
def lookup():
    col_name = request.args.get("col", "id")
    value = request.args.get("v", "")
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    col = safe_col(col_name)
    cur.execute(f"SELECT * FROM t WHERE {col} = '{value}'")
    return "ok"
`;
    const r = await analyze(code, 'lookup_concat.py', 'python');
    expect(countSqlFlows(r.taint?.flows)).toBeGreaterThan(0);
  });

  it('recall — wildcard regex in helper still fires sql_injection', async () => {
    const code = `import re, sqlite3
from flask import Flask, request
app = Flask(__name__)

def wildcard_col(name: str) -> str:
    if not re.fullmatch(r".*", name):
        raise ValueError("bad identifier")
    return name

@app.route("/lookup")
def lookup():
    col_name = request.args.get("col", "id")
    value = request.args.get("v", "")
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    col = wildcard_col(col_name)
    cur.execute(f"SELECT * FROM t WHERE {col} = ?", (value,))
    return "ok"
`;
    const r = await analyze(code, 'lookup_wildcard.py', 'python');
    expect(countSqlFlows(r.taint?.flows)).toBeGreaterThan(0);
  });

  it('recall — no helper, value interpolated directly still fires sql_injection', async () => {
    const code = `import sqlite3
from flask import Flask, request
app = Flask(__name__)

@app.route("/lookup")
def lookup():
    col_name = request.args.get("col", "id")
    value = request.args.get("v", "")
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM t WHERE {col_name} = ?", (value,))
    return "ok"
`;
    const r = await analyze(code, 'lookup_no_helper.py', 'python');
    expect(countSqlFlows(r.taint?.flows)).toBeGreaterThan(0);
  });
});
