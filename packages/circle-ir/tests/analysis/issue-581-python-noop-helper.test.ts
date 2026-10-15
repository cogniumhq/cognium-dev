/**
 * cognium-dev#581 (slice, Python): a same-file `def` whose body is a single
 * `return <expr>` built only from its own parameter, string literals, `+`, and
 * the pass-through methods `strip` / `lstrip` / `rstrip` / `lower` / `upper` /
 * `str()` is not credited as a sanitizer by the class-less `sanitize` row. A
 * helper that really escapes (replace, re.sub, html.escape, a branch, a loop)
 * keeps today's by-name credit.
 *
 * SAST regression fixtures — the handlers are deliberately vulnerable.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

async function sqlLines(code: string, file = 'lookup.py'): Promise<number[]> {
  const r = await analyze(code, file, 'python');
  return [...new Set((r.taint.flows ?? []).filter((f) => f.sink_type === 'sql_injection').map((f) => f.sink_line))].sort((a, b) => a - b);
}

const app = (helper: string, name = 'sanitize') => `import sqlite3
from flask import Flask, request
app = Flask(__name__)
${helper.replace(/sanitize/g, name)}
@app.route("/a")
def by_id():
    uid = ${name}(request.args.get("id"))
    db = sqlite3.connect("d.db")
    db.execute("SELECT * FROM t WHERE id='" + uid + "'")
    return "ok"
`;

describe('cognium-dev#581 Python no-op helper is not credited by name', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // sink line = 5 helper lines (3 + helper) ... computed per fixture
  const sinkLine = (code: string) => code.split('\n').findIndex((l) => l.includes('db.execute')) + 1;

  it('lookup.py: a strip-only sanitize() helper reports sql_injection', async () => {
    const code = app('def sanitize(v):\n    return v.strip()');
    expect(await sqlLines(code)).toEqual([sinkLine(code)]);
  });

  it('lookup_escaped.py: a sanitize() that really escapes keeps its credit', async () => {
    const code = app(`def sanitize(v):\n    return v.replace("'", "''")`);
    expect(await sqlLines(code, 'lookup_escaped.py')).toEqual([]);
  });

  it('the same strip-only helper under another name reports (control)', async () => {
    const code = app('def sanitize(v):\n    return v.strip()', 'tidy');
    expect(await sqlLines(code)).toEqual([sinkLine(code)]);
  });

  it('a one-line def, lower/upper/str() pass-throughs and literal wrapping are no-ops', async () => {
    for (const body of [
      'def sanitize(v): return v.strip()',
      'def sanitize(v):\n    return str(v).lower()',
      'def sanitize(v):\n    return "x" + v.upper().lstrip() + "y"',
      'def sanitize(value):\n    return value.rstrip()',
    ]) {
      const code = app(body);
      expect(await sqlLines(code), body).toEqual([sinkLine(code)]);
    }
  });

  it('a helper with any other body keeps the by-name credit', async () => {
    for (const body of [
      'import re\ndef sanitize(v):\n    return re.sub(r"[^a-z]", "", v)',
      'import html\ndef sanitize(v):\n    return html.escape(v)',
      'def sanitize(v):\n    if v:\n        return v.strip()\n    return ""',
      'def sanitize(v):\n    out = v.strip()\n    return out',
      'def sanitize(v):\n    return "".join(c for c in v if c.isalnum())',
      'def sanitize(v):\n    return v.strip().replace(";", "")',
    ]) {
      const code = app(body);
      expect(await sqlLines(code), body).toEqual([]);
    }
  });

  it('a name with a second, escaping definition keeps the by-name credit', async () => {
    const code = app('def sanitize(v):\n    return v.strip()\ndef sanitize(v, extra):\n    return v.replace("\'", "")');
    expect(await sqlLines(code)).toEqual([]);
  });

  it('a class-scoped sanitizer row is untouched: html.escape on a value still clears xss', async () => {
    const code = `import html
from flask import Flask, request
app = Flask(__name__)
@app.route("/a")
def show():
    name = html.escape(request.args.get("n"))
    return "<p>" + name + "</p>"
`;
    const r = await analyze(code, 'show.py', 'python');
    expect((r.taint.flows ?? []).filter((f) => f.sink_type === 'xss')).toHaveLength(0);
  });
});
