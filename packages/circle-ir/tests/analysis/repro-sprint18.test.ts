/**
 * Repro for cognium-dev Sprint 18 — Python consolidation.
 *
 * Issues in scope:
 *   - #100 — Python safe-corpus FP regressions (4 distinct fix families):
 *       parameterized SQL, type-cast barrier, realpath+startswith guard,
 *       custom-sanitizer wrapper.
 *   - #96 — Conventional FN subset (3 of 5): urllib.request.urlretrieve
 *     (ssrf + path_traversal), git format-patch filename argv,
 *     dulwich-style Path(repo) / entry.path → open().
 *   - #65 — psycopg2 / sqlite3 parameterized-query recognition
 *     (`cursor.execute("... %s", (uid,))`).
 *
 * Layout:
 *   - #100.1 — parameterized SQL safe → no sql_injection
 *   - #100.2 — int() cast then xss render → no xss
 *   - #100.3 — realpath() + startswith() guard → no path_traversal
 *   - #100.4 — companion safe SQL (different shape) → no sql_injection
 *   - #100.5 — custom sanitizer wrapper for shlex.quote → no command_injection
 *   - #100.6 — wrong-context sanitizer (html.escape used as SQL value) → still fires
 *   - #100.7 — fake sanitizer (identity function) → still fires
 *   - #96.1 — urllib.request.urlretrieve → ssrf + path_traversal
 *   - #96.2 — subprocess.run list-form with tainted argv → command_injection
 *   - #96.3 — Path(repo_dir) / entry.path → open() → path_traversal
 *   - #65.1 — psycopg2 placeholder + tuple → no sql_injection
 *   - #65.2 — psycopg2 f-string interpolation → sql_injection (negative control)
 *
 * Target release: circle-ir 3.68.0 / cognium-dev 3.68.0
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('cognium-dev Python consolidation — Sprint 18', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const hasFlow = (
    flows: Array<{ sink_type?: string; sink_line?: number; source_line?: number }> | undefined,
    sinkType: string,
    sinkLine?: number,
  ) =>
    (flows ?? []).some(
      (f) => f.sink_type === sinkType && (sinkLine === undefined || f.sink_line === sinkLine),
    );

  // ---------------------------------------------------------------------------
  // #100 — FP suppression fixtures (5)
  // ---------------------------------------------------------------------------

  it('#100.1 — psycopg2 parameterized execute should NOT fire sql_injection', async () => {
    const code = `from flask import request
import psycopg2
conn = psycopg2.connect("...")
def get_user():
    uid = request.args.get('id', '')
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s", (uid,))
    return cur.fetchone()
`;
    const r = await analyze(code, 't100_1.py', 'python');
    expect(hasFlow(r.taint.flows, 'sql_injection')).toBe(false);
  });

  it('#100.2 — int() cast then f-string render should NOT fire xss', async () => {
    const code = `from flask import request
def view():
    n = int(request.args.get('n', '0'))
    return f"<p>count={n}</p>"
`;
    const r = await analyze(code, 't100_2.py', 'python');
    expect(hasFlow(r.taint.flows, 'xss')).toBe(false);
  });

  it('#100.3 — realpath() + startswith() guard should NOT fire path_traversal', async () => {
    const code = `from flask import request
import os
SAFE_DIR = '/var/app/data'
def read_safe():
    name = request.args.get('name', '')
    p = os.path.realpath(os.path.join(SAFE_DIR, name))
    if not p.startswith(SAFE_DIR):
        return 'forbidden', 403
    return open(p).read()
`;
    const r = await analyze(code, 't100_3.py', 'python');
    expect(hasFlow(r.taint.flows, 'path_traversal')).toBe(false);
  });

  it('#100.4 — sqlite3 parameterized execute (? placeholder) should NOT fire sql_injection', async () => {
    const code = `from flask import request
import sqlite3
conn = sqlite3.connect('app.db')
def find_post():
    pid = request.args.get('pid', '')
    cur = conn.cursor()
    cur.execute("SELECT * FROM posts WHERE id = ?", (pid,))
    return cur.fetchone()
`;
    const r = await analyze(code, 't100_4.py', 'python');
    expect(hasFlow(r.taint.flows, 'sql_injection')).toBe(false);
  });

  it('#100.5 — custom sanitizer wrapper around shlex.quote should NOT fire command_injection', async () => {
    const code = `from flask import request
import subprocess
import shlex
def my_clean(x):
    return shlex.quote(x)
def run_it():
    name = request.args.get('name', '')
    subprocess.run('echo ' + my_clean(name), shell=True)
`;
    const r = await analyze(code, 't100_5.py', 'python');
    expect(hasFlow(r.taint.flows, 'command_injection')).toBe(false);
  });

  // ---------------------------------------------------------------------------
  // #100 — Keep-firing negative locks (2)
  // ---------------------------------------------------------------------------

  it('#100.6 — wrong-context sanitizer (html.escape used in SQL) should STILL fire sql_injection', async () => {
    const code = `from flask import request
import psycopg2
import html
conn = psycopg2.connect("...")
def get_user():
    name = request.args.get('name', '')
    safe = html.escape(name)
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + safe + "'")
    return cur.fetchone()
`;
    const r = await analyze(code, 't100_6.py', 'python');
    expect(hasFlow(r.taint.flows, 'sql_injection')).toBe(true);
  });

  it('#100.7 — fake sanitizer (identity function) should STILL fire command_injection', async () => {
    const code = `from flask import request
import subprocess
def safe(x):
    return x
def run_it():
    name = request.args.get('name', '')
    subprocess.run('echo ' + safe(name), shell=True)
`;
    const r = await analyze(code, 't100_7.py', 'python');
    expect(hasFlow(r.taint.flows, 'command_injection')).toBe(true);
  });

  // ---------------------------------------------------------------------------
  // #96 — Conventional FN fixtures (3)
  // ---------------------------------------------------------------------------

  it('#96.1 — urllib.request.urlretrieve should fire ssrf AND path_traversal', async () => {
    const code = `from flask import request
import urllib.request
def fetch():
    url = request.args.get('url', '')
    dest = request.args.get('dest', '')
    urllib.request.urlretrieve(url, dest)
`;
    const r = await analyze(code, 't96_1.py', 'python');
    expect(hasFlow(r.taint.flows, 'ssrf')).toBe(true);
    expect(hasFlow(r.taint.flows, 'path_traversal')).toBe(true);
  });

  it('#96.2 — subprocess.run string-form with tainted concat (shell=True) should fire command_injection', async () => {
    // Note: the original #96 L60 case (`subprocess.run(['git', 'format-patch',
    // '--subject=' + subj])`) is deliberately suppressed by the safe-shape
    // skip in `isSafePythonSubprocessCall` (cognium-dev #48): list-form
    // without `shell=True` invokes execve() directly with no shell
    // interpolation. The true vulnerability there is path_traversal via the
    // patch-file name git creates from the subject — that requires modeling
    // subprocess side-effects and is deferred to Sprint 19.
    //
    // This fixture instead locks the genuinely vulnerable string-form +
    // shell=True shape, which is the real command-injection vector covered
    // by the existing sink model.
    const code = `from flask import request
import subprocess
def patch():
    subj = request.args.get('subject', '')
    subprocess.run('git format-patch --subject=' + subj + ' HEAD~1', shell=True)
`;
    const r = await analyze(code, 't96_2.py', 'python');
    expect(hasFlow(r.taint.flows, 'command_injection')).toBe(true);
  });

  it('#96.3 — Path(repo_dir) / entry.path flow into open() should fire path_traversal', async () => {
    const code = `from flask import request
from pathlib import Path
def checkout():
    entry_path = request.args.get('path', '')
    repo_dir = '/var/repos/proj'
    f = open(Path(repo_dir) / entry_path)
    return f.read()
`;
    const r = await analyze(code, 't96_3.py', 'python');
    expect(hasFlow(r.taint.flows, 'path_traversal')).toBe(true);
  });

  // ---------------------------------------------------------------------------
  // #65 — Parameterized SQL recognition (placeholder + tuple)
  // ---------------------------------------------------------------------------

  it('#65.1 — psycopg2 placeholder + tuple should NOT fire sql_injection', async () => {
    const code = `from flask import request
import psycopg2
conn = psycopg2.connect("...")
def lookup():
    uid = request.args.get('id', '')
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s", (uid,))
    return cur.fetchone()
`;
    const r = await analyze(code, 't65_1.py', 'python');
    expect(hasFlow(r.taint.flows, 'sql_injection')).toBe(false);
  });

  it('#65.2-neg — psycopg2 f-string interpolation should STILL fire sql_injection', async () => {
    const code = `from flask import request
import psycopg2
conn = psycopg2.connect("...")
def lookup():
    uid = request.args.get('id', '')
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE id = {uid}")
    return cur.fetchone()
`;
    const r = await analyze(code, 't65_2_neg.py', 'python');
    expect(hasFlow(r.taint.flows, 'sql_injection')).toBe(true);
  });
});
