/**
 * Sink configuration coverage tests for issues #44, #45, #46, #48, #54, #65.
 *
 * Each issue closes a gap where a real-world vulnerability pattern was not
 * matched by the default sink registry. These tests pin the expected
 * behaviour as plain `analyzeTaint()` smoke tests on minimal inputs.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initParser, parse } from '../../src/core/parser.js';
import { extractCalls } from '../../src/core/extractors/calls.js';
import { extractTypes } from '../../src/core/extractors/types.js';
import { analyzeTaint } from '../../src/analysis/taint-matcher.js';
import { getDefaultConfig, DEFAULT_SANITIZERS } from '../../src/analysis/config-loader.js';

describe('Sink config coverage gaps (issues #44, #45, #46, #48, #54, #65)', () => {
  beforeAll(async () => {
    await initParser();
  });

  // ─────────────────────────────────────────────────────────────────────────
  // Issue #44 — log_injection sinks for Java and JavaScript/TypeScript
  // ─────────────────────────────────────────────────────────────────────────

  it('#44 Java: slf4j Logger.info is a log_injection sink', async () => {
    const code = `
import org.slf4j.Logger;
public class C {
    private Logger log;
    public void handle(String userInput) {
        log.info("Search: {}", userInput);
    }
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const taint = analyzeTaint(calls, types, getDefaultConfig(), undefined, 'java');

    const logSink = taint.sinks.find(s => s.type === 'log_injection');
    expect(logSink).toBeDefined();
    expect(logSink!.cwe).toBe('CWE-117');
  });

  it('#44 Java: Logger.warn / error / debug are log_injection sinks', async () => {
    const code = `
public class C {
    private Logger log;
    public void handle(String x) {
        log.warn("Audit: {}", x);
        log.error("Err: {}", x);
        log.debug("Dbg: {}", x);
    }
}
`;
    const tree = await parse(code, 'java');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const taint = analyzeTaint(calls, types, getDefaultConfig(), undefined, 'java');

    const logSinks = taint.sinks.filter(s => s.type === 'log_injection');
    expect(logSinks.length).toBeGreaterThanOrEqual(3);
  });

  it('#44 JS: console.log is a log_injection sink', async () => {
    const code = `
function handle(req) {
  const action = req.body.action;
  console.log("AUDIT action=" + action);
}
`;
    const tree = await parse(code, 'javascript');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const taint = analyzeTaint(calls, types, getDefaultConfig(), undefined, 'javascript');

    const logSink = taint.sinks.find(s => s.type === 'log_injection');
    expect(logSink).toBeDefined();
    expect(logSink!.cwe).toBe('CWE-117');
  });

  it('#44 JS: console.warn / error / info are log_injection sinks', async () => {
    const code = `
function handle(req) {
  console.warn(req.query.x);
  console.error(req.query.x);
  console.info(req.query.x);
}
`;
    const tree = await parse(code, 'javascript');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const taint = analyzeTaint(calls, types, getDefaultConfig(), undefined, 'javascript');

    const logSinks = taint.sinks.filter(s => s.type === 'log_injection');
    expect(logSinks.length).toBeGreaterThanOrEqual(3);
  });

  it('#44 JS: console.log fires with method = "log"', async () => {
    const code = `console.log("plain string");`;
    const tree = await parse(code, 'javascript');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const taint = analyzeTaint(calls, types, getDefaultConfig(), undefined, 'javascript');

    const logSink = taint.sinks.find(s => s.type === 'log_injection');
    expect(logSink).toBeDefined();
    expect(logSink!.method).toBe('log');
  });

  // ─────────────────────────────────────────────────────────────────────────
  // Issue #45 — nosql_injection for mongoose Model / Query and classless
  //            MongoDB-specific method names
  // ─────────────────────────────────────────────────────────────────────────

  it('#45 mongoose Model.findOne is a nosql_injection sink (classless match)', async () => {
    // The receiver `User` is a mongoose Model. Even when the analyzer cannot
    // resolve the receiver class to `Model`, the classless+language-scoped
    // entry should still match by method name alone.
    const code = `
async function lookup(req) {
  const username = req.body.username;
  return await User.findOne({ username });
}
`;
    const tree = await parse(code, 'javascript');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const taint = analyzeTaint(calls, types, getDefaultConfig(), undefined, 'javascript');

    const sink = taint.sinks.find(s => s.type === 'nosql_injection');
    expect(sink).toBeDefined();
    expect(sink!.cwe).toBe('CWE-943');
  });

  it('#45 mongoose findOneAndUpdate / updateOne / deleteOne match by method name', async () => {
    const code = `
async function ops(req) {
  await User.findOneAndUpdate({ id: req.body.id }, { $set: { name: req.body.name } });
  await User.updateOne({ id: req.body.id }, { $set: { x: 1 } });
  await User.deleteOne({ id: req.body.id });
}
`;
    const tree = await parse(code, 'javascript');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const taint = analyzeTaint(calls, types, getDefaultConfig(), undefined, 'javascript');

    const sinks = taint.sinks.filter(s => s.type === 'nosql_injection');
    expect(sinks.length).toBeGreaterThanOrEqual(3);
  });

  // ─────────────────────────────────────────────────────────────────────────
  // Issue #46 — Express open_redirect (classless res.redirect)
  // ─────────────────────────────────────────────────────────────────────────

  it('#46 Express res.redirect is an open_redirect sink (classless match)', async () => {
    const code = `
function handler(req, res) {
  const next = req.query.next;
  res.redirect(next);
}
`;
    const tree = await parse(code, 'javascript');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const taint = analyzeTaint(calls, types, getDefaultConfig(), undefined, 'javascript');

    const sink = taint.sinks.find(s => s.type === 'open_redirect');
    expect(sink).toBeDefined();
    expect(sink!.cwe).toBe('CWE-601');
  });

  it('#46 TypeScript res.redirect is an open_redirect sink', async () => {
    const code = `
function handler(req: any, res: any) {
  const next: string = req.query.next;
  res.redirect(next);
}
`;
    const tree = await parse(code, 'typescript');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const taint = analyzeTaint(calls, types, getDefaultConfig(), undefined, 'typescript');

    const sink = taint.sinks.find(s => s.type === 'open_redirect');
    expect(sink).toBeDefined();
  });

  // ─────────────────────────────────────────────────────────────────────────
  // Issue #54 — Jinja2 render_template_string mislabel (xss → code_injection)
  // ─────────────────────────────────────────────────────────────────────────

  it('#54 Python: render_template_string is code_injection (CWE-94), not xss', async () => {
    const code = `
from flask import render_template_string, request
def handler():
    name = request.args.get("name", "")
    template = "<h1>Hello " + name + "</h1>"
    return render_template_string(template)
`;
    const tree = await parse(code, 'python');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const taint = analyzeTaint(calls, types, getDefaultConfig(), undefined, 'python');

    const sink = taint.sinks.find(s => s.location.includes('render_template_string'));
    expect(sink).toBeDefined();
    // Closes #54: was previously xss/CWE-79; should now be code_injection/CWE-94.
    expect(sink!.type).toBe('code_injection');
    expect(sink!.cwe).toBe('CWE-94');
  });

  it('#54 Python: render_template_string emits no xss/CWE-79 sink on the same call', async () => {
    const code = `
def handler():
    template = "<h1>Hello " + name + "</h1>"
    return render_template_string(template)
`;
    const tree = await parse(code, 'python');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const taint = analyzeTaint(calls, types, getDefaultConfig(), undefined, 'python');

    const rtsSinks = taint.sinks.filter(s => s.location.includes('render_template_string'));
    expect(rtsSinks.length).toBeGreaterThan(0);
    for (const s of rtsSinks) {
      expect(s.type).not.toBe('xss');
      expect(s.cwe).not.toBe('CWE-79');
    }
  });

  // ─────────────────────────────────────────────────────────────────────────
  // Issue #48 part 2 — Python path_traversal sanitizers: realpath/abspath
  // (normpath was already registered prior to this change)
  // ─────────────────────────────────────────────────────────────────────────

  it('#48 Python: os.path.realpath is registered as a path_traversal sanitizer', () => {
    const sanitizer = DEFAULT_SANITIZERS.find(
      s => s.method === 'realpath' && s.class === 'os.path',
    );
    expect(sanitizer).toBeDefined();
    expect(sanitizer!.removes).toContain('path_traversal');
  });

  it('#48 Python: os.path.abspath is registered as a path_traversal sanitizer', () => {
    const sanitizer = DEFAULT_SANITIZERS.find(
      s => s.method === 'abspath' && s.class === 'os.path',
    );
    expect(sanitizer).toBeDefined();
    expect(sanitizer!.removes).toContain('path_traversal');
  });

  it('#48 Python: os.path.normpath remains a path_traversal sanitizer (regression)', () => {
    const sanitizer = DEFAULT_SANITIZERS.find(
      s => s.method === 'normpath' && s.class === 'os.path',
    );
    expect(sanitizer).toBeDefined();
    expect(sanitizer!.removes).toContain('path_traversal');
  });

  it('#48 Python: realpath/abspath also registered on bare `path` receiver', () => {
    // Covers `import os.path as path` style imports where the matched
    // receiver simple-name is `path` rather than `os.path`.
    const realpath = DEFAULT_SANITIZERS.find(
      s => s.method === 'realpath' && s.class === 'path',
    );
    const abspath = DEFAULT_SANITIZERS.find(
      s => s.method === 'abspath' && s.class === 'path',
    );
    expect(realpath).toBeDefined();
    expect(abspath).toBeDefined();
  });

  it('#48 Python: os.path.realpath produces a sanitizer entry on real code', async () => {
    const code = `
import os.path
def handler(filename):
    candidate = os.path.realpath(os.path.join("/uploads", filename))
    with open(candidate, "r") as fh:
        return fh.read()
`;
    const tree = await parse(code, 'python');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const taint = analyzeTaint(calls, types, getDefaultConfig(), undefined, 'python');

    const sanitizer = taint.sanitizers?.find(s => s.method.includes('realpath'));
    expect(sanitizer).toBeDefined();
  });

  it('#48 Python: os.path.abspath produces a sanitizer entry on real code', async () => {
    const code = `
import os.path
def handler(filename):
    candidate = os.path.abspath(filename)
    return candidate
`;
    const tree = await parse(code, 'python');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const taint = analyzeTaint(calls, types, getDefaultConfig(), undefined, 'python');

    const sanitizer = taint.sanitizers?.find(s => s.method.includes('abspath'));
    expect(sanitizer).toBeDefined();
  });

  // ─────────────────────────────────────────────────────────────────────────
  // Issue #65 / #48 part 3 — `cur.execute(...)` was mis-classified as xss
  // (CWE-79) because the receiver `cur` (length 3) prefix-matched the XWiki
  // XSS sink class `CurrentTimePlugin` via the CamelCase word prefix
  // heuristic in `receiverMightBeClass` (`'current'.startsWith('cur')` with
  // ratio 3/7 ≥ 0.4). The fix adds `cur` to the `ambiguousIdentifiers`
  // denylist and maps `cur`/`cursor` → `Cursor` in `commonMappings`, and
  // adds a 40% coverage gate to the bare prefix/suffix heuristic.
  // ─────────────────────────────────────────────────────────────────────────

  it('#65 Python: psycopg2 cur.execute("...%s", (param,)) emits no xss sink', async () => {
    const code = `
from flask import request, jsonify
def handler():
    name = request.args.get("name", "")
    cur.execute("SELECT * FROM users WHERE name = %s", (name,))
    return jsonify(cur.fetchall())
`;
    const tree = await parse(code, 'python');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const taint = analyzeTaint(calls, types, getDefaultConfig(), undefined, 'python');

    const xssOnExecute = taint.sinks.find(
      s => s.location.includes('cur.execute') && s.type === 'xss',
    );
    expect(xssOnExecute).toBeUndefined();
  });

  it('#65 Python: sqlite3 cur.execute("...?", (param,)) emits no xss sink', async () => {
    const code = `
from flask import request, jsonify
def handler():
    username = request.args.get("username", "")
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    return jsonify(cur.fetchall())
`;
    const tree = await parse(code, 'python');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const taint = analyzeTaint(calls, types, getDefaultConfig(), undefined, 'python');

    const xssOnExecute = taint.sinks.find(
      s => s.location.includes('cur.execute') && s.type === 'xss',
    );
    expect(xssOnExecute).toBeUndefined();
  });

  it('#65 Python: psycopg2 parameterized execute emits no sinks at all', async () => {
    // Both parameterized SQL (placeholder + params tuple, no concat) and the
    // xss mislabel must be suppressed. Combined assertion mirrors the issue
    // acceptance ("safe_api.py produces 0 security findings" for this case).
    const code = `
def handler(name):
    cur.execute("SELECT * FROM users WHERE name = %s", (name,))
`;
    const tree = await parse(code, 'python');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const taint = analyzeTaint(calls, types, getDefaultConfig(), undefined, 'python');

    const onExecute = taint.sinks.filter(s => s.location.includes('cur.execute'));
    expect(onExecute).toEqual([]);
  });

  it('#65 Python: legitimate string-concatenation SQL injection still fires', async () => {
    // Regression guard: the parameterized-query skip must NOT swallow a real
    // SQLi where the query is built by string concatenation.
    const code = `
def handler(name):
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
`;
    const tree = await parse(code, 'python');
    const calls = extractCalls(tree);
    const types = extractTypes(tree);
    const taint = analyzeTaint(calls, types, getDefaultConfig(), undefined, 'python');

    const sqli = taint.sinks.find(
      s => s.location.includes('cur.execute') && s.type === 'sql_injection',
    );
    expect(sqli).toBeDefined();
  });
});
