/**
 * cognium-dev#581 (slice, JavaScript): a same-file `function` whose body is a
 * single `return <expr>` built only from its own parameter, string literals, `+`,
 * and the pass-through calls `trim` / `toLowerCase` / `toUpperCase` /
 * `toString` / `String()` is not credited as a sanitizer by the class-less
 * `sanitize` / `escape` rows. A helper that really escapes keeps today's
 * by-name credit.
 *
 * SAST regression fixtures — the handlers are deliberately vulnerable.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

async function sqlLines(code: string, file = 'lookup.js'): Promise<number[]> {
  const r = await analyze(code, file, 'javascript');
  return [...new Set((r.taint.flows ?? []).filter((f) => f.sink_type === 'sql_injection').map((f) => f.sink_line))].sort((a, b) => a - b);
}

async function xssLines(code: string, file = 'page.js'): Promise<number[]> {
  const r = await analyze(code, file, 'javascript');
  return [...new Set((r.taint.flows ?? []).filter((f) => f.sink_type === 'xss').map((f) => f.sink_line))].sort((a, b) => a - b);
}

const app = (helper: string, name = 'sanitize') => `const express = require("express");
const db = { query: () => {} };
const app = express();
${helper.replace(/sanitize/g, name)}
app.get("/a", (req, res) => {
  const uid = ${name}(req.query.id);
  db.query("SELECT * FROM t WHERE id=" + uid);
  res.end("ok");
});
`;

const lineOf = (code: string, needle: string) => code.split('\n').findIndex((l) => l.includes(needle)) + 1;

describe('cognium-dev#581 JavaScript no-op helper is not credited by name', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('lookup.js: a trim-only sanitize() helper reports sql_injection', async () => {
    const code = app('function sanitize(v) { return v.trim(); }');
    expect(await sqlLines(code)).toEqual([lineOf(code, 'db.query')]);
  });

  it('page_safe.js: a helper that really escapes keeps its credit', async () => {
    const code = `function escape(v) { return v.replace(/</g, "&lt;").replace(/>/g, "&gt;"); }
const express = require("express");
const app = express();
app.get("/p", (req, res) => {
  const x = req.query.x;
  res.write("<p>" + escape(x) + "</p>");
  res.end();
});
`;
    expect(await xssLines(code, 'page_safe.js')).toEqual([]);
  });

  it('the same trim-only helper under another name reports (control)', async () => {
    const code = app('function sanitize(v) { return v.trim(); }', 'tidy');
    expect(await sqlLines(code)).toEqual([lineOf(code, 'db.query')]);
  });

  it('escape trim-only is not credited; decorate with literal wrap still reports xss', async () => {
    const code = `function escape(v) { return v.trim(); }
function decorate(v) { return "[" + v.trim() + "]"; }
const express = require("express");
const app = express();
app.get("/p", (req, res) => {
  const x = req.query.x;
  res.write(escape(x));
  res.write(decorate(x));
  res.end();
});
`;
    const esc = lineOf(code, 'res.write(escape');
    const dec = lineOf(code, 'res.write(decorate');
    expect(await xssLines(code)).toEqual([esc, dec].sort((a, b) => a - b));
  });

  it('a helper with a branch keeps the by-name credit', async () => {
    const code = `function escape(v) {
  if (v) return v.replace(/</g, "&lt;").replace(/>/g, "&gt;");
  return "";
}
const express = require("express");
const app = express();
app.get("/p", (req, res) => {
  const x = req.query.x;
  res.write("<p>" + escape(x) + "</p>");
  res.end();
});
`;
    expect(await xssLines(code, 'page_branch.js')).toEqual([]);
  });
});
