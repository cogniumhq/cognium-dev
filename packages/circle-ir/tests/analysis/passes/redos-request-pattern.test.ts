/**
 * `redos` (CWE-1333) taint flows on JS/TS: a request value used as the
 * pattern of `new RegExp(...)` on the same line as its read. Before this
 * change the inline (colocated) flow was never produced because `redos` was
 * missing from the request sources' reach map; only a value passed through a
 * local reached the sink.
 *
 * Fixtures in `tests/fixtures/redos-request-pattern/`:
 *   - vulnerable.ts  — every FLAG line gives exactly one `redos` flow
 *   - fixed.ts       — the value escaped first (`escape-string-regexp`,
 *                      `_.escapeRegExp`): zero
 *   - safe-shapes.ts — the request value as the subject: zero
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { analyze, initAnalyzer } from '../../../src/analyzer.js';

const FIXTURES = resolve(dirname(fileURLToPath(import.meta.url)), '../../fixtures/redos-request-pattern');
const fixture = (name: string) => readFileSync(resolve(FIXTURES, name), 'utf8');

type R = Awaited<ReturnType<typeof analyze>>;
const redosSinkLines = (r: R) => [...new Set((r.taint.flows ?? []).filter(f => f.sink_type === 'redos').map(f => f.sink_line))].sort((a, b) => a - b);

describe('redos: request value as a RegExp pattern', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('vulnerable.ts: a flow on every FLAG line', async () => {
    const code = fixture('vulnerable.ts');
    const expected = code.split('\n').flatMap((l, i) => (l.includes('// FLAG') ? [i + 1] : []));
    expect(redosSinkLines(await analyze(code, 'vulnerable.ts', 'typescript'))).toEqual(expected);
  });

  it('fixed.ts: escaped values give no flow', async () => {
    expect(redosSinkLines(await analyze(fixture('fixed.ts'), 'fixed.ts', 'typescript'))).toEqual([]);
  });

  it('safe-shapes.ts: the request value as the subject gives no flow', async () => {
    expect(redosSinkLines(await analyze(fixture('safe-shapes.ts'), 'safe-shapes.ts', 'typescript'))).toEqual([]);
  });

  it('JavaScript: a named Express handler', async () => {
    const code = [
      "const express = require('express');",
      'const app = express();',
      "app.get('/find', function find(req, res) {",
      '  const re = new RegExp(req.query.pattern);',
      "  res.json({ ok: re.test('abc') });",
      '});',
    ].join('\n');
    expect(redosSinkLines(await analyze(code, 'app.js', 'javascript'))).toEqual([4]);
  });

  it('Java: a request value as the subject of String.matches is not a pattern', async () => {
    const code = [
      'import javax.servlet.http.*;',
      'public class C extends HttpServlet {',
      '  protected void doGet(HttpServletRequest request, HttpServletResponse response) {',
      '    boolean ok = request.getParameter("x").matches("[a-z]+");',
      '  }',
      '}',
    ].join('\n');
    expect(redosSinkLines(await analyze(code, 'C.java', 'java'))).toEqual([]);
  });
});
