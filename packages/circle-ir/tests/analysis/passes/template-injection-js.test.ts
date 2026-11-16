/**
 * JS/TS `template_injection` (CWE-1336): a request value used as the source
 * of a server-side template (`Handlebars.compile`, `ejs.render` /
 * `ejs.compile`, `pug.render` / `pug.compile`, `nunjucks.renderString`).
 *
 * Fixtures in `tests/fixtures/template-injection/`:
 *   - vulnerable.ts  — every FLAG line gives exactly one finding
 *   - fixed.ts       — the same handlers with a fixed template and the value
 *                      passed as data: zero (a fix must read `gone`)
 *   - safe-shapes.ts — near misses: zero
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { analyze, initAnalyzer } from '../../../src/analyzer.js';
import { blankJsStringText, firstJsCallArg } from '../../../src/analysis/passes/language-sources-pass.js';

const FIXTURES = resolve(dirname(fileURLToPath(import.meta.url)), '../../fixtures/template-injection');
const fixture = (name: string) => readFileSync(resolve(FIXTURES, name), 'utf8');

type R = Awaited<ReturnType<typeof analyze>>;
const ssti = (r: R) => (r.findings ?? []).filter(f => f.rule_id === 'template_injection');

describe('template_injection (JS): argument text', () => {
  it.each([
    ['ejs.render(tpl, { a: 1 })', 'tpl'],
    ["ejs.render('a, b', { a })", "'a, b'"],
    ['pug.render(f(a, b), c)', 'f(a, b)'],
    ['x.compile(`a${b}`)', '`a${b}`'],
    ['ejs.render(', ''],
    ["h.compile('it\\'s', x)", "'it\\'s'"],
  ])('%s → first argument %s', (call, arg) => {
    expect(firstJsCallArg(call, call.indexOf('(') + 1)).toBe(arg);
  });

  it.each([
    ["'<p><%= name %></p>'", "''"],
    ['"a \\" name"', "''"],
    ['`<h1>${title}</h1>`', "'' title"],
    ['`<h1><%= title %></h1>`', "''"],
    ['tpl + "x"', "tpl + ''"],
  ])('%s blanks to %s', (expr, out) => {
    expect(blankJsStringText(expr)).toBe(out);
  });
});

describe('template_injection (JS): fixtures', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('vulnerable.ts: one finding per FLAG line, CWE-1336', async () => {
    const code = fixture('vulnerable.ts');
    const expected = code.split('\n').flatMap((l, i) => (l.includes('// FLAG') ? [i + 1] : []));
    const found = ssti(await analyze(code, 'vulnerable.ts', 'typescript'));
    expect(found.map(f => f.line).sort((a, b) => a - b)).toEqual(expected);
    for (const f of found) expect(f.cwe).toBe('CWE-1336');
  });

  it('fixed.ts: no finding', async () => {
    expect(ssti(await analyze(fixture('fixed.ts'), 'fixed.ts', 'typescript'))).toEqual([]);
  });

  it('safe-shapes.ts: no finding', async () => {
    expect(ssti(await analyze(fixture('safe-shapes.ts'), 'safe-shapes.ts', 'typescript'))).toEqual([]);
  });

  it('JavaScript: a fixed EJS template naming the request variable is not a finding', async () => {
    const code = [
      "const express = require('express');",
      "const ejs = require('ejs');",
      'const app = express();',
      "app.get('/greet', function greet(req, res) {",
      '  const name = req.query.name;',
      "  res.send(ejs.render('<p>Hello <%= name %></p>', { name }));",
      '});',
      "app.get('/raw', function raw(req, res) {",
      '  const tpl = req.query.tpl;',
      "  res.send(ejs.render(tpl, { user: 'x' }));",
      '});',
    ].join('\n');
    expect(ssti(await analyze(code, 'app.js', 'javascript')).map(f => f.line)).toEqual([10]);
  });
});
