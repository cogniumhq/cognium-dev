/**
 * Three defects found by re-testing published 4.13.0:
 *  - a sanitizer on one operand cleared a sink that also received a raw one;
 *  - a JS/TS `switch` body was not visited by constant propagation, so a
 *    variable assigned only literals in it was no longer known constant;
 *  - C# `if (false)` / `if (5 != 5)` were not evaluated, so the sibling-branch
 *    rule kept taint assigned in dead code.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

beforeAll(async () => {
  await initAnalyzer();
});

const flows = async (code: string, file: string, language: 'csharp' | 'javascript' | 'typescript', type: string) =>
  ((await analyze(code, file, language)).taint.flows ?? []).filter(f => f.sink_type === type);

const controller = (body: string[]) => [
  'using System.Text.Encodings.Web; using System.Web; using Microsoft.AspNetCore.Mvc; using System.Threading.Tasks;',
  'public class MController : Controller {',
  '  public async Task<object> Run() {',
  '    var a = Request.Query["a"].ToString();',
  '    var b = Request.Query["b"].ToString();',
  ...body.map(l => '    ' + l),
  '    return null;',
  '  }',
  '}',
].join('\n');

describe('C#: a sanitizer covers its own operand, not the whole sink call', () => {
  it('reports the raw operand next to an encoded one', async () => {
    const code = controller(['await Response.WriteAsync(HtmlEncoder.Default.Encode(a) + b);']);
    expect((await flows(code, 'M.cs', 'csharp', 'xss')).length).toBeGreaterThan(0);
  });

  it('reports the raw operand next to an encoded variable', async () => {
    const code = controller([
      'var ea = HtmlEncoder.Default.Encode(a);',
      'await Response.WriteAsync("<p>" + ea + "</p>" + b);',
    ]);
    expect((await flows(code, 'M.cs', 'csharp', 'xss')).length).toBeGreaterThan(0);
  });

  it('reports Html.Raw with one encoded and one raw operand', async () => {
    const code = controller(['var h = Html.Raw(HtmlEncoder.Default.Encode(a) + b);']);
    expect((await flows(code, 'M.cs', 'csharp', 'xss')).length).toBeGreaterThan(0);
  });

  it('stays quiet when every operand is encoded', async () => {
    const code = controller([
      'await Response.WriteAsync(HtmlEncoder.Default.Encode(a) + HtmlEncoder.Default.Encode(b));',
    ]);
    expect(await flows(code, 'M.cs', 'csharp', 'xss')).toEqual([]);
  });

  it('stays quiet when the raw name is only inside a string literal', async () => {
    const code = controller(['await Response.WriteAsync("b: " + HtmlEncoder.Default.Encode(a));']);
    expect(await flows(code, 'M.cs', 'csharp', 'xss')).toEqual([]);
  });

  it('stays quiet when the other operand was reassigned to a constant', async () => {
    const code = controller([
      'b = "fixed";',
      'await Response.WriteAsync(HtmlEncoder.Default.Encode(a) + b);',
    ]);
    expect(await flows(code, 'M.cs', 'csharp', 'xss')).toEqual([]);
  });
});

describe('JS/TS: a switch that assigns only literals leaves a constant', () => {
  const handler = (arms: string[]) => [
    "const express = require('express');",
    "const { exec } = require('child_process');",
    'const app = express();',
    "app.get('/run', (req, res) => {",
    '  let cmd;',
    '  switch (req.query.action) {',
    ...arms.map(l => '    ' + l),
    '  }',
    '  exec(cmd);',
    "  res.send('ok');",
    '});',
  ].join('\n');
  const literalArms = ["case 'list':", "  cmd = 'ls';", '  break;', 'default:', "  cmd = 'pwd';"];

  it('javascript', async () => {
    expect(await flows(handler(literalArms), 'a.js', 'javascript', 'command_injection')).toEqual([]);
  });

  it('typescript', async () => {
    expect(await flows(handler(literalArms), 'a.ts', 'typescript', 'command_injection')).toEqual([]);
  });
});

describe('C#: taint assigned in dead code does not survive a literal in the live branch', () => {
  const xpath = (cond: string, thenBody: string, elseBody: string) => [
    'using System; using System.Xml;',
    'public class C {',
    '  public void Run() {',
    '    string data = null;',
    `    if (${cond}) {`,
    `      ${thenBody}`,
    '    } else {',
    `      ${elseBody}`,
    '    }',
    '    XmlDocument doc = new XmlDocument();',
    '    doc.SelectNodes("/users/user[name=\'" + data + "\']");',
    '  }',
    '}',
  ].join('\n');
  const src = 'data = Console.ReadLine();';
  const lit = 'data = "foo";';

  it.each([
    ['false', src, lit],
    ['5 != 5', src, lit],
    ['true', lit, src],
    ['5 == 5', lit, src],
  ])('if (%s): dead source is ignored', async (cond, a, b) => {
    expect(await flows(xpath(cond, a, b), 'C.cs', 'csharp', 'xpath_injection')).toEqual([]);
  });

  it.each([
    ['true', src, lit],
    ['5 == 5', src, lit],
    ['false', lit, src],
  ])('if (%s): live source is reported', async (cond, a, b) => {
    expect((await flows(xpath(cond, a, b), 'C.cs', 'csharp', 'xpath_injection')).length).toBeGreaterThan(0);
  });
});
