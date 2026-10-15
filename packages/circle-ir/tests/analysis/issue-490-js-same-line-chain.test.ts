/**
 * cognium-dev#490 (slice, JavaScript / TypeScript, with the C# one-line form):
 * the data-flow graph links a use to every definition on its line, and a
 * handler signature seeds the first body line by adjacency, so in
 * `const q = req.query.q; const tool = "ls";` the unrelated constant was
 * tainted. On a line with a second statement a definition now keeps the link
 * only when its own statement reads the linked variable. A single-statement
 * line, a neighbour built from the read, and a statement whose initializer
 * cannot be isolated keep the line-granular behaviour.
 *
 * SAST regression fixtures — the handlers are deliberately vulnerable.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

type Lang = 'javascript' | 'typescript' | 'csharp';

async function lines(code: string, file: string, lang: Lang, type: string) {
  const r = await analyze(code, file, lang);
  return [...new Set((r.taint.flows ?? []).filter((f) => f.sink_type === type).map((f) => f.sink_line))].sort((a, b) => a - b);
}

const route = `const express = require("express");
const { exec } = require("child_process");
const app = express();

app.get("/run", (req, res) => {
  const q = req.query.q; const tool = "ls";
  exec(tool);
  res.end(q);
});

app.get("/build", (req, res) => {
  const w = req.query.w; const cmd = "make " + w;
  exec(cmd);
  res.end("ok");
});
`;

const wrap = (body: string) => `const express = require("express");
const { exec } = require("child_process");
const app = express();

app.get("/r", (req, res) => {
${body}
  res.end("ok");
});
`;

describe('cognium-dev#490 JS second statement on a source line', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('the constant beside the read is clean; the neighbour built from it still reports', async () => {
    // line 7: exec(tool) -> clean; line 13: exec(cmd) -> still command_injection
    expect(await lines(route, 'run_route.js', 'javascript', 'command_injection')).toEqual([13]);
  });

  it('the same split over two lines is unchanged', async () => {
    const split = wrap(`  const q = req.query.q;\n  const tool = "ls";\n  exec(tool);`);
    expect(await lines(split, 'split_route.js', 'javascript', 'command_injection')).toEqual([]);
  });

  it('the read itself still reaches the sink', async () => {
    const tp = wrap(`  const q = req.query.q; const tool = "ls";\n  exec(q);`);
    expect(await lines(tp, 'tp_route.js', 'javascript', 'command_injection')).toEqual([7]);
  });

  it('a template, concatenation or call that uses the read keeps the taint', async () => {
    for (const rhs of ['`make ${q}`', '"make " + q', 'String(q)', 'q.trim()']) {
      const code = wrap(`  const q = req.query.q; const cmd = ${rhs};\n  exec(cmd);`);
      expect(await lines(code, 'derived_route.js', 'javascript', 'command_injection'), rhs).toEqual([7]);
    }
  });

  it('a neighbour that is a call, a literal containing ";" or a destructured name is not the read', async () => {
    for (const rhs of ['pick()', '"a;b"', '`x`']) {
      const code = wrap(`  const q = req.query.q; const tool = ${rhs};\n  exec(tool);`);
      expect(await lines(code, 'clean_route.js', 'javascript', 'command_injection'), rhs).toEqual([]);
    }
    const destructured = wrap(`  const { a } = req.query; const tool = "ls";\n  exec(tool);`);
    expect(await lines(destructured, 'destructured_route.js', 'javascript', 'command_injection')).toEqual([]);
  });

  it('a reassigned neighbour keeps its taint (the statement cannot be isolated)', async () => {
    const code = wrap(`  const q = req.query.q; let t = "ls"; t = q;\n  exec(t);`);
    expect(await lines(code, 'reassign_route.js', 'javascript', 'command_injection')).toEqual([7]);
  });

  it('a neighbour whose initializer wraps onto the next line keeps the taint', async () => {
    // line 6 holds the read and the start of `cmd`; the read reaches `cmd` on line 7
    const concat = wrap(`  const q = req.query.q; const cmd = 'ls ' +\n    q;\n  exec(cmd);`);
    expect(await lines(concat, 'wrap_concat_route.js', 'javascript', 'command_injection')).toEqual([8]);
    const paren = wrap(`  const q = req.query.q; var cmd = 'ls ' + (\n    q);\n  exec(cmd);`);
    expect(await lines(paren, 'wrap_paren_route.js', 'javascript', 'command_injection')).toEqual([8]);
    const unterminated = wrap(`  const q = req.query.q; const cmd = 'ls '\n    + q;\n  exec(cmd);`);
    expect(await lines(unterminated, 'wrap_lead_op_route.js', 'javascript', 'command_injection')).toEqual([8]);
  });

  it('a neighbour that is compound-assigned or updated on the line keeps the taint', async () => {
    for (const write of ['cmd += q;', 'cmd ||= q;', 'cmd ??= q;', 'cmd = cmd + q;']) {
      const code = wrap(`  const q = req.query.q; let cmd = 'ls '; ${write}\n  exec(cmd);`);
      expect(await lines(code, 'compound_route.js', 'javascript', 'command_injection'), write).toEqual([7]);
    }
  });

  it('a ";" inside a regex literal does not end the initializer early', async () => {
    const code = wrap(`  const q = req.query.q; const t = /;/.test(q) ? q : '';\n  exec(t);`);
    expect(await lines(code, 'regex_route.js', 'javascript', 'command_injection')).toEqual([7]);
  });

  it('a destructuring assignment of the neighbour on the line keeps the taint', async () => {
    for (const body of [
      `let b = req.query.q; let a = 'ls'; [a, b] = [b, a];`,
      `const q = req.query.q; let a = 'ls'; [a] = [q];`,
      `const q = req.query.q; let a = 'ls'; ({ a } = { a: q });`,
    ]) {
      const code = wrap(`  ${body}\n  exec(a);`);
      expect(await lines(code, 'swap_route.js', 'javascript', 'command_injection'), body).toEqual([7]);
    }
  });

  it('a one-line handler body: the constant is clean, the read still reports', async () => {
    const clean = wrap(`  const q = req.query.q; const tool = "ls"; exec(tool);`);
    expect(await lines(clean, 'oneline_route.js', 'javascript', 'command_injection')).toEqual([]);
    const tp = wrap(`  const q = req.query.q; exec(q);`);
    expect(await lines(tp, 'oneline_tp_route.js', 'javascript', 'command_injection')).toEqual([6]);
  });

  it('TypeScript (a cast on the read)', async () => {
    const code = wrap(`  const q = req.query.q as string; const tool = "ls";\n  exec(tool);`);
    expect(await lines(code, 'typed_route.ts', 'typescript', 'command_injection')).toEqual([]);
  });

  it('C#: a constant beside the console read is clean, a neighbour built from it reports', async () => {
    const cs = (body: string) =>
      `using System;\nusing System.Diagnostics;\nclass P {\n    static void Main(string[] args) {\n${body}\n    }\n}\n`;
    const clean = cs(`        string q = Console.ReadLine(); string x = "fixed";\n        Process.Start(x);`);
    expect(await lines(clean, 'P.cs', 'csharp', 'command_injection')).toEqual([]);
    const derived = cs(`        string q = Console.ReadLine(); string x = "a" + q;\n        Process.Start(x);`);
    expect(await lines(derived, 'P.cs', 'csharp', 'command_injection')).toEqual([6]);
    const interpolated = cs(`        string q = Console.ReadLine(); string x = $"a {q}";\n        Process.Start(x);`);
    expect(await lines(interpolated, 'P.cs', 'csharp', 'command_injection')).toEqual([6]);
  });
});
