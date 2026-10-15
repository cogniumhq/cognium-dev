/**
 * cognium-dev#582 (slice, JavaScript): a tainted assignment made inside a nested
 * block (`if`, `else`, `switch` case) must reach a use after the block, while a
 * merge of only constants stays clean and a straight-line overwrite keeps
 * last-definition-wins.
 *
 * SAST regression fixtures — the handlers are deliberately vulnerable.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

function marked(code: string, tag: string): number[] {
  return code.split('\n').flatMap((l, i) => (l.includes('// ' + tag) ? [i + 1] : []));
}

async function lines(code: string, file: string, type = 'command_injection') {
  const r = await analyze(code, file, 'javascript');
  return [...new Set((r.taint.flows ?? []).filter((f) => f.sink_type === type).map((f) => f.sink_line))].sort((a, b) => a - b);
}

const route = `const express = require("express");
const { exec } = require("child_process");
const app = express();
app.get("/a", (req, res) => {
  let target = null;
  if (req.query.m) { target = req.query.t; }
  exec("ping " + target); // SINK-TP
  res.end("ok");
});
app.get("/b", (req, res) => {
  let target = "localhost";
  if (req.query.m) {
    target = "example.org";
  } else {
    target = "example.net";
  }
  exec("ping " + target); // SINK-CLEAN
  res.end("ok");
});
app.get("/c", (req, res) => {
  let target;
  switch (req.query.m) {
    case "x":
      target = req.query.t;
      break;
    default:
      target = "localhost";
  }
  exec("ping " + target); // SINK-TP
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

describe('cognium-dev#582 JS block-local definition reaches the use after the block', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('reports the if-without-else and switch/default routes; the all-constant merge stays clean', async () => {
    expect(await lines(route, 'route.js')).toEqual(marked(route, 'SINK-TP'));
  });

  it('if/else with the tainted arm last', async () => {
    const code = wrap(`  let t = "x";
  if (req.query.m) {
    t = "safe";
  } else {
    t = req.query.t;
  }
  exec("ping " + t); // SINK-TP`);
    expect(await lines(code, 'a.js')).toEqual(marked(code, 'SINK-TP'));
  });

  it('if/else with the tainted arm first', async () => {
    const code = wrap(`  let t = "x";
  if (req.query.m) {
    t = req.query.t;
  } else {
    t = "safe";
  }
  exec("ping " + t); // SINK-TP`);
    expect(await lines(code, 'a.js')).toEqual(marked(code, 'SINK-TP'));
  });

  it('else-if chain without a final else keeps the tainted arm reaching', async () => {
    const code = wrap(`  let t = "x";
  if (req.query.m === "1") {
    t = "a";
  } else if (req.query.m === "2") {
    t = req.query.t;
  }
  exec("ping " + t); // SINK-TP`);
    expect(await lines(code, 'a.js')).toEqual(marked(code, 'SINK-TP'));
  });

  it('a straight-line constant overwrite after the block kills the taint', async () => {
    const code = wrap(`  let t = "x";
  if (req.query.m) { t = req.query.t; }
  t = "fixed";
  exec("ping " + t); // SINK-TP`);
    expect(await lines(code, 'a.js')).toEqual([]);
  });

  it('a straight-line constant overwrite before the block does not hide a tainted branch', async () => {
    const code = wrap(`  let t = req.query.t;
  t = "fixed";
  if (req.query.m) { t = "other"; }
  exec("ping " + t); // SINK-TP`);
    expect(await lines(code, 'a.js')).toEqual([]);
  });

  it('a loop body assignment reaches the use after the loop', async () => {
    const code = wrap(`  let t = "x";
  for (const k of Object.keys(req.query)) { t = req.query[k]; }
  exec("ping " + t); // SINK-TP`);
    expect(await lines(code, 'a.js')).toEqual(marked(code, 'SINK-TP'));
  });

  it('straight-line control still reports', async () => {
    const code = wrap(`  let t = req.query.t;
  exec("ping " + t); // SINK-TP`);
    expect(await lines(code, 'a.js')).toEqual(marked(code, 'SINK-TP'));
  });

  it('a one-line if / else-if / else chain of constants, with a request read in its conditions, stays clean', async () => {
    const code = wrap(`  let t = "x";
  if (req.query.m) { t = "a"; } else if (req.query.n) { t = "b"; } else { t = "c"; }
  exec("ping " + t); // SINK-CLEAN`);
    expect(await lines(code, 'a.js')).toEqual([]);
  });

  it('a one-line if whose body reads the request still reports', async () => {
    const code = wrap(`  let t = "x";
  if (req.query.m) { t = req.query.t; }
  exec("ping " + t); // SINK-TP`);
    expect(await lines(code, 'a.js')).toEqual(marked(code, 'SINK-TP'));
  });

  it('a nested if reaches the use after both blocks', async () => {
    const code = wrap(`  let t = "x";
  if (req.query.m) {
    if (req.query.n) { t = req.query.t; }
  }
  exec("ping " + t); // SINK-TP`);
    expect(await lines(code, 'a.js')).toEqual(marked(code, 'SINK-TP'));
  });

  it('switch: a fall-through case group and a constant in a later case', async () => {
    const code = wrap(`  let t = "x";
  switch (req.query.m) {
    case "a":
    case "b":
      t = req.query.t;
      break;
    case "c": { t = "k"; break; }
  }
  exec("ping " + t); // SINK-TP`);
    expect(await lines(code, 'a.js')).toEqual(marked(code, 'SINK-TP'));
  });

  it('a while body assignment reaches the use after the loop (TypeScript too)', async () => {
    const code = wrap(`  let t: string = "x";
  while (req.query.m) { t = req.query.t as string; break; }
  exec("ping " + t); // SINK-TP`);
    const r = await analyze(code, 'a.ts', 'typescript');
    const got = [...new Set((r.taint.flows ?? []).filter((f) => f.sink_type === 'command_injection').map((f) => f.sink_line))];
    expect(got).toEqual(marked(code, 'SINK-TP'));
  });

  it('a branch assignment of a non-request value after a request value does not report', async () => {
    const code = wrap(`  let t = "x";
  if (req.query.m) { t = "k"; }
  exec("ping " + t); // SINK-CLEAN`);
    expect(await lines(code, 'a.js')).toEqual([]);
  });

  it('a one-line brace-less if/else with the tainted assignment in the else arm reports', async () => {
    const code = wrap(`  let t;
  if (req.query.a) t = "b"; else t = req.query.t;
  exec("ping " + t); // SINK-TP`);
    expect(await lines(code, 'a.js')).toEqual(marked(code, 'SINK-TP'));
  });

  it('a one-line braced var declaration in each arm, tainted in else, reports', async () => {
    const code = wrap(`  if (req.query.a) { var t = "x"; } else { var t = req.query.t; }
  exec("ping " + t); // SINK-TP`);
    expect(await lines(code, 'a.js')).toEqual(marked(code, 'SINK-TP'));
  });

  it('a sanitizer in the only assignment arm stays clean for xss', async () => {
    const code = `const express = require("express");
const escapeHtml = require("escape-html");
const app = express();
app.get("/u", (req, res) => {
  let n = "x";
  if (req.query.a) {
    n = escapeHtml(req.query.n);
  }
  res.send("<p>" + n + "</p>"); // SINK-CLEAN
});
`;
    const r = await analyze(code, 'app.js', 'javascript');
    const got = [...new Set((r.taint.flows ?? []).filter((f) => f.sink_type === 'xss').map((f) => f.sink_line))];
    expect(got).toEqual([]);
  });

  it('straight-line escapeHtml stays clean for xss', async () => {
    const code = `const express = require("express");
const escapeHtml = require("escape-html");
const app = express();
app.get("/u", (req, res) => {
  const n = escapeHtml(req.query.n);
  res.send("<p>" + n + "</p>"); // SINK-CLEAN
});
`;
    const r = await analyze(code, 'app.js', 'javascript');
    const got = [...new Set((r.taint.flows ?? []).filter((f) => f.sink_type === 'xss').map((f) => f.sink_line))];
    expect(got).toEqual([]);
  });
});
