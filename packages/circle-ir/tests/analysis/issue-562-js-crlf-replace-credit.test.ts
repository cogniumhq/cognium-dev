/**
 * cognium-dev#562 (minimal slice, JavaScript / TypeScript): `String.replace`
 * sanitizer credit for `log_injection` is argument-aware. The credit holds only
 * when the replace chain strips both CR and LF; an LF-only strip, or a
 * non-global regex that removes only the first match, does not neutralise
 * log forging. Shapes the analyzer cannot decide (a pattern or replacement that
 * is not a literal) keep the credit they had.
 *
 * SAST regression fixtures — the handlers are deliberately vulnerable.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

async function logLines(code: string, file: string, lang: 'javascript' | 'typescript' = 'javascript') {
  const r = await analyze(code, file, lang);
  return [...new Set((r.taint.flows ?? []).filter((f) => f.sink_type === 'log_injection').map((f) => f.sink_line))].sort((a, b) => a - b);
}

const route = `const express = require("express");
const app = express();

app.get("/audit", (req, res) => {
  const actor = req.query.actor;
  const lfOnly = actor.replace(/\\n/g, "");
  console.log("actor=" + lfOnly);
  const bothStripped = actor.replace(/[\\r\\n]/g, "");
  console.log("actor=" + bothStripped);
  res.end("ok");
});
`;

const variants = `const express = require("express");
const app = express();

app.get("/v", (req, res) => {
  const a = req.query.a;
  const chained = a.replace(/\\n/g, "").replace(/\\r/g, "");
  console.log("a=" + chained);
  const alt = a.replace(/\\r|\\n/g, " ");
  console.log("a=" + alt);
  const ws = a.replace(/\\s+/g, " ");
  console.log("a=" + ws);
  const ctl = a.replace(/[\\x00-\\x1f]/g, "");
  console.log("a=" + ctl);
  const crOnly = a.replace(/\\r/g, "");
  console.log("a=" + crOnly);
  const lt = a.replace(/</g, "");
  console.log("a=" + lt);
  const reintro = a.replace(/[\\r\\n]/g, "\\n");
  console.log("a=" + reintro);
  const raw = a;
  console.log("a=" + raw);
  const neighbour = a.replace(/\\n/g, "") + a;
  console.log("a=" + neighbour);
  res.end("ok");
});
`;

const ambiguous = `const express = require("express");
const app = express();
const PAT = /[\\r\\n]/g;

app.get("/amb", (req, res) => {
  const a = req.query.a;
  const viaVar = a.replace(PAT, "");
  console.log("a=" + viaVar);
  const viaCtor = a.replace(new RegExp("[\\\\r\\\\n]", "g"), "");
  console.log("a=" + viaCtor);
  const viaFn = a.replace(/\\n/g, (m) => "");
  console.log("a=" + viaFn);
  res.end("ok");
});
`;

const tsRoute = `import express from "express";
const app = express();

app.get("/audit", (req: express.Request, res: express.Response) => {
  const actor = req.query.actor as string;
  const lfOnly = actor.replace(/\\n/g, "");
  console.log("actor=" + lfOnly);
  const both = actor.replace(/[\\r\\n]/g, "");
  console.log("actor=" + both);
  res.end("ok");
});
`;

describe('cognium-dev#562 JS replace credit is argument-aware', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('LF-only strip reports log_injection; CR+LF strip stays clean', async () => {
    expect(await logLines(route, 'audit_route.js')).toEqual([7]);
  });

  it('TypeScript shares the decision', async () => {
    expect(await logLines(tsRoute, 'audit_route.ts', 'typescript')).toEqual([7]);
  });

  it('chains, alternations, \\s and control-character classes keep their credit; partial strips do not', async () => {
    // 7 chained, 9 alt, 11 ws, 13 ctl: credited (clean)
    // 15 CR-only, 17 `<`-only, 19 strip re-introducing LF, 21 raw, 23 stripped value beside the raw one: reported
    expect(await logLines(variants, 'variants.js')).toEqual([15, 17, 19, 21, 23]);
  });

  it('patterns and replacements that are not literals keep the existing credit', async () => {
    expect(await logLines(ambiguous, 'ambiguous.js')).toEqual([]);
  });
});
