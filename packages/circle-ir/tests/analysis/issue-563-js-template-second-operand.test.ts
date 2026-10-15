/**
 * cognium-dev #563 (PAT-INPUT-01 js slice) — in a template-literal sink
 * argument only the first interpolated identifier was checked. When that
 * value was sanitized (`const qty = parseInt(...)`), a raw `${note}` after it
 * was never looked at and the xss flow was lost.
 */

import { describe, it, beforeAll, expect } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

async function xss(code: string, file = 'order_receipt.js'): Promise<number[]> {
  const ir = await analyze(code, file, file.endsWith('.ts') ? 'typescript' : 'javascript');
  return (ir.taint.flows ?? []).filter(f => f.sink_type === 'xss').map(f => f.source_line);
}

const route = (decl: string, out: string) => `const express = require('express');
const app = express();
app.get('/receipt', (req, res) => {
  res.set('Cache-Control', 'no-store');
${decl}
  res.end(${out});
});
module.exports = app;
`;

beforeAll(async () => {
  await initAnalyzer();
});

describe('#563 template literal: later raw operand', () => {
  it('raw value after a parsed number fires, credited to the raw read', async () => {
    const code = route(
      "  const qty = parseInt(req.query.qty, 10);\n  const note = req.query.note;",
      '`ordered ${qty}: ${note}`',
    );
    expect(await xss(code)).toEqual([6]);
  });

  it('TypeScript: same shape fires', async () => {
    const code = route(
      "  const qty = Number(req.query.qty);\n  const note = String(req.query.note);",
      '`ordered ${qty}: ${note}`',
    );
    expect((await xss(code, 'order_receipt.ts')).length).toBeGreaterThan(0);
  });

  it('safe twin: both operands neutralised stays clean', async () => {
    const code = route(
      "  const qty = parseInt(req.query.qty, 10);\n  const note = encodeURIComponent(req.query.note);",
      '`ordered ${qty}: ${note}`',
    );
    expect(await xss(code)).toEqual([]);
  });

  it('safe twin: parsed number beside a constant stays clean', async () => {
    const code = route(
      "  const qty = parseInt(req.query.qty, 10);\n  const label = 'units';",
      '`ordered ${qty} ${label}`',
    );
    expect(await xss(code)).toEqual([]);
  });
});
