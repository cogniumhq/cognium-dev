/**
 * `language: 'tsx'` is normalised to `'typescript'` (cognium-dev #4-adjacent
 * API-surface fix).
 *
 * `'tsx'` is a parser-routing tag that is also a public `SupportedLanguage`
 * value, so a caller doing its own extension detection can legally pass it.
 * Doing so used to bypass the routing design documented at the top of
 * `analyze()`: every `languages: ['javascript', 'typescript']` pattern scope
 * (134 sinks, 27 sources) and every `language === 'typescript'` pass gate
 * omits `'tsx'`, so the file parsed cleanly and then reported almost nothing.
 *
 * The failure was silent — no error, no warning, just a near-empty result —
 * which is why it is worth a test rather than a doc note. The CLI maps
 * `.tsx` → `'typescript'` and was never affected.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../src/analyzer.js';

const handler = [
  "import { exec } from 'child_process';",
  'export function handler(req: any, res: any) {',
  '  const cmd = req.query.cmd;',
  '  exec(cmd);',
  "  const el = document.getElementById('x');",
  '  el!.innerHTML = req.query.html;',
  '  res.redirect(req.query.next);',
  '}',
].join('\n');

describe("analyze() with language: 'tsx'", () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('finds the same flows as the same file declared typescript', async () => {
    const asTsx = await analyze(handler, 'h.tsx', 'tsx');
    const asTs = await analyze(handler, 'h.tsx', 'typescript');

    expect((asTsx.taint.flows ?? []).length).toBe((asTs.taint.flows ?? []).length);
    expect((asTsx.taint.flows ?? []).length).toBeGreaterThan(0);
    expect(new Set(asTsx.taint.sinks.map(s => s.type))).toEqual(
      new Set(asTs.taint.sinks.map(s => s.type)),
    );
  });

  it('reports the normalised language in meta', async () => {
    const ir = await analyze(handler, 'h.tsx', 'tsx');
    expect(ir.meta.language).toBe('typescript');
  });

  it('still parses JSX — the tsx grammar is selected regardless', async () => {
    const jsx = [
      "import React from 'react';",
      'export function Card({ name }: { name: string }) {',
      '  const q = new URLSearchParams(location.search).get("q");',
      '  return <div className="card" title={q!}><h1>{name}</h1></div>;',
      '}',
    ].join('\n');

    for (const declared of ['tsx', 'typescript'] as const) {
      const ir = await analyze(jsx, 'Card.tsx', declared);
      // JSX would produce ERROR nodes under the plain TS grammar; a clean
      // parse yields the component's calls.
      expect(ir.calls.length).toBeGreaterThan(0);
      expect(ir.calls.map(c => c.method_name)).toContain('get');
    }
  });

  it('leaves .ts files on the plain typescript grammar', async () => {
    const ir = await analyze(handler, 'h.ts', 'typescript');
    expect(ir.meta.language).toBe('typescript');
    expect((ir.taint.flows ?? []).length).toBeGreaterThan(0);
  });
});
