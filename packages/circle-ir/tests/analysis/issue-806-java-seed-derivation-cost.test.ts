/**
 * cognium-dev#806 — Java receiver-chain seeding (#624) re-ran the file-wide
 * derivation once per source and re-scanned every line once per derived local,
 * so a large class with many sources took seconds to analyze. The work is now
 * done once per distinct seed name, and only when a local not already tainted
 * reads `seed.` on its right-hand side.
 *
 * The assertion counts calls to the file-wide derivation rather than timing
 * the run, so it does not depend on machine load.
 */

import { describe, it, expect, beforeAll, vi } from 'vitest';

const counter = vi.hoisted(() => ({ calls: 0 }));

vi.mock('../../src/analysis/passes/language-sources-pass.js', async (importOriginal) => {
  const mod = await importOriginal<typeof import('../../src/analysis/passes/language-sources-pass.js')>();
  return {
    ...mod,
    buildJavaTaintedVars: (...args: Parameters<typeof mod.buildJavaTaintedVars>) => {
      counter.calls++;
      return mod.buildJavaTaintedVars(...args);
    },
  };
});

import { initAnalyzer, analyze } from '../../src/analyzer.js';

const METHODS = 60;

/** Many handlers that each read the same-named request parameter. */
function manyHandlers(): string {
  const body: string[] = [];
  for (let i = 0; i < METHODS; i++) {
    body.push(`
    public void handle${i}(HttpServletRequest request) throws IOException {
        String name = request.getParameter("name${i}");
        String upper = name.toUpperCase();
        int count${i} = ${i};
        Runtime.getRuntime().exec(upper);
    }`);
  }
  return `package com.example.handlers;

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;

public class ManyHandlers {
${body.join('\n')}
}
`;
}

beforeAll(async () => {
  await initAnalyzer();
});

describe('#806 receiver-chain seeding cost', () => {
  it('derives once per seed name, not once per source', async () => {
    const code = manyHandlers();
    counter.calls = 0;
    const ir = await analyze(code, 'ManyHandlers.java', 'java');

    const sources = ir.taint.sources.filter(s => s.variable === 'name');
    expect(sources.length).toBeGreaterThanOrEqual(METHODS);
    // Was one call per source (>= METHODS); now a handful for the whole file.
    expect(counter.calls).toBeLessThan(10);

    // The receiver-chain local still carries taint to the sink.
    const cmd = (ir.taint.flows ?? []).filter(f => f.sink_type === 'command_injection');
    expect(cmd.length).toBeGreaterThan(0);
  });
});
