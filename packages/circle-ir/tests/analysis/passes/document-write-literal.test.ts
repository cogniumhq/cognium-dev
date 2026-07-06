/**
 * cognium-dev #239 C.4 — JS document.write / document.writeln
 * literal-argument guard.
 *
 * `document.write("static HTML")` and `document.writeln("...")` with a
 * string-literal argument are safe: the payload is compile-time
 * constant. Only `document.write(userInput)` is CWE-79.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const xssSinks = (sinks: Array<{ type?: string }> | undefined) =>
  (sinks ?? []).filter((s) => s.type === 'xss');

describe('cognium-dev #239 C.4 — document.write literal guard', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('drops sink when document.write arg is a string literal', async () => {
    const code = `document.write("<h1>Static Header</h1>");`;
    const r = await analyze(code, 'src/app/render.js', 'javascript');
    expect(xssSinks(r.taint?.sinks)).toHaveLength(0);
  });

  it('drops sink when document.writeln arg is a string literal', async () => {
    const code = `document.writeln("static row");`;
    const r = await analyze(code, 'src/app/render.js', 'javascript');
    expect(xssSinks(r.taint?.sinks)).toHaveLength(0);
  });

  it('preserves sink when document.write arg is a variable', async () => {
    const code = `const x = location.hash;
document.write(x);`;
    const r = await analyze(code, 'src/app/render.js', 'javascript');
    expect(xssSinks(r.taint?.sinks).length).toBeGreaterThanOrEqual(1);
  });
});
