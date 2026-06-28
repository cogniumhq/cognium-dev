import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

/**
 * Sprint 56 — #182 Slice D: regression lock for TS `console.*` log_injection
 * sink detection.
 *
 * Ticket #182 claimed TS log_injection was an FN, but DEFAULT_SINKS already
 * registers `console.log/warn/error/info` for both javascript and typescript
 * languages (config-loader.ts ~line 1603-1608). The claim is stale; this
 * spec only locks sink detection so a future refactor cannot regress.
 *
 * (Flow emission for log_injection is gated by canSourceReachSink, which
 * does not currently include log_injection in any source mapping; that is
 * a separate engine-wide concern outside this slice.)
 */
describe('Sprint 56 — #182 TS log_injection regression lock', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const sinkMethods = (r: Awaited<ReturnType<typeof analyze>>) =>
    (r.taint?.sinks ?? []).filter(s => s.type === 'log_injection').map(s => s.method);

  it('regression — console.log in .ts file is detected as log_injection sink', async () => {
    const code = `function handler(req: { query: { name: string } }) {
    console.log("user=" + req.query.name);
}`;
    const r = await analyze(code, 'a.ts', 'typescript');
    expect(sinkMethods(r)).toContain('log');
  });

  it('regression — console.warn/error/info in .ts file all detected', async () => {
    const code = `function handler(req: { query: { name: string } }) {
    console.warn("u=" + req.query.name);
    console.error("u=" + req.query.name);
    console.info("u=" + req.query.name);
}`;
    const r = await analyze(code, 'b.ts', 'typescript');
    const methods = sinkMethods(r);
    expect(methods).toContain('warn');
    expect(methods).toContain('error');
    expect(methods).toContain('info');
  });
});
