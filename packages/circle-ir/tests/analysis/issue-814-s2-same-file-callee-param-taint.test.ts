/**
 * cognium-dev#814 slice S2 — same-file call passes tainted actual into callee
 * parameter so the callee body sees taint (declaration order no longer blocks it).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

type IR = Awaited<ReturnType<typeof analyze>>;

const sinksAt = (ir: IR, sinkType: string, line: number): boolean =>
  (ir.taint.flows ?? []).some(f => f.sink_type === sinkType && f.sink_line === line);

const HELPER_FIRST = `
import javax.servlet.http.*;
class Foo {
    void sink(String p) throws Exception {
        Runtime.getRuntime().exec(p);
    }
    protected void doGet(HttpServletRequest req) throws Exception {
        String x = req.getParameter("x");
        sink(x);
    }
}
`;

describe('#814 S2: same-file callee parameter taint (Java)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('reports command_injection in callee when helper is declared before caller', async () => {
    const ir = await analyze(HELPER_FIRST, 'Foo.java', 'java');
    const execLine = HELPER_FIRST.split('\n').findIndex(l => l.includes('.exec(')) + 1;
    expect(sinksAt(ir, 'command_injection', execLine)).toBe(true);
  });
});
