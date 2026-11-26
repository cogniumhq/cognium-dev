/**
 * #1432: JSPWiki-style classless `render` XSS rows must not match a local
 * JS/TS function named `render`.
 */
import { beforeAll, describe, expect, it } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';
import { generateFindings } from '../../src/analysis/findings.js';

const SAFE = `
export function f(v: string) {
  const render = (x: string): string => x.trim();
  let out = '';
  out += render(v);
  return out;
}
`;

describe('#1432: classless wiki render row is Java-only', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('does not treat a local render() as an xss sink', async () => {
    const result = await analyze(SAFE, 'local-render.ts', 'typescript');
    const xssSinks =
      result.taint?.sinks.filter((s) => s.type === 'xss') ?? [];
    expect(xssSinks).toHaveLength(0);
    const xssFlows =
      result.taint?.flows?.filter((f) => f.sink_type === 'xss') ?? [];
    expect(xssFlows).toHaveLength(0);
    const findings = generateFindings(
      result.taint?.sources ?? [],
      result.taint?.sinks ?? [],
      result.dfg,
      'local-render.ts',
      SAFE,
      'typescript',
      result.taint?.flows ?? [],
    );
    expect(findings.map((f) => f.type)).not.toContain('xss');
  });
});