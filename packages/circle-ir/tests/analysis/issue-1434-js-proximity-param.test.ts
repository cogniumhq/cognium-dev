/**
 * #1434 — JS/TS: proximity-only pairings from bare `interprocedural_param`
 * sources are dropped when flows are known (mirrors ParamSourceFlowGatePass).
 */
import { beforeAll, describe, expect, it } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';
import { generateFindings } from '../../src/analysis/findings.js';

const MODULE_SCOPE_SINK = `
const RE = new RegExp(String.raw\`x\`);
export function f(code: string) {
  return RE.test(code);
}
`;

const REAL_FLOW = `
export function h(code: string) {
  const q = \`select \${code}\`;
  db.query(q);
}
`;

describe('#1434: JS proximity does not pair bare params with module-scope sinks', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('(i) module-scope sink: no proximity finding from param source', async () => {
    const ir = await analyze(MODULE_SCOPE_SINK, 'mod-scope.ts', 'typescript');
    const t = ir.taint!;
    const flows = t.flows ?? [];
    expect(flows).toHaveLength(0);

    const findings = generateFindings(
      t.sources ?? [],
      t.sinks ?? [],
      ir.dfg,
      'mod-scope.ts',
      MODULE_SCOPE_SINK,
      'typescript',
      t.sanitizers ?? [],
      ir.types ?? [],
      flows,
    );
    expect(findings).toHaveLength(0);
  });

  it('(ii) a DFG-backed sql_injection finding still reports', async () => {
    const ir = await analyze(REAL_FLOW, 'real-flow.ts', 'typescript');
    const t = ir.taint!;
    const findings = generateFindings(
      t.sources ?? [],
      t.sinks ?? [],
      ir.dfg,
      'real-flow.ts',
      REAL_FLOW,
      'typescript',
      t.sanitizers ?? [],
      ir.types ?? [],
      t.flows ?? [],
    );
    const sql = findings.filter((f) => f.type === 'sql_injection');
    expect(sql.length).toBeGreaterThanOrEqual(1);
    expect(sql.some((f) => f.verification?.graph_path_exists === true)).toBe(true);
  });
});