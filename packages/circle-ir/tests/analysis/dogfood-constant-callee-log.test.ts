/**
 * Dogfood 2026-11-02 (cognium-dev 4.19.0 baseline): a tainted value passed to a
 * function made every log sink in that function an inter-procedural
 * log_injection finding, including sinks whose argument is a string constant
 * wrapped in a formatter — `console.error(bold('═══'))` in cognium-ai's
 * `swarm.ts` printSummary, `console.error(colors.red('Error: WASM files not
 * found'))` in the cognium-dev CLI (8 findings). A sink built from literals
 * alone receives nothing from the parameter.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';
import { jsExpressionIsConstant } from '../../src/analysis/passes/interprocedural-pass.js';

const file = (body: string) => `import * as fs from 'fs';
import { bold, colors } from './colors.js';
declare function analyze(files: unknown[]): Promise<{ results: string[] }>;

export async function main(paths: string[]) {
  const files = paths.map(p => ({ path: p, getContent: () => fs.readFileSync(p, 'utf-8') }));
  const result = await analyze(files);
  printSummary(result);
}

function printSummary(result: { results: string[] }): void {
  const first = result.results[0];
${body}
}
`;

const logSinkLines = async (body: string) => {
  const ir = await analyze(file(body), 'swarm.ts', 'typescript');
  return [...new Set(ir.taint.flows.filter(f => f.sink_type === 'log_injection').map(f => f.sink_line))];
};

describe('interprocedural: a callee log sink built from literals is not reached', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('drops a constant wrapped in a formatter call', async () => {
    expect(await logSinkLines(`  console.error(bold('SUMMARY'));`)).toEqual([]);
    expect(await logSinkLines(`  console.error(colors.red('Error: no supported manifests found'));`)).toEqual([]);
    expect(await logSinkLines(`  console.error(bold('='.repeat(60)));`)).toEqual([]);
  });

  it('keeps a sink that logs the parameter or a value derived from it', async () => {
    expect(await logSinkLines(`  console.error(bold(first));`)).toEqual([13]);
    expect(await logSinkLines(`  console.error(colors.red(\`files: \${result.results.join(',')}\`));`)).toEqual([13]);
    expect(await logSinkLines(`  console.error(result.results.join(','));`)).toEqual([13]);
    expect(await logSinkLines(`  console.error(first.trim());`)).toEqual([13]);
  });
});

describe('jsExpressionIsConstant', () => {
  const values = new Set(['result', 'first']);
  it.each([
    [`'plain'`, true],
    [`bold('x')`, true],
    [`colors.red("Error: x")`, true],
    [`\`no holes\``, true],
    [`' '.repeat(60)`, true],
    [`bold(colors.dim('a') + 'b')`, true],
    [`first`, false],
    [`bold(first)`, false],
    [`first.trim()`, false],
    [`\`n=\${first}\``, false],
    [`this.name`, false],
    [`bold(SOME_CONST)`, false],
    [`colors.reset`, false],
    [`x => x`, false],
    [``, false],
  ])('%s → %s', (expr, expected) => {
    expect(jsExpressionIsConstant(expr, values)).toBe(expected);
  });
});
