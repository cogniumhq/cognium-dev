/**
 * cognium-dev #1187 — acceptance fixtures from issue body (test vs production caller).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';
import { generateFindings } from '../../src/analysis/findings.js';
import { dropJsTestToProductionTaintPaths } from '../../src/analysis/test-to-production-taint-gate.js';

describe('cognium-dev #1187 — test-source vs production-source (issue acceptance)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const exportProd = `import { writeFileSync } from 'node:fs';
export function exportReport(dir: string, body: string) {
  writeFileSync(\`\${dir}/report.txt\`, body);
}
`;

  const exportTest = `import { exportReport } from './export';
test('writes', () => {
  exportReport(process.env.TMP_DIR!, 'x');
});
`;

  /** Cross-file path_traversal shape that analyzeProject actually connects (parity with #1136). */
  const pathHelper = `import fs from 'fs';
export function walk(root: string): string[] {
  const full = root + '/cfg.json';
  return [fs.readFileSync(full, 'utf-8')];
}
`;

  const prodRunner = `import { walk } from './helper';
export function run() {
  const input = process.argv[2] ?? '';
  return walk(input);
}
`;

  const testRunner = `import { walk } from './helper';
test('walk', () => {
  const input = process.argv[2] ?? 'x';
  walk(input);
});
`;

  function pathTraversalOnExport(r: Awaited<ReturnType<typeof analyzeProject>>) {
    const prod = r.files.find(f => f.file === 'src/lib/export.ts');
    expect(prod).toBeTruthy();
    const flows = (prod!.analysis.taint.flows ?? []).filter(f => f.sink_type === 'path_traversal');
    const sources = prod!.analysis.taint.sources ?? [];
    const sinks = prod!.analysis.taint.sinks ?? [];
    const findings = generateFindings(
      sources,
      sinks,
      prod!.analysis.dfg,
      'src/lib/export.ts',
      flows,
    );
    const fromFindings = findings.filter(f => f.type === 'path_traversal');
    const paths = (r.taint_paths ?? []).filter(
      p => p.sink.file === 'src/lib/export.ts' && p.sink.type === 'path_traversal',
    );
    return { flows, findings: fromFindings, paths, prod: prod! };
  }

  it('export.ts + export.test.ts only — no path_traversal from test file into production sink', async () => {
    const r = await analyzeProject([
      { code: exportProd, filePath: 'src/lib/export.ts', language: 'typescript' },
      { code: exportTest, filePath: 'src/lib/export.test.ts', language: 'typescript' },
    ]);
    const { flows, findings, paths } = pathTraversalOnExport(r);
    const testSourced = paths.filter(p => p.source.file === 'src/lib/export.test.ts');
    expect(testSourced).toHaveLength(0);
    expect(flows).toHaveLength(0);
    expect(findings).toHaveLength(0);
  });

  it('production caller cross-file path_traversal is not suppressed (helper + prod runner)', async () => {
    const r = await analyzeProject([
      { code: pathHelper, filePath: 'src/lib/helper.ts', language: 'typescript' },
      { code: prodRunner, filePath: 'src/lib/runner-prod.ts', language: 'typescript' },
    ]);
    const paths = (r.taint_paths ?? []).filter(p => p.sink.type === 'path_traversal');
    const filtered = dropJsTestToProductionTaintPaths(paths);
    expect(paths.length).toBeGreaterThan(0);
    expect(filtered.length).toBe(paths.length);
    expect(paths.every(p => p.source.file !== 'src/lib/export.test.ts')).toBe(true);
    expect(paths.some(p => p.sink.file === 'src/lib/helper.ts')).toBe(true);
  });

  it('test caller cross-file path into production helper is dropped while prod path stays', async () => {
    const rProd = await analyzeProject([
      { code: pathHelper, filePath: 'src/lib/helper.ts', language: 'typescript' },
      { code: prodRunner, filePath: 'src/lib/runner-prod.ts', language: 'typescript' },
    ]);
    const rAll = await analyzeProject([
      { code: pathHelper, filePath: 'src/lib/helper.ts', language: 'typescript' },
      { code: prodRunner, filePath: 'src/lib/runner-prod.ts', language: 'typescript' },
      { code: testRunner, filePath: 'src/lib/runner.test.ts', language: 'typescript' },
    ]);
    const prodOnly = (rProd.taint_paths ?? []).filter(p => p.sink.type === 'path_traversal');
    const allPaths = (rAll.taint_paths ?? []).filter(p => p.sink.type === 'path_traversal');
    const afterGate = dropJsTestToProductionTaintPaths(allPaths);
    const testSourced = afterGate.filter(p => p.source.file === 'src/lib/runner.test.ts');
    expect(testSourced).toHaveLength(0);
    expect(afterGate.length).toBeGreaterThanOrEqual(prodOnly.length);
    expect(afterGate.some(p => p.source.file === 'src/lib/runner-prod.ts')).toBe(true);
  });

  it('export-prod → export.ts path is not classified as test-only (gate preserves prod sources)', () => {
    const synthetic = [
      {
        id: 'prod',
        source: { file: 'src/lib/export-prod.ts', line: 2, type: 'env_input', code: '' },
        sink: { file: 'src/lib/export.ts', line: 3, type: 'path_traversal', cwe: 'CWE-22', code: '' },
        hops: [],
        sanitizers_in_path: [],
        path_exists: true,
        confidence: 1,
      },
    ];
    expect(dropJsTestToProductionTaintPaths(synthetic)).toHaveLength(1);
  });
});
