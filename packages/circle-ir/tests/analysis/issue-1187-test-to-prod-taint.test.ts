/**
 * cognium-dev #1187 — JS/TS: test-file sources must not produce findings on production sinks.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';
import { generateFindings } from '../../src/analysis/findings.js';
import {
  dropJsTestToProductionTaintPaths,
  isJsTsTestFilePath,
} from '../../src/analysis/test-to-production-taint-gate.js';
import type { TaintPath } from '../../src/types/index.js';

describe('cognium-dev #1187 — JS test → production taint suppression', () => {
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

  it('classifies JS/TS test paths per acceptance globs', () => {
    expect(isJsTsTestFilePath('src/lib/export.test.ts')).toBe(true);
    expect(isJsTsTestFilePath('src/__tests__/util.ts')).toBe(true);
    expect(isJsTsTestFilePath('src/lib/export.ts')).toBe(false);
  });

  it('dropJsTestToProductionTaintPaths preserves prod→prod and drops test→prod', () => {
    const paths: TaintPath[] = [
      {
        id: 'a',
        source: { file: 'src/a.test.ts', line: 1, type: 'env_input', code: '' },
        sink: { file: 'src/a.ts', line: 2, type: 'path_traversal', cwe: 'CWE-22', code: '' },
        hops: [],
        sanitizers_in_path: [],
        path_exists: true,
        confidence: 1,
      },
      {
        id: 'b',
        source: { file: 'src/b.ts', line: 1, type: 'http_param', code: '' },
        sink: { file: 'src/c.ts', line: 2, type: 'xss', cwe: 'CWE-79', code: '' },
        hops: [],
        sanitizers_in_path: [],
        path_exists: true,
        confidence: 1,
      },
    ];
    const out = dropJsTestToProductionTaintPaths(paths);
    expect(out).toHaveLength(1);
    expect(out[0]!.id).toBe('b');
  });

  it('drops cross-file path when only test file seeds taint', async () => {
    const r = await analyzeProject([
      { code: exportProd, filePath: 'src/lib/export.ts', language: 'typescript' },
      { code: exportTest, filePath: 'src/lib/export.test.ts', language: 'typescript' },
    ]);
    const badPaths = (r.taint_paths ?? []).filter(
      p =>
        p.sink.file === 'src/lib/export.ts'
        && p.sink.type === 'path_traversal'
        && p.source.file === 'src/lib/export.test.ts',
    );
    expect(badPaths).toHaveLength(0);

    const prod = r.files.find(f => f.file === 'src/lib/export.ts');
    expect(prod).toBeTruthy();
    const flows = (prod!.analysis.taint.flows ?? []).filter(f => f.sink_type === 'path_traversal');
    expect(flows).toHaveLength(0);

    const sources = prod!.analysis.taint.sources ?? [];
    const sinks = prod!.analysis.taint.sinks ?? [];
    const findings = generateFindings(sources, sinks, prod!.analysis.dfg, 'src/lib/export.ts', flows);
    const pt = findings.filter(f => f.type === 'path_traversal');
    expect(pt).toHaveLength(0);
  });
});
