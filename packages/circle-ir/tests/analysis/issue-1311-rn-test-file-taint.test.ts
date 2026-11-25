/**
 * cognium-dev #1311 (part 3) — React Native / Expo: platform-specific test files
 * (`*.test.ios.ts`, `*.spec.android.js`, `*.test.native.tsx`, `*.test.web.tsx`)
 * are test files, so their sources must not taint production sinks (#1187 gate).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';
import { isJsTsTestFilePath } from '../../src/analysis/test-to-production-taint-gate.js';

describe('cognium-dev #1311 — RN / Expo test files are not taint sources', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const helper = `import fs from 'fs';
export function walk(root: string): string[] {
  const full = root + '/cfg.json';
  return [fs.readFileSync(full, 'utf-8')];
}
`;

  const caller = `import { walk } from './helper';
test('walk', () => {
  const input = process.argv[2] ?? 'x';
  walk(input);
});
`;

  it('classifies platform-suffixed test files as test files', () => {
    expect(isJsTsTestFilePath('src/lib/helper.test.ios.ts')).toBe(true);
    expect(isJsTsTestFilePath('src/lib/helper.test.android.tsx')).toBe(true);
    expect(isJsTsTestFilePath('src/lib/helper.spec.native.js')).toBe(true);
    expect(isJsTsTestFilePath('src/lib/helper.test.web.jsx')).toBe(true);
    expect(isJsTsTestFilePath('src/lib/__tests__/helper.ios.tsx')).toBe(true);
    // Production platform files stay production.
    expect(isJsTsTestFilePath('src/lib/helper.ios.ts')).toBe(false);
    expect(isJsTsTestFilePath('src/lib/helper.native.tsx')).toBe(false);
    expect(isJsTsTestFilePath('src/lib/latest.ios.ts')).toBe(false);
  });

  for (const testFile of [
    'src/lib/helper.test.ios.ts',
    'src/lib/helper.test.native.tsx',
    'src/lib/helper.spec.android.js',
    'src/lib/helper.test.web.tsx',
  ]) {
    it(`drops the cross-file path from ${testFile} into the production helper`, async () => {
      const r = await analyzeProject([
        { code: helper, filePath: 'src/lib/helper.ts', language: 'typescript' },
        {
          code: caller,
          filePath: testFile,
          language: testFile.endsWith('.js') ? 'javascript' : 'typescript',
        },
      ]);
      const fromTest = (r.taint_paths ?? []).filter(p => p.source.file === testFile);
      expect(fromTest).toHaveLength(0);
      const prod = r.files.find(f => f.file === 'src/lib/helper.ts')!;
      const flows = (prod.analysis.taint.flows ?? []).filter(f => f.sink_type === 'path_traversal');
      expect(flows).toHaveLength(0);
    });
  }

  it('keeps the path from a production platform file (helper caller in app.ios.ts)', async () => {
    const r = await analyzeProject([
      { code: helper, filePath: 'src/lib/helper.ts', language: 'typescript' },
      {
        code: `import { walk } from './helper';
export function run() {
  const input = process.argv[2] ?? '';
  return walk(input);
}
`,
        filePath: 'src/lib/app.ios.ts',
        language: 'typescript',
      },
    ]);
    const paths = (r.taint_paths ?? []).filter(
      p => p.source.file === 'src/lib/app.ios.ts' && p.sink.type === 'path_traversal',
    );
    expect(paths.length).toBeGreaterThan(0);
  });
});
