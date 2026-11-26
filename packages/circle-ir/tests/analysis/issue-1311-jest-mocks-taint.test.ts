/**
 * cognium-dev #1311 (Jest mocks): a source in a Jest manual mock under
 * `__mocks__/` must not taint production sinks, like a `*.test.*` file (#1187).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';
import { isJsTsTestFilePath } from '../../src/analysis/test-to-production-taint-gate.js';

describe('cognium-dev #1311 — __mocks__ sources do not taint production', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const helper = `import fs from 'fs';
export function walk(root: string): string[] {
  const full = root + '/cfg.json';
  return [fs.readFileSync(full, 'utf-8')];
}
`;

  const caller = (spec: string) => `import { walk } from '${spec}';
export function run() {
  const input = process.argv[2] ?? '';
  return walk(input);
}
`;

  async function pathsIntoHelper(callerPath: string, spec: string) {
    const r = await analyzeProject([
      { code: helper, filePath: 'src/lib/helper.ts', language: 'typescript' },
      { code: caller(spec), filePath: callerPath, language: 'typescript' },
    ]);
    return (r.taint_paths ?? []).filter(p => p.sink.file === 'src/lib/helper.ts' && p.sink.type === 'path_traversal');
  }

  it('classifies manual mocks as JS/TS test files', () => {
    expect(isJsTsTestFilePath('src/lib/__mocks__/store.ts')).toBe(true);
    expect(isJsTsTestFilePath('__mocks__/expo-haptics.js')).toBe(true);
    expect(isJsTsTestFilePath('src/lib/mocks/store.ts')).toBe(false);
    expect(isJsTsTestFilePath('src/lib/__mocks__/data.json')).toBe(false);
  });

  it('drops the cross-file path from a manual mock into a production sink', async () => {
    expect(await pathsIntoHelper('src/lib/__mocks__/store.ts', '../helper')).toHaveLength(0);
  });

  it('keeps the same path from a production caller', async () => {
    expect((await pathsIntoHelper('src/lib/run.ts', './helper')).length).toBeGreaterThan(0);
  });
});
