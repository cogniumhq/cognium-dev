/**
 * cognium-dev #1136 — JS/TS helper that reads a file only to decide whether to
 * push a path does not return that read as a cross-file source.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';

const helper = (body: string) => `import fs from 'fs';

export function walkConfigFiles(root: string): string[] {
  const out: string[] = [];
  function walk(dir: string) {
    const full = dir + '/cfg.json';
${body}
  }
  walk(root);
  return out;
}
`;

const BRANCH_ONLY = `    if (fs.readFileSync(full, 'utf-8').includes('api')) {
      out.push(full);
    }`;

const safeCaller = `import fs from 'fs';
import { walkConfigFiles } from './helper.js';

export function run() {
  for (const cfgPath of walkConfigFiles('/data')) {
    const data = fs.readFileSync(cfgPath, 'utf-8');
    return data;
  }
}
`;

const taintedCaller = `import fs from 'fs';
import { walkConfigFiles } from './helper.js';

export function run() {
  const input = process.argv[2] ?? '';
  for (const cfgPath of walkConfigFiles(input)) {
    const data = fs.readFileSync(cfgPath, 'utf-8');
    return data;
  }
}
`;

async function pathTraversal(helperBody: string, runnerCode: string) {
  const pa = await analyzeProject([
    { filePath: 'helper.ts', code: helper(helperBody), language: 'typescript' },
    { filePath: 'runner.ts', code: runnerCode, language: 'typescript' },
  ], {});
  const paths = (pa.taint_paths ?? []).filter(p => p.sink.type === 'path_traversal');
  const flows = pa.files.flatMap(f =>
    (f.analysis.taint.flows ?? []).filter(x => x.sink_type === 'path_traversal'),
  );
  return { paths, flows };
}

describe('#1136 branch-only file read in a TS path helper', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('read only in the if condition: no cross-file path from the helper', async () => {
    const { paths } = await pathTraversal(BRANCH_ONLY, safeCaller);
    expect(paths.filter(p => p.source.file === 'helper.ts')).toHaveLength(0);
    expect(paths).toHaveLength(0);
  });

  it('a tainted caller path argument still fires through the same helper', async () => {
    const { flows, paths } = await pathTraversal(BRANCH_ONLY, taintedCaller);
    expect(flows.length + paths.length).toBeGreaterThan(0);
  });

  it('file contents returned from the helper still propagate', async () => {
    const body = `    const text = fs.readFileSync(full, 'utf-8');
    out.push(text);`;
    const { paths } = await pathTraversal(body, safeCaller);
    expect(paths.filter(p => p.source.file === 'helper.ts').length).toBeGreaterThan(0);
  });
});
