/**
 * Dogfood 2026-11-03 (cognium-ai CLI commands): a value returned from a
 * cross-file source wrapper reached a caller-body sink through an argument the
 * sink does not treat as dangerous. `fs.writeFileSync(args.output, report)`
 * with `report` built from file contents was a path_traversal, though only the
 * first argument (the path) is the sink's; and `diff(fs.readFileSync(p), report)`
 * credited `report` (an argument of `diff`) to the `readFileSync` sink on the
 * same line. 10 cross-file path_traversal paths in cognium-ai and circle-ir-ai.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';

const reader = `import * as fs from 'fs';
export function loadSpec(p: string): string {
  const text = fs.readFileSync(p, 'utf8');
  return text;
}`;

const command = (body: string) => `import * as fs from 'fs';
import { loadSpec } from './reader';
function diff(a: string, b: string): string { return a + b; }
export function run(input: string, output: string, other: string): void {
  const report = loadSpec(input);
${body}
}`;

const lineOf = (src: string, needle: string) => src.split('\n').findIndex(l => l.includes(needle)) + 1;

async function sinkLines(body: string): Promise<{ src: string; lines: number[] }> {
  const src = command(body);
  const r = await analyzeProject([
    { code: reader, filePath: 'reader.ts', language: 'typescript' },
    { code: src, filePath: 'command.ts', language: 'typescript' },
  ]);
  const lines = r.taint_paths
    .filter(t => t.source.file === 'reader.ts' && t.sink.file === 'command.ts' && t.sink.type === 'path_traversal')
    .map(t => t.sink.line);
  return { src, lines };
}

describe('cross-file caller-body sink: only the sink call\'s dangerous arguments count', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('does not report file contents written as the data argument of writeFileSync', async () => {
    const { lines } = await sinkLines(`  fs.writeFileSync(output, report);`);
    expect(lines).toEqual([]);
  });

  it('does not credit an argument of another call on the sink line', async () => {
    const { lines } = await sinkLines(`  const d = diff(fs.readFileSync(other, 'utf8'), report);\n  console.log(d.length);`);
    expect(lines).toEqual([]);
  });

  it('still reports file contents used as the path of writeFileSync', async () => {
    const { src, lines } = await sinkLines(`  fs.writeFileSync(report, 'x');`);
    expect(lines).toContain(lineOf(src, `fs.writeFileSync(report`));
  });

  it('still reports file contents used as the path of readFileSync nested in another call', async () => {
    const { src, lines } = await sinkLines(`  const d = diff(fs.readFileSync(report, 'utf8'), other);\n  console.log(d.length);`);
    expect(lines).toContain(lineOf(src, `fs.readFileSync(report`));
  });
});
