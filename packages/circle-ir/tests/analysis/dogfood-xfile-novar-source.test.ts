/**
 * Dogfood 2026-10-31 (cognium-ai security-scan/scanner.ts): a source with no
 * variable — `parseSinkSuppressions(fs.readFileSync(p, 'utf8'))` — skipped the
 * cross-file variable-connectivity gate, so every later cross-file call in the
 * file (`detectCoordinate(repoPath)` in another function) became a path to that
 * callee's sinks: 12 path_traversal findings in unrelated files.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';

const coordinate = `import * as fs from 'fs';
export function detectCoordinate(repoRoot: string): string {
  return fs.readFileSync(repoRoot + '/package.json', 'utf8');
}`;
const scanner = (body: string) => `import * as fs from 'fs';
import { detectCoordinate } from './coordinate';
function parse(text: string): string[] { return text.split('\\n'); }
export function load(p: string): string[] {
${body}
}
export function scan(repoPath: string): string {
  return detectCoordinate(repoPath);
}`;

const paths = async (body: string) => {
  const r = await analyzeProject([
    { code: coordinate, filePath: 'coordinate.ts', language: 'typescript' },
    { code: scanner(body), filePath: 'scanner.ts', language: 'typescript' },
  ]);
  return r.taint_paths.filter(t => t.source.file === 'scanner.ts' && t.sink.file === 'coordinate.ts');
};

describe('cross-file: a source with no variable reaches only the call it is nested in', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('does not reach a later, unrelated cross-file call', async () => {
    expect(await paths(`  return parse(fs.readFileSync(p, 'utf8'));`)).toHaveLength(0);
  });
});
