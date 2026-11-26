/**
 * Dogfood 2026-11-03 (cognium-ai circle-ir-ai security-scan/scanner.ts,
 * skills/bundle-loader.ts): a call to a method that holds a sink was credited
 * with the first source above it in the file, though no argument of that call
 * carries taint. The callee counted as tainted only because its own parameters
 * are speculative `interprocedural_param` sources; the source paired with it
 * (`fs.readFileSync` of `principles.md` / `SKILL.md`) was in another function
 * whose result never reached the call. 5 high path_traversal findings.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const lineOf = (src: string, needle: string) => src.split('\n').findIndex(l => l.includes(needle)) + 1;

async function pathSinks(src: string): Promise<number[]> {
  const ir = await analyze(src, 'scanner.ts', 'typescript');
  return (ir.taint.flows ?? []).filter(f => f.sink_type === 'path_traversal').map(f => f.sink_line);
}

const unrelated = `import * as fs from 'fs';
import * as path from 'path';
function parseRules(text: string): string[] { return text.split('\\n'); }
function loadRules(repoPath: string): string[] {
  const p = path.join(repoPath, '.specifica/principles.md');
  return parseRules(fs.readFileSync(p, 'utf8'));
}
export class Scanner {
  private rules: string[] = [];
  async scan(repoPath: string, outputDir: string): Promise<void> {
    this.rules = loadRules(repoPath);
    const report = { count: this.rules.length };
    this.saveReport(report, outputDir);
  }
  private saveReport(report: object, outputDir: string): void {
    const jsonPath = path.join(outputDir, 'scan.json');
    fs.writeFileSync(jsonPath, JSON.stringify(report));
  }
}
`;

const freeFunctions = `import * as fs from 'fs';
function save(dest: string): void {
  fs.writeFileSync(dest, 'x');
}
export function main(): void {
  const dest = process.argv[2];
  save(dest);
}
`;

const carriedEnv = `import * as fs from 'fs';
export class Scanner {
  scan(): void {
    const dir = process.env.OUT_DIR;
    this.save(dir);
  }
  private save(dest: string): void {
    fs.writeFileSync(dest + '/scan.json', 'x');
  }
}
`;

// #1314: the shape behind the two juice-shop ReDoS flows that #1121 removed.
// The read is in `collectTemplates` and the RegExp in `markerLines`. Neither
// calls the other, and the files read come from a fixed in-repo path list.
// Before #1121 both RegExp lines were paired with the read by line order.
const fixedPathsRegex = `import fs from 'node:fs/promises'

export const TEMPLATE_DIRS = Object.freeze(['./views', './partials'])

interface Template {
  name: string
  body: string
}

export const collectTemplates = async (dirs: readonly string[]): Promise<Template[]> => {
  const found = []
  for (const dir of dirs) {
    const body = await fs.readFile(dir, 'utf8')
    if (body.includes('@marker')) {
      found.push({ name: dir, body })
    }
  }
  return found
}

function templateMarkers (t: Template) {
  const body = t.body
  const tags = body.split(' ').filter(Boolean)
  return tags.map((tag) => markerLines(body, tag))
}

function markerLines (text: string, tag: string) {
  const rows = text.split('\\n')
  const open = []
  const close = []
  for (let i = 0; i < rows.length; i++) {
    if (new RegExp(\`@marker open.*\${tag}\`).exec(rows[i]) != null) {
      open.push(i + 1)
    } else if (new RegExp(\`@marker close.*\${tag}\`).exec(rows[i]) != null) {
      close.push(i + 1)
    }
  }
  return { tag, open, close }
}
`;

describe('interprocedural: a call edge pairs with a source only when it carries taint', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('does not credit an unrelated source in another function to a call with no tainted argument', async () => {
    expect(await pathSinks(unrelated)).not.toContain(lineOf(unrelated, 'fs.writeFileSync(jsonPath'));
  });

  it('still reports a source in the calling free function, callee declared first', async () => {
    expect(await pathSinks(freeFunctions)).toContain(lineOf(freeFunctions, 'fs.writeFileSync(dest'));
  });

  it('still reports a caller-local source passed to a method', async () => {
    expect(await pathSinks(carriedEnv)).toContain(lineOf(carriedEnv, 'fs.writeFileSync(dest'));
  });

  it('does not pair a file read from fixed paths with a RegExp in a function it never calls (#1314)', async () => {
    const ir = await analyze(fixedPathsRegex, 'templates.ts', 'typescript');
    const redos = (ir.taint.flows ?? []).filter(f => f.sink_type === 'redos').map(f => f.sink_line);
    expect(redos).not.toContain(lineOf(fixedPathsRegex, '@marker open'));
    expect(redos).not.toContain(lineOf(fixedPathsRegex, '@marker close'));
  });
});
