/**
 * Dogfood 2026-10-31 (cognium-ai benchmarks/lib/juliet-method-scope.ts):
 * `METHOD_DECL.exec(lines[i])`, where `const METHOD_DECL =` has its regex
 * literal on the next line, was a critical command_injection. #310's regex
 * receiver check read the declaration one line at a time.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const cmdSinks = async (code: string) =>
  (await analyze(code, 'scope.ts', 'typescript')).taint.sinks.filter(s => s.type === 'command_injection');

describe('RegExp.exec with a wrapped or typed declaration is not command execution', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('literal on the next line', async () => {
    const code = `const METHOD_DECL =\n  /^\\s*(public|private)\\s+\\w+\\s*\\(/;\nexport function scan(lines: string[]) {\n  for (let i = 0; i < lines.length; i++) {\n    const decl = METHOD_DECL.exec(lines[i]);\n    if (decl) return i;\n  }\n  return -1;\n}`;
    expect(await cmdSinks(code)).toHaveLength(0);
  });

  it('a field typed RegExp', async () => {
    const code = `export class S {\n  private re: RegExp;\n  constructor(p: string) { this.re = new RegExp(p); }\n  find(line: string) { return re.exec(line); }\n}\nconst re: RegExp = /x/;`;
    expect(await cmdSinks(code)).toHaveLength(0);
  });

  it('child_process exec is still a sink', async () => {
    const code = `import { exec } from 'child_process';\nexport function run(cmd: string) {\n  exec(cmd);\n}`;
    expect((await cmdSinks(code)).length).toBeGreaterThan(0);
  });
});
