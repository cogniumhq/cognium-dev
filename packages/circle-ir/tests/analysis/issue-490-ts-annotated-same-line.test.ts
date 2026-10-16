/**
 * cognium-dev#490 (TypeScript slice) — a second declaration on the source line
 * does not inherit the taint when the declarations carry type annotations.
 *
 * The source's binding was recovered from `const q: string = req.query.q` as the
 * annotation (`string`), so the same-line seeding found no definition of its own
 * and tainted every definition on the line: `const tool: string = "ls"` beside it
 * reached `exec(tool)`.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const route = (...body: string[]): string =>
  [
    'import express from "express";',
    'import { exec } from "child_process";',
    'const app = express();',
    '',
    'app.get("/run", (req: any, res: any) => {',
    ...body.map((l) => '  ' + l),
    '  res.end("ok");',
    '});',
    '',
  ].join('\n');

const cmdi = async (code: string, file = 'run_route.ts'): Promise<number[]> => {
  const r = await analyze(code, file, 'typescript');
  return (r.taint.flows ?? []).filter((f) => f.sink_type === 'command_injection').map((f) => f.sink_line).sort();
};

describe('#490 TypeScript: an annotated neighbour on the source line is not tainted', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('annotated source and annotated constant on one line: exec(tool) is clean', async () => {
    const code = route('const q: string = req.query.q; const tool: string = "ls";', 'exec(tool);');
    expect(await cmdi(code)).toEqual([]);
  });

  it('a neighbour built from the annotated source on the same line still fires', async () => {
    const code = route('const w: string = req.query.w; const cmd: string = "make " + w;', 'exec(cmd);');
    expect(await cmdi(code)).toEqual([7]);
  });

  it('the annotated source itself still fires when it reaches the sink', async () => {
    const code = route('const q: string = req.query.q; const tool: string = "ls";', 'exec(q);');
    expect(await cmdi(code)).toEqual([7]);
  });

  it('is not keyed on names or on the keyword: let / var, other names and types', async () => {
    for (const kw of ['let', 'var', 'const']) {
      const clean = route(`${kw} target: string | undefined = req.query.t; ${kw} binary: string = "ping";`, 'exec(binary);');
      expect(await cmdi(clean, 'other.ts'), kw).toEqual([]);
      const dirty = route(`${kw} target: string | undefined = req.query.t; ${kw} binary: string = "ping";`, 'exec(target as string);');
      expect(await cmdi(dirty, 'other.ts'), kw).toEqual([7]);
    }
  });

  it('a generic annotation on the source is read as an annotation', async () => {
    const code = route(
      'const params: Record<string, string> = req.query as any; const tool: string = "ls";',
      'exec(tool);',
    );
    expect(await cmdi(code)).toEqual([]);
  });

  it('the neighbour declared before the source on the line is not tainted either', async () => {
    const code = route('const tool: string = "ls"; const q: string = req.query.q;', 'exec(tool);');
    expect(await cmdi(code)).toEqual([]);
  });

  it('unannotated source with an annotated neighbour is unchanged (clean)', async () => {
    const code = route('const q = req.query.q; const tool: string = "ls";', 'exec(tool);');
    expect(await cmdi(code)).toEqual([]);
  });

  it('split over two lines: the annotated constant is clean and the source still fires', async () => {
    const clean = route('const q: string = req.query.q;', 'const tool: string = "ls";', 'exec(tool);');
    expect(await cmdi(clean)).toEqual([]);
    const dirty = route('const q: string = req.query.q;', 'const tool: string = "ls";', 'exec(q);');
    expect(await cmdi(dirty)).toEqual([8]);
  });

  it('a source declared with an annotation and alone on its line still fires', async () => {
    const code = route('const q: string = req.query.q;', 'exec("ls " + q);');
    expect(await cmdi(code)).toEqual([7]);
  });

  it('a later reassignment of the annotated neighbour to a request value fires', async () => {
    const code = route(
      'const q: string = req.query.q; let tool: string = "ls";',
      'tool = req.query.t;',
      'exec(tool);',
    );
    expect(await cmdi(code)).toEqual([8]);
  });
});
