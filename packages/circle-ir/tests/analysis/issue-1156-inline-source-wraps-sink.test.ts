/**
 * cognium-dev #1156: when a source call and a sink call share a line and the
 * sink is nested inside the source's argument list, the source's result
 * cannot reach the sink. The sink runs first, and the source consumes its result.
 *
 * Dogfood shape: `parser.parse(fs.readFileSync(abs, 'utf-8'))`, where
 * `parse()` is an io_input source and `readFileSync` a path_traversal sink.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const file = (body: string) => `import * as fs from 'fs';
import type { Request, Response } from 'express';

interface Parser { file: string; parse(text: string): string[] }
const PARSERS: Parser[] = [];

export function walk(abs: string, name: string, req: Request, res: Response): string[] {
  const parser = PARSERS.find((m) => m.file === name);
  if (!parser) return [];
${body}
}
`;

async function pathFlows(body: string) {
  const ir = await analyze(file(body), 'src/walk.ts', 'typescript');
  return (ir.taint.flows ?? []).filter(f => f.sink_type === 'path_traversal');
}

describe('#1156: inline source that wraps the sink', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('parse(readFileSync(abs)) is not a flow from parse() into readFileSync', async () => {
    expect(await pathFlows(`  const deps = parser.parse(fs.readFileSync(abs, 'utf-8')).map((d) => d.trim());
  return deps;`)).toHaveLength(0);
  });

  it('the spread / push form is not a flow either', async () => {
    expect(await pathFlows(`  const out: string[] = [];
  out.push(...parser.parse(fs.readFileSync(abs, 'utf-8')));
  return out;`)).toHaveLength(0);
  });

  it('a source nested inside the sink still flows', async () => {
    expect((await pathFlows(`  res.send(fs.readFileSync(req.query.p as string, 'utf-8'));
  return [];`)).length).toBeGreaterThan(0);
  });

  it('a sink call outside the source call on the same line still flows', async () => {
    expect((await pathFlows(`  const a = parser.parse(fs.readFileSync(abs, 'utf-8')); fs.readFileSync(a[0], 'utf-8');
  return a;`)).length).toBeGreaterThan(0);
  });
});
