/**
 * cognium-dev a file read is not its own path-traversal sink.
 *
 * `fs.readFileSync` is both a `file_input` source (its return value) and a
 * `path_traversal` sink (its path argument). Inside a callback such as
 * `names.map((n) => fs.readFileSync(path.join(dir, n)))` the callback
 * parameter shares the read's line, so it was seeded as if the read's content
 * defined it, and the content then "reached" the read's own path argument.
 * A directory entry joined to the directory it came from, or a constant name
 * joined to a root, carries no taint of its own.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const header = `import * as fs from 'fs';
import { promises as fsp } from 'fs';
import * as path from 'path';
import type { Request, Response } from 'express';
`;

async function pathFlows(body: string) {
  const ir = await analyze(header + body, 'src/files.ts', 'typescript');
  return (ir.taint.flows ?? []).filter(f => f.sink_type === 'path_traversal');
}

describe('a read does not taint its own path argument', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('readdir entry joined to its directory inside map() is not a flow', async () => {
    expect(await pathFlows(`export function walk(dir: string): string[] {
  return fs.readdirSync(dir).map((e) => fs.readFileSync(path.join(dir, e), 'utf-8'));
}
`)).toHaveLength(0);
  });

  it('readdir entry joined to its directory in a for-of loop is not a flow', async () => {
    expect(await pathFlows(`export function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of fs.readdirSync(dir)) {
    const full = path.join(dir, entry);
    out.push(fs.readFileSync(full, 'utf-8'));
  }
  return out;
}
`)).toHaveLength(0);
  });

  it('async readdir + readFile inside map() is not a flow', async () => {
    expect(await pathFlows(`export async function walk(dir: string): Promise<string[]> {
  const names = await fsp.readdir(dir);
  return Promise.all(names.map(async (n) => fsp.readFile(path.join(dir, n), 'utf-8')));
}
`)).toHaveLength(0);
  });

  it('a read inside forEach() is not a flow into its own path', async () => {
    expect(await pathFlows(`export function all(files: string[]): string[] {
  const out: string[] = [];
  files.forEach((f) => { out.push(fs.readFileSync(f, 'utf-8')); });
  return out;
}
`)).toHaveLength(0);
  });

  it('root + constant name is not tainted', async () => {
    expect(await pathFlows(`export function cfg(root: string): string {
  const pkg = fs.readFileSync(path.join(root, 'package.json'), 'utf-8');
  const ts = fs.readFileSync(path.join(root, 'tsconfig.json'), 'utf-8');
  return pkg + ts;
}
`)).toHaveLength(0);
  });

  it('root + constant names mapped in a callback is not tainted', async () => {
    expect(await pathFlows(`export function cfg(root: string): string[] {
  return ['package.json', 'tsconfig.json'].map((n) => fs.readFileSync(path.join(root, n), 'utf-8'));
}
`)).toHaveLength(0);
  });

  it('request input joined to a root still flows', async () => {
    expect((await pathFlows(`const root = '/srv/files';
export function get(req: Request, res: Response) {
  res.send(fs.readFileSync(path.join(root, req.query.f as string), 'utf-8'));
}
`)).length).toBeGreaterThan(0);
  });

  it('request input joined to a root inside an inline handler still flows', async () => {
    expect((await pathFlows(`const root = '/srv/files';
declare const app: { get(p: string, h: (req: Request, res: Response) => void): void };
app.get('/f', (req, res) => res.send(fs.readFileSync(path.join(root, req.query.f as string), 'utf-8')));
`)).length).toBeGreaterThan(0);
  });

  it('a directory taken from the request still flows into the joined read', async () => {
    expect((await pathFlows(`export function list(req: Request, res: Response) {
  const dir = path.join('/srv', req.query.d as string);
  const out: string[] = [];
  for (const entry of fs.readdirSync(dir)) {
    out.push(fs.readFileSync(path.join(dir, entry), 'utf-8'));
  }
  res.json(out);
}
`)).length).toBeGreaterThan(0);
  });
});
