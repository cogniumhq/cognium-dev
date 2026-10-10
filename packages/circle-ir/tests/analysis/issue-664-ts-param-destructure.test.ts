/**
 * #664 — TypeScript object patterns in a parameter list must bind taint
 * the same way JavaScript does. `speculativeParamSources` is required:
 * a bare parameter is not a source unless that opt-in is set.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const EXEC = `import { exec } from 'child_process';`;

async function commandFlows(code: string, lang: 'typescript' | 'javascript') {
  const ir = await analyze(code, lang === 'typescript' ? 'a.ts' : 'a.js', lang, {
    speculativeParamSources: true,
  });
  const flows = (ir.taint.flows ?? []).filter(f => f.sink_type === 'command_injection');
  const params = ir.dfg.defs.filter(d => d.kind === 'param').map(d => d.variable);
  return { flows, params };
}

describe('#664 TypeScript destructured parameters bind taint', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('binds { id } and flows like the JavaScript twin', async () => {
    const ts = await commandFlows(
      `${EXEC}
export function resolve(_: unknown, { id }: { id: string }) {
  exec("ls " + id);
}`,
      'typescript',
    );
    const js = await commandFlows(
      `${EXEC}
function resolve(_, { id }) { exec("ls " + id); }`,
      'javascript',
    );
    expect(ts.params).toContain('id');
    expect(ts.flows.length).toBe(js.flows.length);
    expect(ts.flows.length).toBeGreaterThan(0);
    expect(ts.flows.map(f => f.sink_type)).toEqual(js.flows.map(f => f.sink_type));
  });

  it('renamed { q } has the same flow count and sink type', async () => {
    const id = await commandFlows(
      `${EXEC}
export function resolve(_: unknown, { id }: { id: string }) {
  exec("ls " + id);
}`,
      'typescript',
    );
    const q = await commandFlows(
      `${EXEC}
export function resolve(_: unknown, { q }: { q: string }) {
  exec("ls " + q);
}`,
      'typescript',
    );
    expect(q.params).toContain('q');
    expect(q.flows.length).toBe(id.flows.length);
    expect(q.flows.map(f => f.sink_type)).toEqual(id.flows.map(f => f.sink_type));
  });

  it('binds a nested { a: { b } } pattern', async () => {
    const r = await commandFlows(
      `${EXEC}
export function resolve(_: unknown, { a: { b } }: { a: { b: string } }) {
  exec("ls " + b);
}`,
      'typescript',
    );
    expect(r.params).toContain('b');
    expect(r.flows.length).toBeGreaterThan(0);
  });

  it('binds a typed parameter that has a default value', async () => {
    const r = await commandFlows(
      `${EXEC}
export function resolve(_: unknown, { id }: { id: string } = { id: "x" }) {
  exec("ls " + id);
}`,
      'typescript',
    );
    expect(r.params).toContain('id');
    expect(r.flows.length).toBeGreaterThan(0);
  });

  it('a local destructure of a literal stays clean', async () => {
    const r = await commandFlows(
      `${EXEC}
export function run() { const { id } = { id: "fixed" }; exec("ls " + id); }`,
      'typescript',
    );
    expect(r.flows).toEqual([]);
  });

  it('keeps property, empty-object, and body-destructure flows that already exist', async () => {
    const prop = await commandFlows(
      `${EXEC}
function f(args) { const q = args.id; exec("ls " + q); }`,
      'javascript',
    );
    const body = await commandFlows(
      `${EXEC}
function f(args) { const { id } = args; exec("ls " + id); }`,
      'javascript',
    );
    const opts = await commandFlows(
      `${EXEC}
export function f(opts = {}) { exec("ls " + opts.id); }`,
      'typescript',
    );
    expect(prop.flows.length).toBeGreaterThan(0);
    expect(body.flows.length).toBeGreaterThan(0);
    expect(opts.flows.length).toBeGreaterThan(0);
  });
});
