/**
 * JS/TS cross-file flows: a tainted value carried into a method in another file
 * is credited to a sink in that method only when it reaches the sink's own
 * arguments (dogfood 2026-11-01, circle-pack: a route value bound as a `?`
 * parameter was credited to `db.prepare(<constant SQL>)` in the callee).
 * A value derived through a literal-only assignment (`x = cond ? 'a' : 'b'`)
 * carries no taint into the sink.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';

const route = `import { Hono } from 'hono';
import { svc } from './svc';
const app = new Hono();
app.get('/r', (c) => {
  const name = c.req.query('name');
  return c.json(svc.run({ name }));
});
`;
const svc = (body: string) => `import { exec } from 'child_process';
export class Svc {
  run(options: { name?: string } = {}) {
${body}
  }
}
export const svc = new Svc();
`;

async function cmdFlows(body: string): Promise<number> {
  const r = await analyzeProject([
    { code: svc(body), filePath: 'src/svc.ts', language: 'typescript' },
    { code: route, filePath: 'src/routes.ts', language: 'typescript' },
  ]);
  return r.files.flatMap(f => f.analysis.taint.flows.filter(x => x.sink_type === 'command_injection')).length
    + (r.taint_paths ?? []).filter(p => p.sink?.type === 'command_injection').length;
}

describe('JS cross-file: the carried parameter must reach the sink arguments', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('a sink built from an unrelated variable is not credited', async () => {
    expect(await cmdFlows("    const dir = process.cwd();\n    exec(`ls ${dir}`);\n    return { greeting: 'hi ' + options.name };")).toBe(0);
  });

  it('a literal-only ternary on the parameter does not carry it', async () => {
    expect(await cmdFlows("    const flag = options.name ? '-la' : '-l';\n    exec(`ls ${flag}`);\n    return {};")).toBe(0);
    expect(await cmdFlows("    let flag = '';\n    flag = options.name ? '-a' : \"-b\";\n    exec('ls ' + flag);\n    return {};")).toBe(0);
  });

  it('the parameter into the sink, directly or derived, still flows', async () => {
    expect(await cmdFlows("    exec('ls ' + options.name);\n    return {};")).toBeGreaterThan(0);
    expect(await cmdFlows("    const n = options.name;\n    const cmd = `ls ${n}`;\n    exec(cmd);\n    return {};")).toBeGreaterThan(0);
    // a ternary that can yield the value itself is not literal-only
    expect(await cmdFlows("    const n = options.name ? options.name : 'x';\n    exec('ls ' + n);\n    return {};")).toBeGreaterThan(0);
  });
});
