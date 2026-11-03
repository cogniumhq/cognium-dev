/**
 * `ids@0.1` on TypeScript/JavaScript, end to end over real `analyze()` output:
 * node ids are as stable as the body id they hang from. Reformatting,
 * comments and reordering other declarations keep every declaration, body
 * and node id; a signature change re-keys that declaration and nothing else;
 * two runs agree byte for byte; and the module stays browser-safe.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyze, initAnalyzer } from '../../src/analyzer.js';
import {
  assignNodeIds,
  deriveStableIds,
  diffStableIds,
  nodeIdBytesOfPrinted,
  base32,
  type StableDecl,
  type StableIdFile,
  type StableNodeIds,
} from '../../src/stable-ids/index.js';
import type { CircleIR } from '../../src/types/index.js';

beforeAll(async () => {
  await initAnalyzer();
});

type Lang = 'typescript' | 'javascript';

interface Run {
  ir: CircleIR;
  ids: StableIdFile;
  nodes: StableNodeIds;
}

async function run(code: string, lang: Lang = 'typescript', file = lang === 'typescript' ? 'src/a.ts' : 'src/a.js'): Promise<Run> {
  const ir = await analyze(code, file, lang);
  const ids = await deriveStableIds(code, file, lang, { packageName: 'pkg' });
  return { ir, ids, nodes: assignNodeIds(ids, ir) };
}

const KINDS = ['cfg_blocks', 'dfg_defs', 'dfg_uses', 'calls'] as const;

/** Every node id, grouped by kind and by the qualified name of the body it hangs from. */
function nodesByDecl(r: Run): Record<string, Record<string, string[]>> {
  const out: Record<string, Record<string, string[]>> = {};
  for (const d of r.ids.decls) {
    out[d.qualified_name] = {};
    for (const k of KINDS) out[d.qualified_name][k] = r.nodes[k].filter((n): n is string => n !== null && n.startsWith(d.body_id + '/'));
  }
  return out;
}

/** Declaration id, body id and node ids of every declaration. */
function snapshot(r: Run): Record<string, { id: string; body_id: string; nodes: Record<string, string[]> }> {
  const nodes = nodesByDecl(r);
  return Object.fromEntries(r.ids.decls.map(d => [d.qualified_name, { id: d.id, body_id: d.body_id, nodes: nodes[d.qualified_name] }]));
}

function decl(r: Run, qname: string): StableDecl {
  const d = r.ids.decls.find(x => x.qualified_name === qname);
  if (!d) throw new Error(`no ${qname} in ${r.ids.decls.map(x => x.qualified_name).join(', ')}`);
  return d;
}

// Callbacks written across lines, then the same code with each callback on
// the line of the statement that holds it (a formatter's choice, nothing else).
const SPREAD = `import { log } from './log';

export function outer(xs: number[]): number[] {
  const ys = xs.map((x) => {
    const z = x + 1;
    return z;
  });
  if (ys.length > 0) {
    log(ys);
  }
  return ys.filter(
    (y) => y > 2,
  );
}

export class Box {
  private items: string[] = [];
  names(prefix: string): string[] {
    const out = this.items
      .filter((s) => s.startsWith(prefix))
      .map((s) => {
        return s.trim();
      });
    return out;
  }
}

export const total = (vs: number[]) =>
  vs.reduce((a, b) => a + b, 0);
`;

const PACKED = `import { log } from "./log"
export function outer(xs: number[]): number[] { const ys = xs.map(x => { const z = x + 1; return z }); if (ys.length > 0) { log(ys) } return ys.filter(y => y > 2) }
export class Box { private items: string[] = []; names(prefix: string): string[] { const out = this.items.filter(s => s.startsWith(prefix)).map(s => { return s.trim() }); return out } }
export const total = (vs: number[]) => vs.reduce((a, b) => a + b, 0)
`;

describe('node ids follow the body id', () => {
  it('reformatting keeps every declaration, body and node id, callbacks on one line included', async () => {
    const a = await run(SPREAD);
    const b = await run(PACKED);
    const d = diffStableIds([a.ids], [b.ids]);
    expect(d.added).toEqual([]);
    expect(d.removed).toEqual([]);
    expect(d.body_changed).toEqual([]);
    expect(snapshot(b)).toEqual(snapshot(a));
    // Not vacuous: the bodies hold nodes of every kind.
    const outer = nodesByDecl(a)['pkg/a:outer'];
    for (const k of KINDS) expect(outer[k].length, k).toBeGreaterThan(0);
  });

  it('places a node on a shared line in its own body, not in the callback that starts there', async () => {
    const r = await run(SPREAD);
    const outer = decl(r, 'pkg/a:outer');
    const callback = r.ids.decls.find(x => x.parent === outer.id && x.flags.includes('unstable:anonymous') && x.start_line === 4);
    expect(callback).toBeDefined();
    const ys = r.ir.dfg.defs.findIndex(x => x.variable === 'ys');
    const x = r.ir.dfg.defs.findIndex(v => v.variable === 'x' && v.kind === 'param');
    expect(r.nodes.dfg_defs[ys]?.startsWith(outer.body_id + '/')).toBe(true);
    expect(r.nodes.dfg_defs[x]?.startsWith((callback as StableDecl).body_id + '/')).toBe(true);
    // The statement holding the callback is a block of the outer body.
    const stmt = r.ir.cfg.blocks.findIndex(blk => blk.start_line === 4 && blk.end_line === 7);
    expect(r.nodes.cfg_blocks[stmt]?.startsWith(outer.body_id + '/')).toBe(true);
  });

  it('comments, blank lines and reordering other declarations keep every id', async () => {
    const a = await run(SPREAD);
    const [head, rest] = SPREAD.split('export function outer');
    const [outerText, afterOuter] = ('export function outer' + rest).split('export class Box');
    const [boxText, totalText] = ('export class Box' + afterOuter).split('export const total');
    const reordered = `${head}/** Totals. */\n\nexport const total${totalText}\n// A box.\n${boxText.replace('names(prefix', '/* by prefix */ names(prefix')}\n\n\n${outerText.replace('if (ys.length', '// guard\n  if (ys.length')}`;
    const b = await run(reordered);
    const d = diffStableIds([a.ids], [b.ids]);
    expect(d.added).toEqual([]);
    expect(d.removed).toEqual([]);
    // Only the module's own body changed: its statements are in another order.
    expect(d.body_changed.map(([x]) => x.qualified_name)).toEqual(['pkg/a']);
    const sa = snapshot(a);
    const sb = snapshot(b);
    delete sa['pkg/a'];
    delete sb['pkg/a'];
    expect(sb).toEqual(sa);
  });

  it('JavaScript: reformatting keeps node ids too', async () => {
    const spread = `function handler(req, res) {\n  const rows = req.items.map((r) => {\n    return r.id;\n  });\n  res.send(rows);\n}\nmodule.exports.handler = handler;\n`;
    const packed = `function handler(req, res) { const rows = req.items.map(r => { return r.id }); res.send(rows) }\nmodule.exports.handler = handler\n`;
    const a = await run(spread, 'javascript');
    const b = await run(packed, 'javascript');
    expect(a.ids.language).toBe('javascript');
    expect(snapshot(b)).toEqual(snapshot(a));
  });
});

describe('a signature change re-keys that declaration and nothing else', () => {
  const BASE = `export function target(a: string, b: number): string {
  return a.repeat(b);
}

export function bystander(s: string) {
  return s.length;
}

export class K {
  run(n: number): void { console.log(n); }
}
`;

  const EDITS: [string, string, string][] = [
    ['parameter type', 'b: number)', 'b: bigint)'],
    ['arity', 'b: number)', 'b: number, c: boolean)'],
    ['optional parameter', 'b: number)', 'b?: number)'],
    ['rest parameter', 'b: number)', '...b: number[])'],
    ['return type', '): string {', '): String {'],
    ['type parameters', 'function target(', 'function target<T>('],
  ];

  for (const [what, from, to] of EDITS) {
    it(what, async () => {
      const a = await run(BASE);
      const b = await run(BASE.replace(from, to));
      const was = decl(a, 'pkg/a:target');
      const now = decl(b, 'pkg/a:target');
      expect(now.signature).not.toBe(was.signature);
      expect(now.id).not.toBe(was.id);
      expect(now.body_id).not.toBe(was.body_id);
      // Its node ids move with it...
      const before = nodesByDecl(a)['pkg/a:target'];
      const after = nodesByDecl(b)['pkg/a:target'];
      expect(after.calls.length).toBeGreaterThan(0);
      for (const k of KINDS) for (const n of after[k]) expect(before[k]).not.toContain(n);
      // ...and every other declaration keeps its ids, its body and its nodes.
      const sa = snapshot(a);
      const sb = snapshot(b);
      for (const s of [sa, sb]) {
        delete s['pkg/a'];
        delete s['pkg/a:target'];
      }
      expect(sb).toEqual(sa);
    });
  }

  it('a member modifier (static, getter) is part of a method signature', async () => {
    const a = await run(BASE);
    for (const edited of [BASE.replace('  run(n', '  static run(n'), BASE.replace('  run(n: number): void', '  get run(): void')]) {
      const b = await run(edited);
      expect(decl(b, 'pkg/a:K.run').id).not.toBe(decl(a, 'pkg/a:K.run').id);
      expect(decl(b, 'pkg/a:bystander').body_id).toBe(decl(a, 'pkg/a:bystander').body_id);
    }
  });

  it('JavaScript: arity is the signature', async () => {
    const a = await run('function f(a) { return a; }\nfunction g() {}\n', 'javascript');
    const b = await run('function f(a, b) { return a; }\nfunction g() {}\n', 'javascript');
    const c = await run('function f(x) { return x; }\nfunction g() {}\n', 'javascript');
    expect(decl(b, 'pkg/a:f').id).not.toBe(decl(a, 'pkg/a:f').id);
    expect(decl(c, 'pkg/a:f').id).toBe(decl(a, 'pkg/a:f').id);
    expect(decl(b, 'pkg/a:g').body_id).toBe(decl(a, 'pkg/a:g').body_id);
  });
});

describe('determinism', () => {
  it('two runs give the same ids, node ids and fixed-width node bytes', async () => {
    const a = await run(SPREAD);
    const b = await run(SPREAD);
    expect(b.ids).toEqual(a.ids);
    expect(b.nodes).toEqual(a.nodes);
    const bytes = (r: Run) => KINDS.flatMap(k => r.nodes[k].filter((n): n is string => n !== null).map(n => base32(nodeIdBytesOfPrinted(n))));
    const ba = bytes(a);
    expect(bytes(b)).toEqual(ba);
    expect(ba.length).toBeGreaterThan(20);
    for (const n of ba) expect(n).toMatch(/^[a-z2-7]{26}$/);
    // Node ids are distinct within one file.
    expect(new Set(ba).size).toBe(ba.length);
  });
});

describe('IR positions the node ids rely on', () => {
  it('JavaScript/TypeScript CFG blocks, defs and uses carry a 0-based column', async () => {
    const { ir } = await run(SPREAD);
    expect(ir.cfg.blocks.length).toBeGreaterThan(0);
    for (const b of ir.cfg.blocks) expect(b.start_column, JSON.stringify(b)).toEqual(expect.any(Number));
    for (const d of ir.dfg.defs) expect(d.column, JSON.stringify(d)).toEqual(expect.any(Number));
    for (const u of ir.dfg.uses) expect(u.column, JSON.stringify(u)).toEqual(expect.any(Number));
    const lines = SPREAD.split('\n');
    const ys = ir.dfg.defs.find(d => d.variable === 'ys');
    expect(lines[(ys?.line ?? 0) - 1].slice(ys?.column)).toMatch(/^ys = /);
    // The exit block sits on the closing brace of its body.
    const exit = ir.cfg.blocks.find(b => b.type === 'exit');
    expect(lines[(exit?.start_line ?? 0) - 1][exit?.start_column ?? -1]).toBe('}');
  });

  it('a lone arrow parameter is a param def with or without parentheses', async () => {
    for (const lang of ['typescript', 'javascript'] as const) {
      const bare = (await run('const f = (xs) => xs.map(x => x + 1);\n', lang)).ir.dfg;
      const parens = (await run('const f = (xs) => xs.map((x) => x + 1);\n', lang)).ir.dfg;
      const params = (dfg: typeof bare) => dfg.defs.filter(d => d.kind === 'param').map(d => d.variable);
      expect(params(bare), lang).toEqual(['xs', 'x']);
      expect(params(parens), lang).toEqual(['xs', 'x']);
      // The use of `x` in the callback reaches its own param def either way.
      const reach = (dfg: typeof bare) => {
        const x = dfg.defs.find(d => d.variable === 'x' && d.kind === 'param');
        return dfg.uses.filter(u => u.variable === 'x').some(u => u.def_id === x?.id);
      };
      expect(reach(bare), lang).toBe(true);
      expect(reach(parens), lang).toBe(true);
    }
  });

  it('Java defs and uses keep their shape; Java CFG blocks gain the column', async () => {
    const ir = await analyze('class A {\n  int f(int n) {\n    int m = n + 1;\n    return m;\n  }\n}\n', 'A.java', 'java');
    const m = ir.dfg.defs.find(d => d.variable === 'm');
    expect(m).toBeDefined();
    expect(m && 'column' in m).toBe(false);
    for (const u of ir.dfg.uses) expect('column' in u).toBe(false);
    expect(ir.cfg.blocks.length).toBeGreaterThan(0);
    for (const b of ir.cfg.blocks) expect(b.start_column).toEqual(expect.any(Number));
  });
});

describe('browser-safe', () => {
  it('the stable-ids module uses no Node.js API', () => {
    const dir = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'src', 'stable-ids');
    const files = readdirSync(dir).filter(f => f.endsWith('.ts'));
    expect(files.length).toBeGreaterThan(5);
    const banned = [
      /from\s+['"](?:node:|fs|path|os|crypto|child_process|module|url|util|buffer)(?:\/[^'"]*)?['"]/,
      /\bimport\s*\(\s*['"](?:node:|fs|path|os|crypto|child_process)/,
      /\brequire\s*\(/,
      /\bprocess\.\w/,
      /\bBuffer\b/,
      /\b__dirname\b|\b__filename\b/,
    ];
    for (const f of files) {
      const src = readFileSync(join(dir, f), 'utf8');
      for (const re of banned) expect(re.test(src), `${f}: ${re}`).toBe(false);
    }
  });
});
