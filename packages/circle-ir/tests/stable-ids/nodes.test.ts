/**
 * Node ids are re-scoped to the body: an edit to one function shifts every
 * per-file IR id after it, but leaves another function's node ids unchanged.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';
import { assignNodeIds, deriveStableIds, type StableIdFile } from '../../src/stable-ids/index.js';
import type { CircleIR } from '../../src/types/index.js';

beforeAll(async () => {
  await initAnalyzer();
});

const A = `export function first(req: any) {
  const q = req.query.q;
  return q;
}
`;
const B = `export function second(x: string) {
  const y = x.trim();
  if (y) { console.log(y); }
  return y;
}
`;

async function both(code: string): Promise<{ ir: CircleIR; ids: StableIdFile }> {
  const ir = await analyze(code, 'src/a.ts', 'typescript');
  const ids = await deriveStableIds(code, 'src/a.ts', 'typescript', { packageName: 'p' });
  return { ir, ids };
}

/** Node ids belonging to the declaration named `name`. */
function under(ids: StableIdFile, nodeIds: (string | null)[], name: string): string[] {
  const d = ids.decls.find(x => x.name === name);
  if (!d) throw new Error(name);
  return nodeIds.filter((n): n is string => n !== null && n.startsWith(d.body_id + '/'));
}

describe('assignNodeIds', () => {
  it('keys nodes by body id plus a per-body index', async () => {
    const { ir, ids } = await both(A + B);
    const n = assignNodeIds(ids, ir);
    expect(n.dfg_defs.length).toBe(ir.dfg.defs.length);
    expect(n.calls.length).toBe(ir.calls.length);
    expect(n.cfg_blocks.length).toBe(ir.cfg.blocks.length);
    const second = under(ids, n.calls, 'second');
    expect(second.length).toBeGreaterThan(0);
    expect(second[0]).toMatch(/^[a-z2-7]{26}\.[a-z2-7]{26}\/c0$/);
    expect(under(ids, n.dfg_defs, 'second').length).toBeGreaterThan(0);
  });

  it("an edit to one function leaves another function's node ids unchanged", async () => {
    const before = await both(A + B);
    const after = await both(A.replace('return q;', 'const r = q + "!";\n  console.log(r);\n  return r;') + B);
    const nb = assignNodeIds(before.ids, before.ir);
    const na = assignNodeIds(after.ids, after.ir);
    for (const key of ['calls', 'dfg_defs', 'dfg_uses', 'cfg_blocks'] as const) {
      const was = under(before.ids, nb[key], 'second');
      expect(under(after.ids, na[key], 'second'), key).toEqual(was);
    }
    // ...while the per-file numeric ids of the second function did move.
    const firstDefB = before.ir.dfg.defs.find(d => d.variable === 'y');
    const firstDefA = after.ir.dfg.defs.find(d => d.variable === 'y');
    expect(firstDefA?.id).not.toBe(firstDefB?.id);
    // The edited function's nodes are under a new body id.
    expect(under(after.ids, na.calls, 'first').length).toBeGreaterThan(under(before.ids, nb.calls, 'first').length);
  });

  it('accepts a partial IR and returns null outside every body', () => {
    const ids: StableIdFile = {
      scheme: 'ids@0.1', file: 'a.ts', language: 'typescript', module: 'a', partial: false,
      decls: [{
        id: 'x', body_id: 'x.h', body_hash: 'h', kind: 'function', name: 'f', qualified_name: 'a:f',
        signature: '()', parent: null, start_line: 2, end_line: 3, start_column: 4, end_column: 1,
        flags: [], token_count: 1,
      }],
    };
    const n = assignNodeIds(ids, {
      calls: [
        { method_name: 'g', receiver: null, arguments: [], location: { line: 2, column: 5 } },
        { method_name: 'g', receiver: null, arguments: [], location: { line: 2, column: 1 } },
        { method_name: 'g', receiver: null, arguments: [], location: { line: 3, column: 1 } },
      ],
      dfg: { defs: [{ id: 1, variable: 'v', line: 9, kind: 'local' }], uses: [] },
    });
    expect(n.calls).toEqual(['x.h/c0', null, null]);
    expect(n.dfg_defs).toEqual([null]);
    expect(n.cfg_blocks).toEqual([]);
  });
});
