/**
 * Node ids are re-scoped to the body: an edit to one function shifts every
 * per-file IR id after it, but leaves another function's node ids unchanged.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';
import { assignNodeIds, deriveStableIds, locateNodes, nodeIdBytes, nodeIdBytesOfPrinted, printedNodeId, NodeIdWriter, digest128Bytes, base32, type StableIdFile } from '../../src/stable-ids/index.js';
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

describe('fixed-width node ids (stable-ids decision 1a)', () => {
  const body = 'a'.repeat(26) + '.' + 'b'.repeat(26);

  it('are digest128 over ids@0.1 · node · body_id · kind · ordinal, 16 bytes, a function of the printed id', () => {
    const bytes = nodeIdBytes(body, 'use', 7);
    expect(bytes.length).toBe(16);
    expect(bytes).toEqual(digest128Bytes(['ids@0.1', 'node', body, 'use', '7']));
    expect(printedNodeId(body, 'use', 7)).toBe(`${body}/u7`);
    expect(nodeIdBytesOfPrinted(`${body}/u7`)).toEqual(bytes);
    expect(nodeIdBytesOfPrinted(`${body}/d0`)).toEqual(nodeIdBytes(body, 'def', 0));
    expect(nodeIdBytesOfPrinted(`${body}/b12`)).toEqual(nodeIdBytes(body, 'block', 12));
    expect(nodeIdBytesOfPrinted(`${body}/c3`)).toEqual(nodeIdBytes(body, 'call', 3));
    // Distinct in every part.
    const all = [nodeIdBytes(body, 'def', 7), nodeIdBytes(body, 'use', 8), nodeIdBytes(body.replace('a', 'c'), 'use', 7), bytes].map(b => base32(b));
    expect(new Set(all).size).toBe(4);
    for (const bad of ['x', `${body}/z1`, `${body}/u`, `${body}/u01`, `${body}/u-1`, `${body}/u1.5`]) {
      expect(() => nodeIdBytesOfPrinted(bad)).toThrow(/printed node id/);
    }
  });

  it('NodeIdWriter writes the same bytes as nodeIdBytes for every ordinal shape', () => {
    const w = new NodeIdWriter();
    const out = new Uint8Array(16 * 6);
    const ordinals = [0, 1, 9, 10, 1234, 2 ** 31 - 1];
    w.forBody(body, 'def');
    ordinals.forEach((n, i) => w.write(n, out, i * 16));
    ordinals.forEach((n, i) => expect(out.subarray(i * 16, i * 16 + 16), String(n)).toEqual(nodeIdBytes(body, 'def', n)));
    // Switching body and kind re-encodes the prefix.
    const other = 'c'.repeat(26) + '.' + 'd'.repeat(26);
    w.forBody(other, 'use');
    w.write(5, out, 0);
    expect(out.subarray(0, 16)).toEqual(nodeIdBytes(other, 'use', 5));
    w.forBody(body, 'def');
    w.write(5, out, 0);
    expect(out.subarray(0, 16)).toEqual(nodeIdBytes(body, 'def', 5));
    expect(() => w.forBody('x'.repeat(300), 'def')).toThrow(RangeError);
  });

  it('locateNodes gives the body and per-body ordinal that assignNodeIds prints', async () => {
    const { ir, ids } = await both(A + B);
    const n = assignNodeIds(ids, ir);
    const located = locateNodes(ids, ir.dfg.uses, (u, at) => at(u.line, u.column));
    expect(located.length).toBe(ir.dfg.uses.length);
    located.forEach((l, i) => {
      expect(l).not.toBeNull();
      expect(printedNodeId((l as NonNullable<typeof l>).decl.body_id, 'use', (l as NonNullable<typeof l>).ordinal)).toBe(n.dfg_uses[i]);
    });
  });
});
