/**
 * `facts@1` columns: the fast columnar path (`canonicalTable`) gives exactly
 * what the row-form reference (`canonicalSet`) gives, and the three keys that
 * repeated on real data (T4, 2026-11-01) — `decl.id` across two
 * `package-info.java`, `imports` `X` vs `X.*`, `unresolved` at one site and
 * name — are unique on fixtures that reproduce each.
 */

import { describe, it, expect } from 'vitest';
import { tableFromIPC } from 'apache-arrow';
import { buildJavaGraph } from '../../src/navigation/index.js';
import { FACTS_RELATION_NAMES, FACTS_RELATIONS, type FactRow, type FactValue, type FactsRelation } from '../../src/facts/schema.js';
import { canonicalSet, compareCodePoints, idBytes } from '../../src/facts/order.js';
import { IdDecoder, canonicalTable, compareStrings, idBytesInto, keyCollisions, tableFromRows, tableRow, tableRows } from '../../src/facts/table.js';
import { javaGraphFactSet, type FactSet } from '../../src/facts/java-facts.js';
import { base32, digest128 } from '../../src/stable-ids/hash.js';
import { STABLE_ID_SCHEME } from '../../src/stable-ids/types.js';

const files = (app: Record<string, string>) => Object.entries(app).map(([path, code]) => ({ path, code }));
const inputs = (app: Record<string, string>) => files(app).map(f => ({ ...f, imports: [] }));
const cells = (r: FactRow) => r.map(v => (v instanceof Uint8Array ? base32(v) : v));

/** A deterministic sample of rows for a relation, with many ties on the leading key columns. */
function sample(rel: FactsRelation, n: number, seed: number): FactRow[] {
  const rnd = (m: number): number => {
    seed = (seed * 1103515245 + 12345) & 0x7fffffff;
    return seed % m;
  };
  const ids = Array.from({ length: 5 }, (_, i) => idBytes(digest128(['id', String(i)])));
  const strings = ['', 'a', 'b', 'é', '\u{1f600}', 'ab', '～'];
  const cell = (type: string, values?: readonly string[]): FactValue => {
    switch (type) {
      case 'fixed16': return ids[rnd(ids.length)];
      case 'u32': return rnd(3) === 0 ? rnd(2) : rnd(70000);
      case 'utf8': return strings[rnd(strings.length)];
      case 'bool': return rnd(2) === 1;
      case 'dict': return (values as readonly string[])[rnd(Math.min(3, (values as readonly string[]).length))];
      default: throw new Error(type);
    }
  };
  return Array.from({ length: n }, () => rel.columns.map(c => cell(c.type, c.values)));
}

describe('canonicalTable equals the row-form reference', () => {
  it('for a sample of every relation: same rows, same order, same dedupe count', () => {
    for (const name of FACTS_RELATION_NAMES) {
      const rel = FACTS_RELATIONS[name];
      const rows = sample(rel, 300, 7 + name.length);
      const reference = canonicalSet(rel, rows);
      const table = tableFromRows(rel, rows);
      expect(table.length).toBe(rows.length);
      const got = canonicalTable(rel, table.columns, table.length);
      expect(got.duplicatesDropped, name).toBe(reference.duplicatesDropped);
      expect(tableRows(rel, got.table).map(cells), name).toEqual(reference.rows.map(cells));
      // Idempotent, and the table's rows read back cell for cell.
      const again = canonicalTable(rel, got.table.columns, got.table.length);
      expect(again.duplicatesDropped).toBe(0);
      expect(tableRows(rel, again.table).map(cells)).toEqual(reference.rows.map(cells));
      expect(() => tableRow(rel, got.table, got.table.length)).toThrow(RangeError);
    }
  });

  it('with ids that share their leading bits (the packed-key fallback sorts the ties)', () => {
    const rel = FACTS_RELATIONS.flow;
    const base = idBytes(digest128(['x']));
    const rows: FactRow[] = [];
    for (let i = 0; i < 50; i++) {
      const id = new Uint8Array(base);
      id[15] = 49 - i; // differs only in the last byte: identical packed key
      rows.push([id, base, i % 2 ? 'taint' : 'def-use']);
    }
    const t = tableFromRows(rel, rows);
    const got = tableRows(rel, canonicalTable(rel, t.columns, t.length).table).map(cells);
    expect(got).toEqual(canonicalSet(rel, rows).rows.map(cells));
  });

  it('compareStrings is code-point order and idBytesInto / IdDecoder are idBytes', () => {
    const strings = ['', 'a', 'ab', 'b', 'é', '\u{1f600}', '～', '\u{1f600}a', 'a\u{1f600}', 'aé'];
    for (const a of strings) for (const b of strings) expect(Math.sign(compareStrings(a, b)), `${a} ${b}`).toBe(Math.sign(compareCodePoints(a, b)));
    const out = new Uint8Array(48);
    const decoder = new IdDecoder();
    for (const [i, parts] of [['a'], ['b'], ['a']].entries()) {
      const id = digest128(parts);
      idBytesInto(id, out, i * 16);
      expect(out.slice(i * 16, i * 16 + 16)).toEqual(idBytes(id));
      const viaCache = new Uint8Array(16);
      decoder.put(id, viaCache, 0);
      expect(viaCache).toEqual(idBytes(id));
    }
    expect(() => idBytesInto('a'.repeat(25) + 'z', out, 0)).toThrow(/ids@0.1/);
    expect(() => idBytesInto('A'.repeat(26), out, 0)).toThrow(/ids@0.1/);
    expect(() => tableFromRows(FACTS_RELATIONS.flow, [[out, out, 'taint']])).toThrow(/16 id bytes/);
    expect(() => canonicalTable(FACTS_RELATIONS.flow, [], 0)).toThrow(/columns/);
  });
});

describe('keys unique on real shapes (T4 findings)', () => {
  const UTIL = `package org.x;

public class Util {
  static int a() { return b(); }
  static int b() { return 1; }
}
`;

  it('decl: two package-info.java (and any same-named module) of one package in two bundles get distinct ids, the later one re-keyed with #2', async () => {
    const app = {
      'bundle0/src/org/x/package-info.java': '/** bundle0 */\npackage org.x;\n',
      'bundle1/src/org/x/package-info.java': '/** bundle1 */\npackage org.x;\n',
      'bundle0/src/org/x/Util.java': UTIL,
      'bundle1/src/org/x/Util.java': UTIL,
    };
    const graph = await buildJavaGraph(files(app));
    // The JSON view is untouched: both files still carry the ids@0.1 ids as derived.
    const moduleIds = graph.files.filter(f => f.file.endsWith('package-info.java')).map(f => f.decls[0].id);
    expect(moduleIds[0]).toBe(moduleIds[1]);
    const set: FactSet = javaGraphFactSet(graph, inputs(app));
    const decl = tableRows(FACTS_RELATIONS.decl, set.relations.decl) as [Uint8Array, string, string, string, number, number, Uint8Array][];
    expect(keyCollisions(FACTS_RELATIONS.decl, set.relations.decl)).toBe(0);
    expect(set.duplicatesDropped.decl).toBe(0);
    expect(new Set(decl.map(r => base32(r[0]))).size).toBe(decl.length);
    const paths = Object.keys(app).sort(compareCodePoints);
    const later = paths.indexOf('bundle1/src/org/x/package-info.java');
    const earlier = paths.indexOf('bundle0/src/org/x/package-info.java');
    const first = decl.find(r => r[4] === earlier && r[1] === 'module');
    const second = decl.find(r => r[4] === later && r[1] === 'module');
    expect(first?.[2]).toBe('org.x/package-info');
    expect(second?.[2]).toBe('org.x/package-info#2');
    // The stable-ids duplicate rule, applied over the snapshot: the id is derived from the suffixed name.
    expect(base32(second?.[0] as Uint8Array)).toBe(digest128([STABLE_ID_SCHEME, 'java', 'module', 'org.x/package-info#2', '']));
    expect(base32(first?.[0] as Uint8Array)).toBe(moduleIds[0]);
    // Callers inside the re-keyed file cite the re-keyed id, so every call row's caller is a decl row.
    const declIds = new Set(decl.map(r => base32(r[0])));
    const call = tableRows(FACTS_RELATIONS.call, set.relations.call) as [Uint8Array, Uint8Array, string, string, number, number, number][];
    expect(call.length).toBeGreaterThan(0);
    for (const r of call) expect(declIds.has(base32(r[0]))).toBe(true);
    const laterUtil = paths.indexOf('bundle1/src/org/x/Util.java');
    const rekeyedA = decl.find(r => r[4] === laterUtil && r[2] === 'org.x:Util.a#2');
    expect(rekeyedA).toBeDefined();
    expect(call.some(r => r[4] === laterUtil && base32(r[0]) === base32(rekeyedA?.[0] as Uint8Array))).toBe(true);
    expect(keyCollisions(FACTS_RELATIONS.call, set.relations.call)).toBe(0);
  });

  it('imports: one file importing both X and X.* writes two rows with distinct keys', async () => {
    const app = {
      'src/a/Main.java': 'package a;\n\nimport org.compiere.util.DisplayType;\nimport org.compiere.util.DisplayType.*;\nimport java.util.List;\n\npublic class Main { void m() { List.of(1); } }\n',
    };
    const graph = await buildJavaGraph(files(app), { emitFacts: 'arrow' });
    const t = tableFromIPC(graph.facts!.relations.imports);
    const rows = t.toArray().map(r => r.toJSON() as { file_id: number; target: string; wildcard: boolean });
    expect(rows).toEqual([
      { file_id: 0, target: 'java.util.List', wildcard: false },
      { file_id: 0, target: 'org.compiere.util.DisplayType', wildcard: false },
      { file_id: 0, target: 'org.compiere.util.DisplayType', wildcard: true },
    ]);
    expect(graph.facts!.manifest.relations.imports).toMatchObject({ rows: 3, duplicates_dropped: 0 });
    const rel = FACTS_RELATIONS.imports;
    const table = tableFromRows(rel, rows.map(r => [r.file_id, r.target, r.wildcard]));
    expect(keyCollisions(rel, table)).toBe(0);
    // Under the old key (file_id, target) the two DisplayType rows collided.
    expect(keyCollisions({ ...rel, key: ['file_id', 'target'] }, table)).toBe(1);
  });

  it('unresolved: rows at one site and name that differ only in receiver or reason stay distinct under the key', () => {
    const rel = FACTS_RELATIONS.unresolved;
    const caller = idBytes(digest128(['caller']));
    const rows: FactRow[] = [
      [caller, 'external', 'java.lang.StringBuilder', 'append', 3, 10, 4],
      [caller, 'external', 'java.lang.Appendable', 'append', 3, 10, 4],
      [caller, 'unknown', '', 'append', 3, 10, 4],
      [caller, 'external', '', 'append', 3, 10, 4],
      [caller, 'external', '', 'append', 3, 10, 4], // an exact duplicate: dropped
    ];
    const t = tableFromRows(rel, rows);
    const got = canonicalTable(rel, t.columns, t.length);
    expect(got.duplicatesDropped).toBe(1);
    expect(got.table.length).toBe(4);
    expect(keyCollisions(rel, got.table)).toBe(0);
    // The reconciliation's row-9 key (site + method_name) alone would see three collisions here.
    expect(keyCollisions({ ...rel, key: ['site_file', 'site_line', 'site_col', 'method_name'] }, got.table)).toBe(3);
    // Sentinel, not null: the unknown receiver is the empty string and sorts first (receiver precedes reason in the key).
    const sorted = tableRows(rel, got.table).map(cells);
    expect(sorted.map(r => `${String(r[1])}|${String(r[2])}`)).toEqual(['external|', 'unknown|', 'external|java.lang.Appendable', 'external|java.lang.StringBuilder']);
  });
});
