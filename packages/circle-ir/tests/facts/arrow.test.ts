/**
 * `facts@1` Arrow emission as a post-pass over `buildJavaGraph` (graph-store
 * plan T2, first half): off by default and invisible when off; on, two runs
 * give byte-identical IPC files whose row counts are the JSON view's counts
 * less the exact duplicates a set collapses (reported in the manifest).
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { tableFromIPC, type Table } from 'apache-arrow';
import { analyze } from '../../src/analyzer.js';
import { buildJavaGraph, type JavaGraph } from '../../src/navigation/index.js';
import { assignNodeIds, nodeIdBytesOfPrinted } from '../../src/stable-ids/index.js';
import type { CircleIR } from '../../src/types/index.js';
import { FACTS_RELATION_NAMES, FACTS_RELATIONS, FACTS_SCHEME, type FactsArrow } from '../../src/facts/index.js';
import { javaGraphFactSet, contentHash } from '../../src/facts/java-facts.js';
import { factsToArrow, relationToArrowIpc } from '../../src/facts/arrow.js';
import { idBytes, rowComparator } from '../../src/facts/order.js';
import { keyCollisions, tableRows } from '../../src/facts/table.js';
import { base32 } from '../../src/stable-ids/hash.js';
import { JAVA_APP } from '../graph-facts/java-fixture.js';

const files = (app: Record<string, string>) => Object.entries(app).map(([path, code]) => ({ path, code }));
const SERVICES = [{ path: 'src/main/resources/META-INF/services/app.plugins.Plugin', text: '# plugins\napp.plugins.Spi\n' }];

let plain: JavaGraph;
let withFacts: JavaGraph;
let again: JavaGraph;
let facts: FactsArrow;
let tables: Record<string, Table>;
let irs: Record<string, CircleIR>;

beforeAll(async () => {
  plain = await buildJavaGraph(files(JAVA_APP), { serviceFiles: SERVICES });
  // Shuffled input order: file ids and row order must not depend on it.
  withFacts = await buildJavaGraph([...files(JAVA_APP)].reverse(), { serviceFiles: SERVICES, emitFacts: 'arrow', factsScheme: 'facts@1', facts: { engine: 'circle-ir@test', parser: 'tree-sitter-java@test' } });
  again = await buildJavaGraph(files(JAVA_APP), { serviceFiles: SERVICES, emitFacts: 'arrow', factsScheme: 'facts@1', facts: { engine: 'circle-ir@test', parser: 'tree-sitter-java@test' } });
  facts = withFacts.facts as FactsArrow;
  tables = Object.fromEntries(FACTS_RELATION_NAMES.map(n => [n, tableFromIPC(facts.relations[n])]));
  irs = Object.fromEntries(await Promise.all(Object.entries(JAVA_APP).map(async ([path, code]) => [path, await analyze(code, path, 'java', { navigationTypes: true })] as const)));
}, 120_000);

/** The post-pass inputs a test builds by hand: imports empty, the DFG from `analyze`. */
const inputs = (app: Record<string, string>) => files(app).map(f => ({ ...f, imports: [], dfg: irs[f.path].dfg }));

/** The `flow` rows a file's DFG yields: one def-use edge per use with a reaching definition the file holds. */
function expectedFlow(path: string): string[] {
  const ir = irs[path];
  const ids = plain.files.find(f => f.file === path);
  if (!ids) throw new Error(path);
  const n = assignNodeIds(ids, ir);
  const defNode = new Map(ir.dfg.defs.map((d, i) => [d.id, n.dfg_defs[i]] as const));
  const out: string[] = [];
  ir.dfg.uses.forEach((u, i) => {
    const from = u.def_id === null ? undefined : defNode.get(u.def_id);
    const to = n.dfg_uses[i];
    if (from && to) out.push(`${base32(nodeIdBytesOfPrinted(from))} ${base32(nodeIdBytesOfPrinted(to))} def-use`);
  });
  return out;
}

describe('off by default', () => {
  it('leaves the graph exactly as it was: no facts key, same JSON', () => {
    expect('facts' in plain).toBe(false);
    const { facts: _f, ...rest } = withFacts;
    expect(JSON.stringify(rest)).toBe(JSON.stringify(plain));
  });
});

describe('facts@1 Arrow emission', () => {
  it('emits the eight relations with the facts@1 schema and metadata', () => {
    expect(facts.scheme).toBe(FACTS_SCHEME);
    expect(Object.keys(facts.relations).sort()).toEqual([...FACTS_RELATION_NAMES].sort());
    for (const name of FACTS_RELATION_NAMES) {
      const t = tables[name];
      expect(t.schema.fields.map(f => f.name), name).toEqual(FACTS_RELATIONS[name].columns.map(c => c.name));
      expect(t.schema.fields.map(f => f.nullable), name).toEqual(FACTS_RELATIONS[name].columns.map(c => c.nullable));
      expect(Object.fromEntries(t.schema.metadata), name).toEqual({ facts: 'facts@1', ids: 'ids@0.1', engine: 'circle-ir@test', parser: 'tree-sitter-java@test' });
      expect(t.schema.fields.every(f => !f.nullable), name).toBe(true);
      for (const f of t.schema.fields) expect(t.getChild(f.name)?.nullCount, `${name}.${f.name}`).toBe(0);
      for (const [i, c] of FACTS_RELATIONS[name].columns.entries()) {
        const type = String(t.schema.fields[i].type);
        const want = { fixed16: 'FixedSizeBinary[16]', u32: 'Uint32', utf8: 'Utf8', bool: 'Bool', dict: 'Dictionary<Int8, Utf8>' }[c.type];
        expect(type, `${name}.${c.name}`).toBe(want);
      }
    }
  });

  it('two runs give byte-identical IPC files and manifests, whatever the input order', () => {
    const second = again.facts as FactsArrow;
    for (const name of FACTS_RELATION_NAMES) {
      expect(Buffer.compare(Buffer.from(facts.relations[name]), Buffer.from(second.relations[name])), name).toBe(0);
    }
    expect(JSON.stringify(second.manifest)).toBe(JSON.stringify(facts.manifest));
  });

  it('row counts equal the JSON view\'s counts less the duplicates a set collapses', () => {
    const m = facts.manifest.relations;
    const rows = (name: (typeof FACTS_RELATION_NAMES)[number]) => tables[name].numRows + m[name].duplicates_dropped;
    expect(rows('files')).toBe(plain.files.length);
    expect(rows('decl')).toBe(plain.files.reduce((n, f) => n + f.decls.length, 0));
    expect(rows('call')).toBe(plain.edges.length);
    expect(rows('unresolved')).toBe(plain.unresolved.length);
    expect(rows('entries')).toBe(plain.entries.length);
    const importLines = Object.values(JAVA_APP).reduce((n, code) => n + code.split('\n').filter(l => /^\s*import\s/.test(l)).length, 0);
    expect(rows('imports')).toBe(importLines);
    const uses = Object.values(irs).reduce((n, ir) => n + ir.dfg.uses.filter(u => u.def_id !== null).length, 0);
    expect(uses).toBeGreaterThan(0);
    expect(rows('flow')).toBe(uses);
    expect(tables.moved.numRows).toBe(0);
    for (const name of FACTS_RELATION_NAMES) {
      expect(m[name].rows, name).toBe(tables[name].numRows);
      expect(m[name].bytes, name).toBe(facts.relations[name].length);
      expect(m[name].batches, name).toBe(tables[name].numRows === 0 ? 0 : 1);
      expect(m[name].file).toBe(`${name}.arrow`);
      expect(m[name].blake3, name).toMatch(/^[0-9a-f]{64}$/);
      expect(m[name].duplicates_dropped, name).toBeGreaterThanOrEqual(0);
      expect(Object.keys(m[name])).toEqual(['file', 'rows', 'batches', 'bytes', 'blake3', 'duplicates_dropped']);
    }
    expect(facts.manifest).toMatchObject({ facts: 'facts@1', ids: 'ids@0.1', source: 'java-graph@0.1', engine: 'circle-ir@test', chunk_rows: 65536 });
  });

  it('every relation is a set with unique keys, in strictly increasing canonical order', () => {
    const set = javaGraphFactSet(plain, inputs(JAVA_APP));
    for (const name of FACTS_RELATION_NAMES) {
      expect(set.relations[name].length + set.duplicatesDropped[name], name).toBeGreaterThan(name === 'moved' || name === 'imports' ? -1 : 0);
      const rel = FACTS_RELATIONS[name];
      const rows = tableRows(rel, set.relations[name]);
      const cmp = rowComparator(rel);
      for (let i = 1; i < rows.length; i++) expect(cmp(rows[i - 1], rows[i]), name).toBeLessThan(0);
      expect(keyCollisions(rel, set.relations[name]), name).toBe(0);
    }
  });

  it('rows are in canonical order and carry the ids@0.1 ids and the graph\'s values', () => {
    const paths = Object.keys(JAVA_APP).sort();
    const fileRows = tables.files.toArray().map(r => r.toJSON() as { file_id: number; path: string; content_hash: Uint8Array; language: string });
    expect(fileRows.map(r => r.path)).toEqual(paths);
    expect(fileRows.map(r => r.file_id)).toEqual(paths.map((_, i) => i));
    expect(fileRows.every(r => r.language === 'java')).toBe(true);
    expect(base32(fileRows[0].content_hash)).toBe(base32(contentHash(JAVA_APP[paths[0]])));

    const declIds = tables.decl.getChild('id')?.toArray() as Uint8Array[];
    const sorted = [...declIds].map(b => base32(b));
    expect(new Set(sorted)).toEqual(new Set(plain.files.flatMap(f => f.decls.map(d => d.id))));
    for (let i = 1; i < declIds.length; i++) expect(Buffer.compare(Buffer.from(declIds[i - 1]), Buffer.from(declIds[i]))).toBeLessThanOrEqual(0);

    const rows = tableRows(FACTS_RELATIONS.call, javaGraphFactSet(plain, files(JAVA_APP).map(f => ({ ...f, imports: [] }))).relations.call);
    const cmp = rowComparator(FACTS_RELATIONS.call);
    for (let i = 1; i < rows.length; i++) expect(cmp(rows[i - 1], rows[i])).toBeLessThan(0);

    const calls = tables.call.toArray().map(r => r.toJSON() as { caller_id: Uint8Array; callee_id: Uint8Array; tier: string; method_name: string; site_file: number; site_line: number; site_col: number });
    const q = new Map(plain.files.flatMap(f => f.decls.map(d => [d.id, d.qualified_name] as const)));
    expect(calls.map(c => `${q.get(base32(c.caller_id))} -> ${q.get(base32(c.callee_id))} [${c.tier}]`)).toEqual(
      expect.arrayContaining(['app.web:UserController.get -> app.core:UserService.find [exact]', 'app.core:UserService.find -> app.core:MemStore.load [polymorphic]']),
    );
    const edge = plain.edges[0];
    const row = calls.find(c => base32(c.caller_id) === edge.from && base32(c.callee_id) === edge.to && c.site_line === edge.site.line && c.site_col === edge.site.col);
    expect(row?.site_file).toBe(paths.indexOf(edge.site.file));
    expect(row?.method_name).toBe(edge.methodName);

    const imports = tables.imports.toArray().map(r => r.toJSON() as { file_id: number; target: string; wildcard: boolean });
    expect(imports).toContainEqual({ file_id: paths.indexOf('src/main/java/app/web/UserController.java'), target: 'app.core.UserService', wildcard: false });
    const entries = tables.entries.toArray().map(r => r.toJSON() as { decl_id: Uint8Array; kind: string; source: string; certainty: string });
    expect(entries.map(e => `${e.kind} ${e.certainty} ${q.get(base32(e.decl_id))} ${e.source}`)).toContain('main declared app:Main.main public static void main(String[])');
    const unresolved = tables.unresolved.toArray().map(r => r.toJSON() as { reason: string; receiver: string });
    expect(unresolved.length + facts.manifest.relations.unresolved.duplicates_dropped).toBe(plain.unresolved.length);
    // No nulls: an unknown receiver is the empty string.
    expect(new Set(unresolved.map(u => u.receiver))).toEqual(new Set(plain.unresolved.map(u => u.receiver ?? '')));
    expect(new Set(unresolved.map(u => u.reason))).toEqual(new Set(plain.unresolved.map(u => u.reason)));
    const bodyHashes = tables.decl.getChild('body_hash')?.toArray() as Uint8Array[];
    expect(bodyHashes.every(b => b.length === 16 && b.some(x => x !== 0))).toBe(true); // Java always derives one
    const entryKinds = new Set(tables.entries.getChild('kind')?.toArray() as string[]);
    expect(entryKinds.has('bean')).toBe(false);
  });

  it('flow: one def-use row per DFG use with a reaching def, on the fixed-width node ids of the printed ids@0.1 node ids', () => {
    const want = Object.keys(JAVA_APP).flatMap(expectedFlow).sort();
    const got = tables.flow.toArray().map(r => { const j = r.toJSON() as { from_id: Uint8Array; to_id: Uint8Array; kind: string }; return `${base32(j.from_id)} ${base32(j.to_id)} ${j.kind}`; });
    expect(got.length + facts.manifest.relations.flow.duplicates_dropped).toBe(want.length);
    expect(new Set(got)).toEqual(new Set(want));
    expect(got.length).toBe(new Set(got).size);
    const fromIds = tables.flow.getChild('from_id')?.toArray() as Uint8Array[];
    for (let i = 1; i < fromIds.length; i++) expect(Buffer.compare(Buffer.from(fromIds[i - 1]), Buffer.from(fromIds[i]))).toBeLessThanOrEqual(0);
    expect(keyCollisions(FACTS_RELATIONS.flow, javaGraphFactSet(plain, inputs(JAVA_APP)).relations.flow)).toBe(0);
    // Without a DFG a file contributes no flow row, and nothing else changes.
    const without = javaGraphFactSet(plain, files(JAVA_APP).map(f => ({ ...f, imports: [] })));
    expect(without.relations.flow.length).toBe(0);
    const withDfg = javaGraphFactSet(plain, inputs(JAVA_APP));
    for (const name of FACTS_RELATION_NAMES) if (name !== 'flow') expect(tableRows(FACTS_RELATIONS[name], without.relations[name]), name).toEqual(tableRows(FACTS_RELATIONS[name], withDfg.relations[name]));
  });

  it('flow: an edit to one method leaves every other method\'s rows unchanged', async () => {
    const path = 'src/main/java/app/core/UserService.java';
    const before = JAVA_APP[path];
    expect(before).toContain('store.load(id)');
    const after = before.replace('store.load(id)', 'store.load(id == null ? "anonymous" : id.trim())');
    const edited = { ...JAVA_APP, [path]: after };
    const graph = await buildJavaGraph(files(edited));
    const editedIrs = { ...irs, [path]: await analyze(after, path, 'java', { navigationTypes: true }) };
    const findBody = (g: JavaGraph): string => {
      const d = g.files.find(f => f.file === path)?.decls.find(x => x.name === 'find');
      if (!d) throw new Error('find');
      return d.body_id;
    };
    expect(findBody(graph)).not.toBe(findBody(plain));
    /** The emitted flow rows, each tagged with whether it touches the edited method's body. */
    const rowsOf = (g: JavaGraph, app: Record<string, string>, i: Record<string, CircleIR>, body: string): { all: string[]; outside: string[] } => {
      const set = javaGraphFactSet(g, files(app).map(f => ({ ...f, imports: [], dfg: i[f.path].dfg })));
      const all = tableRows(FACTS_RELATIONS.flow, set.relations.flow).map(r => `${base32(r[0] as Uint8Array)} ${base32(r[1] as Uint8Array)}`);
      // Rows under the method's body, from the printed node ids of its file.
      const inBody = new Set<string>();
      const ir = i[path];
      const n = assignNodeIds(g.files.find(f => f.file === path) as JavaGraph['files'][number], ir);
      const defNode = new Map(ir.dfg.defs.map((d, k) => [d.id, n.dfg_defs[k]] as const));
      ir.dfg.uses.forEach((u, k) => {
        const from = u.def_id === null ? undefined : defNode.get(u.def_id);
        const to = n.dfg_uses[k];
        if (from && to && (from.startsWith(body + '/') || to.startsWith(body + '/'))) inBody.add(`${base32(nodeIdBytesOfPrinted(from))} ${base32(nodeIdBytesOfPrinted(to))}`);
      });
      expect(inBody.size).toBeGreaterThan(0);
      return { all, outside: all.filter(r => !inBody.has(r)) };
    };
    const was = rowsOf(plain, JAVA_APP, irs, findBody(plain));
    const now = rowsOf(graph, edited, editedIrs, findBody(graph));
    expect(now.all).not.toEqual(was.all);
    expect(now.outside).toEqual(was.outside);
    expect(was.outside.length).toBeGreaterThan(0);
  });
});

describe('relationToArrowIpc', () => {
  it('chunks rows at 65536 and writes the whole vocabulary as the dictionary', async () => {
    const id = idBytes('a'.repeat(26));
    // Distinct rows (a set): the id's last two bytes count up.
    const rows = Array.from({ length: 65536 + 3 }, (_, i) => { const to = new Uint8Array(id); to[13] = i >> 16; to[14] = (i >> 8) & 0xff; to[15] = i & 0xff; return [id, to, 'def-use']; });
    const { bytes, batches, rows: kept, duplicatesDropped } = await relationToArrowIpc('flow', rows);
    expect(batches).toBe(2);
    expect(kept).toBe(65536 + 3);
    expect(duplicatesDropped).toBe(0);
    const t = tableFromIPC(bytes);
    expect(t.numRows).toBe(65536 + 3);
    expect(t.batches.map(b => b.numRows)).toEqual([65536, 3]);
    const kind = t.getChild('kind');
    expect([...(kind?.data[0].dictionary?.toArray() ?? [])]).toEqual(['def-use', 'taint']);
    expect(kind?.get(0)).toBe('def-use');
  });

  it('rows in the row form are made canonical: sorted and deduplicated, duplicates counted', async () => {
    const a = idBytes('a'.repeat(26));
    const b = new Uint8Array(16);
    b[0] = 1;
    const { bytes, rows, duplicatesDropped } = await relationToArrowIpc('flow', [[b, a, 'taint'], [a, b, 'def-use'], [b, a, 'taint'], [a, b, 'def-use']]);
    expect(rows).toBe(2);
    expect(duplicatesDropped).toBe(2);
    const t = tableFromIPC(bytes);
    expect(t.toArray().map(r => { const j = r.toJSON() as { from_id: Uint8Array; kind: string }; return `${j.from_id[0]} ${j.kind}`; })).toEqual(['0 def-use', '1 taint']);
    const out = await factsToArrow({ files: [], decl: [], call: [], unresolved: [], flow: [[a, b, 'taint'], [a, b, 'taint']], imports: [], entries: [], moved: [] });
    expect(out.manifest.relations.flow).toMatchObject({ rows: 1, duplicates_dropped: 1 });
  });

  it('refuses a cell that does not fit its column, nulls included', async () => {
    const id = idBytes('a'.repeat(26));
    await expect(relationToArrowIpc('flow', [[id, id, 'nope']])).rejects.toThrow(/vocabulary/);
    await expect(relationToArrowIpc('flow', [[id, id]])).rejects.toThrow(/cells/);
    await expect(relationToArrowIpc('files', [[1, 'p', id, null]])).rejects.toThrow(/non-nullable/);
    await expect(relationToArrowIpc('unresolved', [[id, 'external', null, 'm', 1, 2, 3]])).rejects.toThrow(/non-nullable/);
    await expect(relationToArrowIpc('files', [[-1, 'p', id, 'java']])).rejects.toThrow(/unsigned 32-bit/);
    await expect(relationToArrowIpc('files', [[1, 7, id, 'java']])).rejects.toThrow(/string/);
    await expect(relationToArrowIpc('files', [[1, 'p', new Uint8Array(3), 'java']])).rejects.toThrow(/16 id bytes/);
    await expect(relationToArrowIpc('imports', [[1, 'p', 'yes']])).rejects.toThrow(/boolean/);
  });

  it('writes an empty relation as a schema with no record batch', async () => {
    const out = await factsToArrow({ files: [], decl: [], call: [], unresolved: [], flow: [], imports: [], entries: [], moved: [] });
    for (const name of FACTS_RELATION_NAMES) {
      const t = tableFromIPC(out.relations[name]);
      expect(t.numRows).toBe(0);
      expect(out.manifest.relations[name].batches).toBe(0);
      expect(t.schema.fields.map(f => f.name)).toEqual(FACTS_RELATIONS[name].columns.map(c => c.name));
    }
    expect(Object.keys(out.manifest)).toEqual(['facts', 'ids', 'chunk_rows', 'relations']);
    for (const name of FACTS_RELATION_NAMES) expect(out.manifest.relations[name].duplicates_dropped).toBe(0);
  });
});

