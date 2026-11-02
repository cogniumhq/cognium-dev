/**
 * `facts@1` Arrow emission as a post-pass over `buildJavaGraph` (graph-store
 * plan T2, first half): off by default and invisible when off; on, two runs
 * give byte-identical IPC files whose row counts are the JSON view's counts.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { tableFromIPC, type Table } from 'apache-arrow';
import { buildJavaGraph, type JavaGraph } from '../../src/navigation/index.js';
import { FACTS_RELATION_NAMES, FACTS_RELATIONS, FACTS_SCHEME, type FactsArrow } from '../../src/facts/index.js';
import { javaGraphFacts, contentHash } from '../../src/facts/java-facts.js';
import { factsToArrow, relationToArrowIpc } from '../../src/facts/arrow.js';
import { idBytes, rowComparator } from '../../src/facts/order.js';
import { base32 } from '../../src/stable-ids/hash.js';
import { JAVA_APP } from '../graph-facts/java-fixture.js';

const files = (app: Record<string, string>) => Object.entries(app).map(([path, code]) => ({ path, code }));
const SERVICES = [{ path: 'src/main/resources/META-INF/services/app.plugins.Plugin', text: '# plugins\napp.plugins.Spi\n' }];

let plain: JavaGraph;
let withFacts: JavaGraph;
let again: JavaGraph;
let facts: FactsArrow;
let tables: Record<string, Table>;

beforeAll(async () => {
  plain = await buildJavaGraph(files(JAVA_APP), { serviceFiles: SERVICES });
  // Shuffled input order: file ids and row order must not depend on it.
  withFacts = await buildJavaGraph([...files(JAVA_APP)].reverse(), { serviceFiles: SERVICES, emitFacts: 'arrow', facts: { engine: 'circle-ir@test', parser: 'tree-sitter-java@test' } });
  again = await buildJavaGraph(files(JAVA_APP), { serviceFiles: SERVICES, emitFacts: 'arrow', facts: { engine: 'circle-ir@test', parser: 'tree-sitter-java@test' } });
  facts = withFacts.facts as FactsArrow;
  tables = Object.fromEntries(FACTS_RELATION_NAMES.map(n => [n, tableFromIPC(facts.relations[n])]));
}, 120_000);

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

  it('row counts equal the JSON view\'s counts', () => {
    expect(tables.files.numRows).toBe(plain.files.length);
    expect(tables.decl.numRows).toBe(plain.files.reduce((n, f) => n + f.decls.length, 0));
    expect(tables.call.numRows).toBe(plain.edges.length);
    expect(tables.unresolved.numRows).toBe(plain.unresolved.length);
    expect(tables.entries.numRows).toBe(plain.entries.length);
    const importLines = Object.values(JAVA_APP).reduce((n, code) => n + code.split('\n').filter(l => /^\s*import\s/.test(l)).length, 0);
    expect(tables.imports.numRows).toBe(importLines);
    expect(tables.flow.numRows).toBe(0);
    expect(tables.moved.numRows).toBe(0);
    for (const name of FACTS_RELATION_NAMES) {
      expect(facts.manifest.relations[name].rows, name).toBe(tables[name].numRows);
      expect(facts.manifest.relations[name].bytes, name).toBe(facts.relations[name].length);
      expect(facts.manifest.relations[name].batches, name).toBe(tables[name].numRows === 0 ? 0 : 1);
      expect(facts.manifest.relations[name].file).toBe(`${name}.arrow`);
    }
    expect(facts.manifest).toMatchObject({ facts: 'facts@1', ids: 'ids@0.1', source: 'java-graph@0.1', engine: 'circle-ir@test', chunk_rows: 65536 });
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

    const rows = javaGraphFacts(plain, files(JAVA_APP).map(f => ({ ...f, imports: [] })));
    const cmp = rowComparator(FACTS_RELATIONS.call);
    for (let i = 1; i < rows.call.length; i++) expect(cmp(rows.call[i - 1], rows.call[i])).toBeLessThanOrEqual(0);

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
    const unresolved = tables.unresolved.toArray().map(r => r.toJSON() as { reason: string; receiver: string | null });
    expect(unresolved.length).toBe(plain.unresolved.length);
    expect(unresolved.map(u => u.receiver ?? null).sort()).toEqual(plain.unresolved.map(u => u.receiver ?? null).sort());
    expect(new Set(unresolved.map(u => u.reason))).toEqual(new Set(plain.unresolved.map(u => u.reason)));
  });
});

describe('relationToArrowIpc', () => {
  it('chunks rows at 65536 and writes the whole vocabulary as the dictionary', async () => {
    const id = idBytes('a'.repeat(26));
    const rows = Array.from({ length: 65536 + 3 }, (_, i) => [id, id, 'def-use'] as const);
    const { bytes, batches } = await relationToArrowIpc('flow', rows.map(r => [...r]));
    expect(batches).toBe(2);
    const t = tableFromIPC(bytes);
    expect(t.numRows).toBe(65536 + 3);
    expect(t.batches.map(b => b.numRows)).toEqual([65536, 3]);
    const kind = t.getChild('kind');
    expect([...(kind?.data[0].dictionary?.toArray() ?? [])]).toEqual(['def-use', 'taint']);
    expect(kind?.get(0)).toBe('def-use');
  });

  it('refuses a cell that does not fit its column', async () => {
    const id = idBytes('a'.repeat(26));
    await expect(relationToArrowIpc('flow', [[id, id, 'nope']])).rejects.toThrow(/vocabulary/);
    await expect(relationToArrowIpc('flow', [[id, id]])).rejects.toThrow(/cells/);
    await expect(relationToArrowIpc('files', [[1, 'p', id, null]])).rejects.toThrow(/non-nullable/);
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
  });
});

