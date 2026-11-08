/**
 * `facts@2` emission: opt-in behind `factsScheme` with `facts@1` the default;
 * two runs give byte-identical IPC files; the file-key vector lands in the
 * bytes; one Java file and one TypeScript file go from source through the
 * graph, the post-pass and Arrow, and read back as the graph says; a line
 * shift or an added file moves no row a rule reads.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { tableFromIPC } from 'apache-arrow';
import { analyze } from '../../src/analyzer.js';
import { buildJavaGraph, buildTsCallGraph, type JavaGraph, type TsCallGraph } from '../../src/navigation/index.js';
import { FACTS_RELATIONS, type FactsArrow } from '../../src/facts/index.js';
import { FACTS2_RELATION_NAMES, FACTS2_RELATIONS, fileKey, type Facts2RelationName } from '../../src/facts/schema2.js';
import { javaGraphFact2Set, tsGraphFact2Set, type Fact2Set, type Facts2Input } from '../../src/facts/facts2.js';
import { facts2ToArrow, relation2ToArrowIpc, type Facts2Arrow } from '../../src/facts/arrow.js';
import { contentHash, javaGraphFactSet } from '../../src/facts/java-facts.js';
import { compareCodePoints, idBytes, rowComparator } from '../../src/facts/order.js';
import { keyCollisions, tableRows } from '../../src/facts/table.js';
import { base32, digest128 } from '../../src/stable-ids/hash.js';
import { STABLE_ID_SCHEME } from '../../src/stable-ids/types.js';
import type { CircleIR } from '../../src/types/index.js';
import { JAVA_APP } from '../graph-facts/java-fixture.js';

type Row = Record<string, unknown>;

const files = (app: Record<string, string>) => Object.entries(app).map(([path, code]) => ({ path, code }));
const SERVICES = [{ path: 'src/main/resources/META-INF/services/app.plugins.Plugin', text: '# plugins\napp.plugins.Spi\n' }];
const OPTS = { emitFacts: 'arrow' as const, factsScheme: 'facts@2' as const, facts: { engine: 'circle-ir@test', parser: 'tree-sitter-java@test' } };
const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');
const ZERO = '0'.repeat(32);

/** Every row of one relation's IPC bytes, as plain objects. */
function rowsOf(facts: Facts2Arrow, name: Facts2RelationName): Row[] {
  return tableFromIPC(facts.relations[name]).toArray().map(r => r.toJSON() as Row);
}

/** A relation's rows as strings (ids in base32), for set comparisons. */
function rowStrings(set: Fact2Set, name: Facts2RelationName): string[] {
  return tableRows(FACTS2_RELATIONS[name], set.relations[name]).map(r => r.map(v => (v instanceof Uint8Array ? base32(v) : String(v))).join(' '));
}

// ---------------------------------------------------------------------------
// One Java file, at the path of the schema's file-key test vector.

const APP_PATH = 'src/main/java/org/example/App.java';
const APP_KEY_HEX = 'd26d79b82b9a2df38e9b9ccd3946a3e8';
const APP_JAVA = `package org.example;

import java.util.List;
import java.util.function.Supplier;

public class App {
  interface Shape { int area(); }

  static class Square implements Shape {
    Square() {}
    public int area() { return 4; }
  }

  static class Circle implements Shape {
    public int area() { return 3; }
  }

  private static final int SEED = seed();

  static int seed() { return 7; }

  static {
    seed();
  }

  int total(List<Shape> shapes) {
    int n = 0;
    for (Shape s : shapes) {
      n += s.area();
    }
    return n;
  }

  Supplier<Integer> lazy() {
    return this::seedValue;
  }

  int seedValue() { return SEED; }

  Object load(String name) throws Exception {
    return Class.forName(name);
  }

  void log(String msg) {
    System.out.println(msg);
  }

  public static void main(String[] args) {
    Runnable r = () -> new App().log("hi");
    r.run();
  }
}
`;

// One TypeScript file.
const TS_PATH = 'src/shapes.ts';
const TS_CODE = [
  "import express from 'express';",
  'interface Shape { area(): number; }',
  'export class Square implements Shape {',
  '  constructor() {}',
  '  area() { return 4; }',
  '}',
  'export class Circle extends Square {',
  '  area() { return 3; }',
  '}',
  'export const handlers = { measure };',
  'export function measure(s: Square) {',
  '  return s.area();',
  '}',
  'export function later(cb: () => void) { setTimeout(cb, 1); }',
  'later(() => measure(new Square()));',
  'const app = express();',
  "app.get('/x', pick('h'));",
  'function pick(n: string) { return (req: any, res: any) => res.send(n); }',
].join('\n');

let appPlain: JavaGraph;
let appGraph: JavaGraph;
let appFacts: Facts2Arrow;
let fixturePlain: JavaGraph;
let fixtureFacts: Facts2Arrow;
let fixtureAgain: Facts2Arrow;
let fixtureV1: FactsArrow;
let fixtureIrs: Record<string, CircleIR>;
let tsGraph: TsCallGraph;
let tsFacts: Facts2Arrow;

beforeAll(async () => {
  appPlain = await buildJavaGraph([{ path: APP_PATH, code: APP_JAVA }]);
  appGraph = await buildJavaGraph([{ path: APP_PATH, code: APP_JAVA }], OPTS);
  appFacts = appGraph.facts as Facts2Arrow;
  fixturePlain = await buildJavaGraph(files(JAVA_APP), { serviceFiles: SERVICES });
  // Shuffled input order: nothing in the bytes may depend on it.
  fixtureFacts = (await buildJavaGraph([...files(JAVA_APP)].reverse(), { serviceFiles: SERVICES, ...OPTS })).facts as Facts2Arrow;
  fixtureAgain = (await buildJavaGraph(files(JAVA_APP), { serviceFiles: SERVICES, ...OPTS })).facts as Facts2Arrow;
  fixtureV1 = (await buildJavaGraph(files(JAVA_APP), { serviceFiles: SERVICES, emitFacts: 'arrow', facts: OPTS.facts })).facts as FactsArrow;
  fixtureIrs = Object.fromEntries(await Promise.all(Object.entries(JAVA_APP).map(async ([path, code]) => [path, await analyze(code, path, 'java', { navigationTypes: true })] as const)));
  tsGraph = await buildTsCallGraph([{ path: TS_PATH, code: TS_CODE }]);
  tsFacts = await facts2ToArrow(tsGraphFact2Set(tsGraph, [{ path: TS_PATH, code: TS_CODE, imports: [] }]), { source: 'ts-call-edges@0.1', engine: 'circle-ir@test' });
}, 180_000);

describe('opt-in: facts@1 stays the default', () => {
  it('emitFacts alone still writes facts@1, byte for byte the same as before', async () => {
    expect(fixtureV1.scheme).toBe('facts@1');
    expect(fixtureV1.manifest.facts).toBe('facts@1');
    expect(Object.keys(fixtureV1.relations)).toHaveLength(8);
    const explicit = (await buildJavaGraph(files(JAVA_APP), { serviceFiles: SERVICES, emitFacts: 'arrow', factsScheme: 'facts@1', facts: OPTS.facts })).facts as FactsArrow;
    for (const name of Object.keys(fixtureV1.relations) as (keyof FactsArrow['relations'])[]) {
      expect(hex(explicit.relations[name]), name).toBe(hex(fixtureV1.relations[name]));
    }
  });

  it('factsScheme facts@2 writes the twelve relations; without emitFacts nothing is written; the graph JSON is unchanged', async () => {
    expect(appFacts.scheme).toBe('facts@2');
    expect(Object.keys(appFacts.relations)).toEqual([...FACTS2_RELATION_NAMES]);
    const quiet = await buildJavaGraph([{ path: APP_PATH, code: APP_JAVA }], { factsScheme: 'facts@2' });
    expect('facts' in quiet).toBe(false);
    const { facts: _f, ...rest } = appGraph;
    expect(JSON.stringify(rest)).toBe(JSON.stringify(appPlain));
    expect(JSON.stringify(quiet)).toBe(JSON.stringify(appPlain));
  });

  it('refuses an unknown scheme', async () => {
    await expect(buildJavaGraph([{ path: APP_PATH, code: APP_JAVA }], { emitFacts: 'arrow', factsScheme: 'facts@3' as 'facts@2' })).rejects.toThrow(/facts@3/);
  });
});

describe('facts@2 Arrow emission', () => {
  it('writes every relation with the facts@2 columns, types and metadata', () => {
    for (const name of FACTS2_RELATION_NAMES) {
      const t = tableFromIPC(fixtureFacts.relations[name]);
      const rel = FACTS2_RELATIONS[name];
      expect(t.schema.fields.map(f => f.name), name).toEqual(rel.columns.map(c => c.name));
      expect(t.schema.fields.every(f => !f.nullable), name).toBe(true);
      expect(Object.fromEntries(t.schema.metadata), name).toEqual({ facts: 'facts@2', ids: 'ids@0.1', engine: 'circle-ir@test', parser: 'tree-sitter-java@test' });
      for (const [i, c] of rel.columns.entries()) {
        const want = { fixed16: 'FixedSizeBinary[16]', u32: 'Uint32', utf8: 'Utf8', bool: 'Bool', dict: 'Dictionary<Int8, Utf8>' }[c.type];
        expect(String(t.schema.fields[i].type), `${name}.${c.name}`).toBe(want);
      }
      for (const f of t.schema.fields) expect(t.getChild(f.name)?.nullCount, `${name}.${f.name}`).toBe(0);
    }
    const m = fixtureFacts.manifest;
    expect(Object.keys(m)).toEqual(['facts', 'ids', 'source', 'engine', 'parser', 'chunk_rows', 'relations']);
    expect(m).toMatchObject({ facts: 'facts@2', ids: 'ids@0.1', source: 'java-graph@0.1', chunk_rows: 65536 });
    expect(Object.keys(m.relations)).toEqual([...FACTS2_RELATION_NAMES]);
    for (const name of FACTS2_RELATION_NAMES) {
      expect(m.relations[name].file).toBe(`${name}.arrow`);
      expect(m.relations[name].bytes).toBe(fixtureFacts.relations[name].length);
      expect(m.relations[name].blake3).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it('two runs give byte-identical IPC files and manifests, whatever the input order', () => {
    for (const name of FACTS2_RELATION_NAMES) {
      expect(hex(fixtureAgain.relations[name]), name).toBe(hex(fixtureFacts.relations[name]));
    }
    expect(JSON.stringify(fixtureAgain.manifest)).toBe(JSON.stringify(fixtureFacts.manifest));
  });

  it('two TypeScript runs give byte-identical IPC files too', async () => {
    const again = await facts2ToArrow(tsGraphFact2Set(await buildTsCallGraph([{ path: TS_PATH, code: TS_CODE }]), [{ path: TS_PATH, code: TS_CODE, imports: [] }]), { source: 'ts-call-edges@0.1', engine: 'circle-ir@test' });
    for (const name of FACTS2_RELATION_NAMES) expect(hex(again.relations[name]), name).toBe(hex(tsFacts.relations[name]));
    expect(JSON.stringify(again.manifest)).toBe(JSON.stringify(tsFacts.manifest));
  });

  it('row counts equal the graph\'s counts less the duplicates a set collapses', () => {
    const m = fixtureFacts.manifest.relations;
    const n = (name: Facts2RelationName): number => m[name].rows + m[name].duplicates_dropped;
    const declCount = fixturePlain.files.reduce((k, f) => k + f.decls.length, 0);
    expect(n('files')).toBe(fixturePlain.files.length);
    expect(n('decl')).toBe(declCount);
    expect(n('decl_pos')).toBe(declCount);
    expect(n('call')).toBe(fixturePlain.edges.length);
    expect(n('unresolved')).toBe(fixturePlain.unresolved.length);
    expect(n('ref')).toBe(fixturePlain.references.length);
    expect(n('registration')).toBe(fixturePlain.unresolvedRegistrations.length);
    expect(n('parse_error')).toBe(fixturePlain.partial.length);
    expect(n('entries')).toBe(fixturePlain.entries.length);
    expect(m.moved.rows).toBe(0);
    for (const name of FACTS2_RELATION_NAMES) expect(m[name].rows, name).toBe(tableFromIPC(fixtureFacts.relations[name]).numRows);
  });

  it('every relation is a set with unique keys, in strictly increasing canonical order', () => {
    const inputs = files(JAVA_APP).map(f => ({ ...f, imports: [], dfg: fixtureIrs[f.path].dfg }));
    const set = javaGraphFact2Set(fixturePlain, inputs);
    for (const name of FACTS2_RELATION_NAMES) {
      const rel = FACTS2_RELATIONS[name];
      const rows = tableRows(rel, set.relations[name]);
      const cmp = rowComparator(rel);
      for (let i = 1; i < rows.length; i++) expect(cmp(rows[i - 1], rows[i]), name).toBeLessThan(0);
      expect(keyCollisions(rel, set.relations[name]), name).toBe(0);
    }
    expect(set.relations.flow.length).toBeGreaterThan(0);
  });

  it('flow, entries and moved are the facts@1 rows unchanged', () => {
    const inputs = files(JAVA_APP).map(f => ({ ...f, imports: [], dfg: fixtureIrs[f.path].dfg }));
    const v1 = javaGraphFactSet(fixturePlain, inputs);
    const v2 = javaGraphFact2Set(fixturePlain, inputs);
    for (const name of ['flow', 'entries', 'moved'] as const) {
      expect(tableRows(FACTS2_RELATIONS[name], v2.relations[name]), name).toEqual(tableRows(FACTS_RELATIONS[name], v1.relations[name]));
    }
  });

  it('every site renders back to its absolute line: decl_pos.line of its owner plus rel_line', () => {
    const declPos = new Map(rowsOf(fixtureFacts, 'decl_pos').map(r => [base32(r.id as Uint8Array), r.line as number] as const));
    const want = (sites: readonly { from: string; site: { line: number; col: number } }[]): string[] => sites.map(s => `${s.from} ${s.site.line} ${s.site.col}`).sort();
    const got = (name: 'call' | 'unresolved' | 'ref', owner: string): string[] =>
      rowsOf(fixtureFacts, name).map(r => { const o = base32(r[owner] as Uint8Array); return `${o} ${(declPos.get(o) as number) + (r.rel_line as number)} ${r.col as number}`; }).sort();
    expect([...new Set(got('call', 'caller_id'))]).toEqual([...new Set(want(fixturePlain.edges))]);
    expect([...new Set(got('unresolved', 'caller_id'))]).toEqual([...new Set(want(fixturePlain.unresolved))]);
    expect([...new Set(got('ref', 'from_id'))]).toEqual([...new Set(want(fixturePlain.references))]);
  });
});

describe('one Java file, end to end', () => {
  const ids = (): Map<string, string> => new Map(appPlain.files[0].decls.map(d => [d.id, d.qualified_name] as const));
  const q = (b: unknown): string => ids().get(base32(b as Uint8Array)) ?? (hex(b as Uint8Array) === ZERO ? '-' : base32(b as Uint8Array));

  it('files: the schema\'s file-key test vector, in the files row and in every row that names the file', () => {
    expect(hex(fileKey(APP_PATH))).toBe(APP_KEY_HEX);
    const fileRows = rowsOf(appFacts, 'files');
    expect(fileRows).toHaveLength(1);
    expect(hex(fileRows[0].file as Uint8Array)).toBe(APP_KEY_HEX);
    expect(fileRows[0]).toMatchObject({ path: APP_PATH, language: 'java', partial: false });
    expect(hex(fileRows[0].content_hash as Uint8Array)).toBe(hex(contentHash(APP_JAVA)));
    const decl = rowsOf(appFacts, 'decl');
    expect(decl.length).toBe(appPlain.files[0].decls.length);
    expect(decl.every(r => hex(r.file as Uint8Array) === APP_KEY_HEX)).toBe(true);
    const imports = rowsOf(appFacts, 'imports');
    expect(imports.map(r => `${hex(r.file as Uint8Array)} ${r.target as string} ${String(r.wildcard)}`)).toEqual([
      `${APP_KEY_HEX} java.util.List false`,
      `${APP_KEY_HEX} java.util.function.Supplier false`,
    ]);
    expect(rowsOf(appFacts, 'parse_error')).toEqual([]);
  });

  it('decl: name, parent, type-only, the ids@0.1 flags and the two structural bits', () => {
    const decl = new Map(rowsOf(appFacts, 'decl').map(r => [q(r.id), r] as const));
    const bits = (name: string): string => {
      const r = decl.get(name) as Row;
      return ['type_only', 'anonymous', 'duplicate', 'contained', 'loads_parent'].filter(k => r[k] === true).join(',');
    };
    expect(decl.get('org.example:App.seed')).toMatchObject({ kind: 'method', name: 'seed', signature: expect.any(String) });
    expect(q((decl.get('org.example:App.seed') as Row).parent_id)).toBe('org.example:App');
    expect(q((decl.get('org.example/App') as Row).parent_id)).toBe('-');
    expect(q((decl.get('org.example:App') as Row).parent_id)).toBe('org.example/App');
    // Java: every non-type member of a type loads it; fields, <clinit> and anonymous bodies are contained; a constructor only runs when called.
    expect(bits('org.example/App')).toBe('');
    expect(bits('org.example:App')).toBe('');
    expect(bits('org.example:App.Shape')).toBe('type_only');
    expect(bits('org.example:App.Shape.area')).toBe('type_only,loads_parent');
    expect(bits('org.example:App.Square')).toBe('');
    expect(bits('org.example:App.Square.constructor')).toBe('loads_parent');
    expect(bits('org.example:App.SEED')).toBe('contained,loads_parent');
    expect(bits('org.example:App.<clinit>')).toBe('contained,loads_parent');
    expect(bits('org.example:App.seed')).toBe('loads_parent');
    expect(bits('org.example:App.main/<lambda>@4.0.1.1')).toBe('anonymous,contained');
    expect((decl.get('org.example:App.main/<lambda>@4.0.1.1') as Row).name).toBe('<lambda>');
    for (const r of decl.values()) expect((r.body_hash as Uint8Array).some(x => x !== 0)).toBe(true);
  });

  it('decl_pos: one row per declaration with its start and end, lines 1-based and columns 0-based', () => {
    const pos = rowsOf(appFacts, 'decl_pos').map(r => `${q(r.id)} ${r.line as number}:${r.col as number}-${r.end_line as number}:${r.end_col as number}`).sort();
    expect(pos).toEqual(appPlain.files[0].decls.map(d => `${d.qualified_name} ${d.start_line}:${d.start_column}-${d.end_line}:${d.end_column}`).sort());
    expect(pos).toContain('org.example:App.total 26:2-32:3');
  });

  it('call: sites relative to the caller, no file; the declaring row of a polymorphic site marked', () => {
    const calls = rowsOf(appFacts, 'call').map(r => `${q(r.caller_id)} -> ${q(r.callee_id)} ${r.tier as string} ${r.method_name as string} +${r.rel_line as number}:${r.col as number}${r.declaring ? ' declaring' : ''}`);
    expect(calls.sort()).toEqual([
      'org.example:App.<clinit> -> org.example:App.seed exact seed +1:4',
      'org.example:App.SEED -> org.example:App.seed exact seed +0:34',
      'org.example:App.main/<lambda>@4.0.1.1 -> org.example:App exact App +0:23',
      'org.example:App.main/<lambda>@4.0.1.1 -> org.example:App.log exact log +0:23',
      'org.example:App.total -> org.example:App.Circle.area polymorphic area +3:11',
      'org.example:App.total -> org.example:App.Shape.area polymorphic area +3:11 declaring',
      'org.example:App.total -> org.example:App.Square.area polymorphic area +3:11',
    ].sort());
    // The graph's via on the other rows of the site is the declaring row's callee.
    const declaring = appPlain.edges.find(e => e.methodName === 'area' && e.via === undefined);
    expect(appPlain.edges.filter(e => e.methodName === 'area' && e.via !== undefined).every(e => e.via === declaring?.to)).toBe(true);
  });

  it('unresolved, ref and registration: relative sites; an unknown receiver is the empty string', () => {
    expect(rowsOf(appFacts, 'unresolved').map(r => `${q(r.caller_id)} ${r.method_name as string} ${r.reason as string} [${r.receiver as string}] +${r.rel_line as number}:${r.col as number}`).sort()).toEqual([
      'org.example:App.load forName dynamic [] +1:11',
      'org.example:App.log println external [] +1:4',
      'org.example:App.main run external [java.lang.Runnable] +2:4',
    ]);
    expect(rowsOf(appFacts, 'ref').map(r => `${q(r.from_id)} -> ${q(r.to_id)} +${r.rel_line as number}:${r.col as number}`)).toEqual(['org.example:App.lazy -> org.example:App.seedValue +1:11']);
    expect(rowsOf(appFacts, 'registration').map(r => `${q(r.from_id)} ${r.reason as string} ${r.evidence as string} +${r.rel_line as number}:${r.col as number}`)).toEqual([
      'org.example:App.load handler-unresolved Class.forName with a computed name +1:11',
    ]);
    expect(rowsOf(appFacts, 'entries').map(r => `${q(r.decl_id)} ${r.kind as string} ${r.certainty as string}`)).toEqual(['org.example:App.main main declared']);
  });
});

describe('one TypeScript file, end to end', () => {
  const ids = (): Map<string, string> => new Map(tsGraph.files[0].decls.map(d => [d.id, d.qualified_name] as const));
  const q = (b: unknown): string => ids().get(base32(b as Uint8Array)) ?? (hex(b as Uint8Array) === ZERO ? '-' : base32(b as Uint8Array));

  it('files and decl: the file key, the language, and the TypeScript structural bits', () => {
    const fileRows = rowsOf(tsFacts, 'files');
    expect(fileRows).toHaveLength(1);
    expect(hex(fileRows[0].file as Uint8Array)).toBe(hex(fileKey(TS_PATH)));
    expect(fileRows[0]).toMatchObject({ path: TS_PATH, language: 'typescript', partial: false });
    expect(tsFacts.manifest).toMatchObject({ facts: 'facts@2', source: 'ts-call-edges@0.1' });
    const decl = new Map(rowsOf(tsFacts, 'decl').map(r => [q(r.id), r] as const));
    const bits = (name: string): string => {
      const r = decl.get(name) as Row;
      return ['type_only', 'anonymous', 'duplicate', 'contained', 'loads_parent'].filter(k => r[k] === true).join(',');
    };
    expect(decl.size).toBe(tsGraph.files[0].decls.length);
    expect(bits('src/shapes:Shape')).toBe('type_only');
    // Outside Java a constructor is contained (a class used as a value may be constructed); top-level values are contained by the module.
    expect(bits('src/shapes:Square.constructor')).toBe('contained');
    expect(bits('src/shapes:Square.area')).toBe('');
    expect(bits('src/shapes:handlers')).toBe('contained');
    expect(bits('src/shapes:app')).toBe('contained');
    expect(bits('src/shapes:pick/<anonymous>@2.0.0')).toBe('anonymous,contained');
    expect(q((decl.get('src/shapes:pick/<anonymous>@2.0.0') as Row).parent_id)).toBe('src/shapes:pick');
    expect([...decl.values()].some(r => r.loads_parent === true)).toBe(false);
  });

  it('call: the declaring row of a polymorphic site is the one whose via is itself', () => {
    const calls = rowsOf(tsFacts, 'call').filter(r => r.tier === 'polymorphic').map(r => `${q(r.caller_id)} -> ${q(r.callee_id)} +${r.rel_line as number}:${r.col as number}${r.declaring ? ' declaring' : ''}`);
    expect(calls.sort()).toEqual([
      'src/shapes:measure -> src/shapes:Circle.area +1:9',
      'src/shapes:measure -> src/shapes:Square.area +1:9 declaring',
    ]);
    expect(rowsOf(tsFacts, 'call').filter(r => r.tier !== 'polymorphic').every(r => r.declaring === false)).toBe(true);
    expect(rowsOf(tsFacts, 'call').length + tsFacts.manifest.relations.call.duplicates_dropped).toBe(tsGraph.edges.length);
  });

  it('ref, unresolved and registration: a registration with no engine owner belongs to the declaration enclosing it (here the module)', () => {
    expect(rowsOf(tsFacts, 'ref').map(r => `${q(r.from_id)} -> ${q(r.to_id)} +${r.rel_line as number}:${r.col as number}`)).toEqual(['src/shapes:handlers -> src/shapes:measure +0:26']);
    const reg = rowsOf(tsFacts, 'registration');
    expect(tsGraph.unresolvedRegistrations).toHaveLength(1);
    expect(tsGraph.unresolvedRegistrations[0].from).toBeUndefined();
    expect(reg.map(r => `${q(r.from_id)} ${r.reason as string} +${r.rel_line as number}:${r.col as number}`)).toEqual(['src/shapes handler-unresolved +16:14']);
    expect(reg[0].evidence).toBe(tsGraph.unresolvedRegistrations[0].evidence);
    const unresolved = rowsOf(tsFacts, 'unresolved');
    expect(unresolved.length + tsFacts.manifest.relations.unresolved.duplicates_dropped).toBe(tsGraph.unresolved.length);
    expect(unresolved.every(r => r.receiver === '')).toBe(true);
    expect(rowsOf(tsFacts, 'imports')).toEqual([]);
    expect(rowsOf(tsFacts, 'flow')).toEqual([]);
  });

  it('refuses inputs that do not match the graph', () => {
    expect(() => tsGraphFact2Set(tsGraph, [])).toThrow(/not in the inputs/);
    expect(() => tsGraphFact2Set(tsGraph, [{ path: TS_PATH, code: TS_CODE, imports: [] }, { path: 'src/other.ts', code: '', imports: [] }])).toThrow(/not in the graph/);
  });
});

describe('partial files', () => {
  it('a file that did not parse cleanly is partial and has exactly one parse_error row, its column 0-based', async () => {
    const path = 'src/main/java/org/example/Broken.java';
    const code = 'package org.example;\n\npublic class Broken {\n  void ok() {}\n  void bad( { }\n}\n';
    const graph = await buildJavaGraph([{ path, code }, { path: APP_PATH, code: APP_JAVA }]);
    const broken = graph.files.find(f => f.file === path);
    expect(broken?.partial).toBe(true);
    const err = broken?.parseError;
    if (!err) throw new Error('no parse error');
    const facts = await facts2ToArrow(javaGraphFact2Set(graph, [{ path, code, imports: [] }, { path: APP_PATH, code: APP_JAVA, imports: [] }]));
    const partial = rowsOf(facts, 'files').map(r => `${r.path as string} ${String(r.partial)}`).sort();
    expect(partial).toEqual([`${APP_PATH} false`, `${path} true`]);
    expect(rowsOf(facts, 'parse_error').map(r => ({ file: hex(r.file as Uint8Array), line: r.line, col: r.col, node_kind: r.node_kind, parent_kind: r.parent_kind }))).toEqual([
      { file: hex(fileKey(path)), line: err.line, col: err.column - 1, node_kind: err.nodeKind, parent_kind: err.parent },
    ]);
  });

  it('refuses a partial file that names no parse error', () => {
    const graph = { ...appPlain, files: [{ ...appPlain.files[0], partial: true, parseError: undefined }] };
    expect(() => javaGraphFact2Set(graph, [{ path: APP_PATH, code: APP_JAVA, imports: [] }])).toThrow(/no parse error/);
  });

  it('refuses a site above its declaration, a site owner the file does not hold, and a registration outside the graph', () => {
    const input = [{ path: APP_PATH, code: APP_JAVA, imports: [] }];
    const edge = appPlain.edges.find(e => e.methodName === 'area') as JavaGraph['edges'][number];
    const above = { ...appPlain, edges: [{ ...edge, site: { ...edge.site, line: 1 } }] };
    expect(() => javaGraphFact2Set(above, input)).toThrow(/lies above/);
    const stranger = { ...appPlain, references: [{ ...appPlain.references[0], from: 'a'.repeat(26) }] };
    expect(() => javaGraphFact2Set(stranger, input)).toThrow(/is not in/);
    const outside = { ...appPlain, unresolvedRegistrations: [{ site: { file: 'src/Nope.java', line: 1, col: 0 }, reason: 'handler-unresolved' as const, evidence: 'x' }] };
    expect(() => javaGraphFact2Set(outside, input)).toThrow(/not in the graph/);
    expect(() => javaGraphFact2Set({ ...appPlain, ids: 'ids@0.2' as 'ids@0.1' }, input)).toThrow(/ids@0.2/);
  });
});

describe('the #n re-key', () => {
  const UTIL = 'package org.x;\n\npublic class Util {\n  static int a() { return b(); }\n  static int b() { return 1; }\n}\n';
  const app = { 'bundle0/src/org/x/Util.java': UTIL, 'bundle1/src/org/x/Util.java': UTIL };

  it('rewrites the later file\'s ids, parents and callers; decl stays keyed uniquely and flags the re-keyed rows duplicate', async () => {
    const graph = await buildJavaGraph(files(app));
    const set = javaGraphFact2Set(graph, files(app).map(f => ({ ...f, imports: [] })));
    expect(keyCollisions(FACTS2_RELATIONS.decl, set.relations.decl)).toBe(0);
    expect(keyCollisions(FACTS2_RELATIONS.decl_pos, set.relations.decl_pos)).toBe(0);
    const decl = tableRows(FACTS2_RELATIONS.decl, set.relations.decl);
    const later = hex(fileKey('bundle1/src/org/x/Util.java'));
    const byName = new Map(decl.map(r => [r[3] as string, r] as const));
    const rekeyed = (qn: string): string => digest128([STABLE_ID_SCHEME, 'java', (byName.get(qn) as readonly unknown[])[1] as string, qn, (byName.get(qn) as readonly unknown[])[4] as string]);
    for (const qn of ['org.x/Util#2', 'org.x:Util#2', 'org.x:Util.a#2', 'org.x:Util.b#2']) {
      const r = byName.get(qn);
      expect(r, qn).toBeDefined();
      expect(hex(r?.[5] as Uint8Array), qn).toBe(later);
      expect(r?.[10], qn).toBe(true); // duplicate
      expect(base32(r?.[0] as Uint8Array), qn).toBe(rekeyed(qn));
    }
    expect(byName.get('org.x:Util.a')?.[10]).toBe(false);
    // parent_id follows the re-key, as caller_id does.
    expect(base32(byName.get('org.x:Util#2')?.[6] as Uint8Array)).toBe(rekeyed('org.x/Util#2'));
    expect(base32(byName.get('org.x:Util.a#2')?.[6] as Uint8Array)).toBe(rekeyed('org.x:Util#2'));
    const declIds = new Set(decl.map(r => base32(r[0] as Uint8Array)));
    for (const name of ['call', 'decl_pos'] as const) {
      for (const r of tableRows(FACTS2_RELATIONS[name], set.relations[name])) expect(declIds.has(base32(r[0] as Uint8Array)), name).toBe(true);
    }
    for (const r of decl) if (r[1] !== 'module') expect(declIds.has(base32(r[6] as Uint8Array)), r[3] as string).toBe(true);
  });
});

describe('what moves when the code moves', () => {
  const PATH = 'src/main/java/app/core/UserService.java';
  const inputsOf = (app: Record<string, string>, irs: Record<string, CircleIR>): Facts2Input[] => files(app).map(f => ({ ...f, imports: [], dfg: irs[f.path].dfg }));

  it('an added import shifts every line of the file but moves no site row: files, imports, decl_pos and the module\'s body hash change', async () => {
    const edited = { ...JAVA_APP, [PATH]: JAVA_APP[PATH].replace('import java.util.List;', 'import java.util.List;\nimport java.util.Map;') };
    const graph = await buildJavaGraph(files(edited), { serviceFiles: SERVICES });
    const irs = { ...fixtureIrs, [PATH]: await analyze(edited[PATH], PATH, 'java', { navigationTypes: true }) };
    const importRows = (app: Record<string, string>): Facts2Input[] => files(app).map(f => ({
      ...f,
      imports: f.code.split('\n').filter(l => /^import\s/.test(l)).map(l => ({ target: l.replace(/^import\s+(static\s+)?/, '').replace(/;$/, '').replace(/\.\*$/, ''), wildcard: l.trim().endsWith('.*;') })),
      dfg: (app === JAVA_APP ? fixtureIrs : irs)[f.path].dfg,
    }));
    const before = javaGraphFact2Set(fixturePlain, importRows(JAVA_APP));
    const after = javaGraphFact2Set(graph, importRows(edited));
    const changed = FACTS2_RELATION_NAMES.filter(n => rowStrings(before, n).join('\n') !== rowStrings(after, n).join('\n'));
    expect(changed).toEqual(['files', 'decl', 'decl_pos', 'imports']);
    expect(rowStrings(after, 'imports').length).toBe(rowStrings(before, 'imports').length + 1);
    // decl: only the file's module row, whose body (the whole file) gained the import; no declaration moved.
    const was = new Set(rowStrings(before, 'decl'));
    const now = rowStrings(after, 'decl').filter(r => !was.has(r));
    expect(now).toHaveLength(1);
    expect(now[0]).toContain(' module app.core/UserService ');
    expect(rowStrings(after, 'decl')).toHaveLength(was.size);
    // Under facts@1 the same edit moves the file's call rows (absolute site lines).
    const v1Before = javaGraphFactSet(fixturePlain, inputsOf(JAVA_APP, fixtureIrs));
    const v1After = javaGraphFactSet(graph, inputsOf(edited, irs));
    expect(tableRows(FACTS_RELATIONS.call, v1After.relations.call)).not.toEqual(tableRows(FACTS_RELATIONS.call, v1Before.relations.call));
  });

  it('an added file adds its own rows and changes no other row', async () => {
    const added = { ...JAVA_APP, 'src/main/java/app/aaa/Extra.java': 'package app.aaa;\n\npublic class Extra {\n  int one() { return two(); }\n  int two() { return 2; }\n}\n' };
    const graph = await buildJavaGraph(files(added), { serviceFiles: SERVICES });
    const irs = { ...fixtureIrs, 'src/main/java/app/aaa/Extra.java': await analyze(added['src/main/java/app/aaa/Extra.java'], 'src/main/java/app/aaa/Extra.java', 'java', { navigationTypes: true }) };
    const before = javaGraphFact2Set(fixturePlain, inputsOf(JAVA_APP, fixtureIrs));
    const after = javaGraphFact2Set(graph, inputsOf(added, irs));
    for (const name of FACTS2_RELATION_NAMES) {
      const now = new Set(rowStrings(after, name));
      const gone = rowStrings(before, name).filter(r => !now.has(r));
      expect(gone, name).toEqual([]);
    }
    expect(rowStrings(after, 'files').length).toBe(rowStrings(before, 'files').length + 1);
    expect(rowStrings(after, 'call').length).toBe(rowStrings(before, 'call').length + 1);
    // Under facts@1 the dense file_id of every path that sorts after the new one shifts.
    const idOf = (rows: readonly (readonly unknown[])[]): Map<unknown, unknown> => new Map(rows.map(r => [r[1], r[0]] as const));
    const v1Before = idOf(tableRows(FACTS_RELATIONS.files, javaGraphFactSet(fixturePlain, inputsOf(JAVA_APP, fixtureIrs)).relations.files));
    const v1After = idOf(tableRows(FACTS_RELATIONS.files, javaGraphFactSet(graph, inputsOf(added, irs)).relations.files));
    expect([...v1Before].filter(([path, id]) => v1After.get(path) !== id).length).toBeGreaterThan(0);
  });
});

describe('relation2ToArrowIpc and facts2ToArrow on rows', () => {
  it('canonicalises rows, refuses cells that do not fit, and writes empty relations as a schema with no batch', async () => {
    const a = idBytes('a'.repeat(26));
    const b = new Uint8Array(16);
    b[0] = 1;
    // ref keys the site first: (from_id, rel_line, col, to_id).
    const { bytes, rows, duplicatesDropped } = await relation2ToArrowIpc('ref', [[a, a, 2, 0], [a, b, 1, 5], [a, a, 2, 0]]);
    expect(rows).toBe(2);
    expect(duplicatesDropped).toBe(1);
    expect(tableFromIPC(bytes).toArray().map(r => { const j = r.toJSON() as Row; return `${j.rel_line as number}:${j.col as number}`; })).toEqual(['1:5', '2:0']);
    await expect(relation2ToArrowIpc('registration', [[a, 'nope', 'e', 0, 0]])).rejects.toThrow(/vocabulary/);
    await expect(relation2ToArrowIpc('decl_pos', [[a, 1, 2, 3]])).rejects.toThrow(/cells/);
    const empty = Object.fromEntries(FACTS2_RELATION_NAMES.map(n => [n, []])) as unknown as Record<Facts2RelationName, []>;
    const out = await facts2ToArrow(empty);
    for (const name of FACTS2_RELATION_NAMES) {
      expect(tableFromIPC(out.relations[name]).numRows).toBe(0);
      expect(out.manifest.relations[name]).toMatchObject({ rows: 0, batches: 0, duplicates_dropped: 0 });
    }
    expect(Object.keys(out.manifest)).toEqual(['facts', 'ids', 'chunk_rows', 'relations']);
    await expect(facts2ToArrow({ ...empty, decl_pos: undefined } as unknown as Record<Facts2RelationName, []>)).rejects.toThrow(/decl_pos is missing/);
  });

  it('paths sort by code point, and the files rows follow the keys, not the paths', () => {
    const set = javaGraphFact2Set(appPlain, [{ path: APP_PATH, code: APP_JAVA, imports: [] }, { path: 'Z/Other.java', code: 'x', imports: [] }]);
    const rows = tableRows(FACTS2_RELATIONS.files, set.relations.files);
    expect(rows.map(r => r[1])).toEqual([APP_PATH, 'Z/Other.java'].sort((x, y) => compareCodePoints(hex(fileKey(x)), hex(fileKey(y)))));
    // An input the graph does not hold is a Java file with no declarations.
    expect(rows.find(r => r[1] === 'Z/Other.java')?.[3]).toBe('java');
  });
});
