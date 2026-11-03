/**
 * `facts@2`: the schema file is well-formed, the TypeScript mirror agrees
 * with it, the test vectors recompute (node id, file key), the changes
 * against `facts@1` are exactly the intended ones, and the canonical-order
 * comparator is a total order over every `facts@2` relation.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { FACTS_CHUNK_ROWS, FACTS_ID_WIDTH, FACTS_RELATIONS, FACTS_SCHEME, sortColumns, type FactRow, type FactValue } from '../../src/facts/schema.js';
import {
  FACTS2_RELATION_NAMES,
  FACTS2_RELATIONS,
  FACTS2_SCHEME,
  FACTS2_STORE_ONLY,
  FACTS_FILE_KEY_PARTS,
  FACTS_REGISTRATION_REASONS,
  fileKey,
} from '../../src/facts/schema2.js';
import { canonicalRows, canonicalSet, idBytes, rowComparator } from '../../src/facts/order.js';
import { base32, digest128, digest128Bytes } from '../../src/stable-ids/hash.js';
import { nodeIdBytes, nodeIdBytesOfPrinted, type StableNodeKind } from '../../src/stable-ids/nodes.js';

const here = dirname(fileURLToPath(import.meta.url));

interface ColumnSpec { name: string; type: string; nullable: boolean; values?: string[]; doc?: string }
interface RelationSpec { key: string[]; store_only: boolean; columns: ColumnSpec[]; doc?: string }
interface SchemaFile {
  scheme: string;
  ids: string;
  id_encoding: { arrow: string; width: number };
  node_id: { parts: string[]; kinds: string[]; example: { printed: string; body_id: string; kind: string; ordinal: number; hex: string; base32: string } };
  file_key: { parts: string[]; example: { path: string; hex: string; base32: string } };
  positions: { line: string; col: string };
  types: Record<string, string>;
  canonical_order: { key_then_remaining_columns: boolean; null_first: boolean; strings: string; sets: boolean };
  chunking: { chunk_rows: number; ipc: string };
  loading: { store_only: string; engine: string };
  metadata: Record<string, string>;
  relations: Record<string, RelationSpec>;
}

const read = (name: string): unknown => JSON.parse(readFileSync(join(here, '..', '..', 'schemas', name), 'utf8'));
const schema = read('facts@2.json') as SchemaFile;
const v1 = read('facts@1.json') as Omit<SchemaFile, 'relations'> & { relations: Record<string, Omit<RelationSpec, 'store_only'>> };

const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');
const columnNames = (rel: { columns: { name: string }[] }): string[] => rel.columns.map(c => c.name);

describe('facts@2 schema file', () => {
  it('names the scheme, the id scheme and the id width; order, chunking and metadata as in facts@1', () => {
    expect(schema.scheme).toBe(FACTS2_SCHEME);
    expect(schema.scheme).toBe('facts@2');
    expect(schema.metadata.facts).toBe('facts@2');
    expect(schema.metadata.ids).toBe('ids@0.1');
    expect(schema.ids).toBe('ids@0.1');
    expect(schema.id_encoding).toEqual({ ...v1.id_encoding, $comment: expect.any(String) });
    expect(schema.id_encoding.width).toBe(FACTS_ID_WIDTH);
    expect(schema.chunking.chunk_rows).toBe(FACTS_CHUNK_ROWS);
    expect(schema.chunking.ipc).toBe('file');
    const strip = <T extends object>(o: T): Omit<T, '$comment'> => { const { $comment: _c, ...rest } = o as T & { $comment?: string }; return rest; };
    expect(strip(schema.canonical_order)).toEqual(strip(v1.canonical_order));
    expect(strip(schema.types)).toEqual(strip(v1.types));
    expect(Object.keys(schema.metadata).filter(k => k !== '$comment')).toEqual(['facts', 'ids', 'engine', 'parser']);
  });

  it('states the fixed-width node id (unchanged from facts@1) and its vector recomputes', () => {
    expect(schema.node_id.parts).toEqual(v1.node_id.parts);
    expect(schema.node_id.kinds).toEqual(v1.node_id.kinds);
    expect(schema.node_id.example).toEqual(v1.node_id.example);
    const ex = schema.node_id.example;
    const bytes = nodeIdBytes(ex.body_id, ex.kind as StableNodeKind, ex.ordinal);
    expect(hex(bytes)).toBe(ex.hex);
    expect(base32(bytes)).toBe(ex.base32);
    expect(nodeIdBytesOfPrinted(ex.printed)).toEqual(bytes);
    expect(digest128Bytes(['ids@0.1', 'node', ex.body_id, ex.kind, String(ex.ordinal)])).toEqual(bytes);
  });

  it('states the stable file key and its vector recomputes through fileKey', () => {
    expect(schema.file_key.parts).toEqual(['ids@0.1', 'file', '<path>']);
    expect(schema.file_key.parts).toEqual([...FACTS_FILE_KEY_PARTS]);
    const ex = schema.file_key.example;
    expect(ex.path).toBe('src/main/java/org/example/App.java');
    const bytes = fileKey(ex.path);
    expect(bytes).toHaveLength(FACTS_ID_WIDTH);
    expect(hex(bytes)).toBe(ex.hex);
    expect(base32(bytes)).toBe(ex.base32);
    expect(digest128(['ids@0.1', 'file', ex.path])).toBe(ex.base32);
    // A function of the path alone: another path, another key; the same path, the same bytes.
    expect(hex(fileKey('src/main/java/org/example/App2.java'))).not.toBe(ex.hex);
    expect(fileKey(ex.path)).toEqual(bytes);
  });

  it('states the site positions: lines 1-based (rel_line 0 on the declaration line), columns 0-based', () => {
    expect(schema.positions.line).toMatch(/^1-based/);
    expect(schema.positions.line).toMatch(/rel_line: 0/);
    expect(schema.positions.col).toBe('0-based');
  });

  it('has exactly the twelve relations, in the order the TypeScript mirror lists them', () => {
    expect(Object.keys(schema.relations)).toEqual([...FACTS2_RELATION_NAMES]);
    expect(FACTS2_RELATION_NAMES).toHaveLength(12);
  });

  it('every relation states store_only; only decl_pos and parse_error are store-only', () => {
    for (const [name, rel] of Object.entries(schema.relations)) expect(typeof rel.store_only, name).toBe('boolean');
    const storeOnly = Object.entries(schema.relations).filter(([, r]) => r.store_only).map(([n]) => n);
    expect(storeOnly).toEqual(['decl_pos', 'parse_error']);
    expect([...FACTS2_STORE_ONLY]).toEqual(storeOnly);
    expect(schema.loading.engine).toMatch(/store_only is false/);
  });

  it('has no nullable column and no `bean`', () => {
    for (const [name, rel] of Object.entries(schema.relations)) {
      for (const c of rel.columns) expect(c.nullable, `${name}.${c.name}`).toBe(false);
    }
    const kinds = schema.relations.entries.columns.find(c => c.name === 'kind')?.values;
    expect(kinds).not.toContain('bean');
    expect(kinds).toContain('di');
  });

  it('every column is well-formed: known type, unique name, vocabulary on dict columns only, keys are columns', () => {
    const types = new Set(Object.keys(schema.types).filter(k => !k.startsWith('$')));
    for (const [name, rel] of Object.entries(schema.relations)) {
      const names = columnNames(rel);
      expect(new Set(names).size, name).toBe(names.length);
      expect(rel.key.length, name).toBeGreaterThan(0);
      expect(new Set(rel.key).size, name).toBe(rel.key.length);
      for (const k of rel.key) expect(names, `${name}.${k}`).toContain(k);
      for (const c of rel.columns) {
        expect(types.has(c.type), `${name}.${c.name} type ${c.type}`).toBe(true);
        if (c.type === 'dict') {
          expect(c.values, `${name}.${c.name}`).toBeDefined();
          expect(new Set(c.values).size).toBe((c.values as string[]).length);
          expect((c.values as string[]).length).toBeLessThanOrEqual(127);
        } else expect(c.values, `${name}.${c.name}`).toBeUndefined();
      }
    }
  });

  it('the TypeScript mirror matches the file column for column, key for key and store_only for store_only', () => {
    for (const name of FACTS2_RELATION_NAMES) {
      const file = schema.relations[name];
      const ts = FACTS2_RELATIONS[name];
      expect(ts.key, name).toEqual(file.key);
      expect(ts.storeOnly, name).toBe(file.store_only);
      expect(ts.columns.map(c => ({ name: c.name, type: c.type, nullable: c.nullable, ...(c.values ? { values: [...c.values] } : {}) })), name)
        .toEqual(file.columns.map(c => ({ name: c.name, type: c.type, nullable: c.nullable, ...(c.values ? { values: c.values } : {}) })));
    }
  });

  it('carries no dense file id and no absolute site column: the file key where a file is named, rel_line + col on every site', () => {
    for (const [name, rel] of Object.entries(schema.relations)) {
      const names = columnNames(rel);
      expect(names.filter(n => n === 'file_id' || n.startsWith('site_')), name).toEqual([]);
    }
    const withFile = Object.entries(schema.relations).filter(([, r]) => r.columns.some(c => c.name === 'file')).map(([n]) => n);
    expect(withFile).toEqual(['files', 'decl', 'parse_error', 'imports']);
    for (const n of withFile) expect(schema.relations[n].columns.find(c => c.name === 'file')?.type, n).toBe('fixed16');
    for (const n of ['call', 'unresolved', 'ref', 'registration']) {
      const cols = schema.relations[n].columns;
      expect(cols.find(c => c.name === 'rel_line')?.type, n).toBe('u32');
      expect(cols.find(c => c.name === 'col')?.type, n).toBe('u32');
    }
    // decl has no position; decl_pos has all four.
    expect(columnNames(schema.relations.decl)).not.toContain('line');
    expect(columnNames(schema.relations.decl_pos)).toEqual(['id', 'line', 'end_line', 'col', 'end_col']);
  });

  it('keys: every site relation keys its site first (owner, rel_line, col)', () => {
    expect(schema.relations.files.key).toEqual(['file']);
    expect(schema.relations.decl.key).toEqual(['id']);
    expect(schema.relations.decl_pos.key).toEqual(['id']);
    expect(schema.relations.call.key).toEqual(['caller_id', 'rel_line', 'col', 'callee_id']);
    expect(schema.relations.unresolved.key).toEqual(['caller_id', 'rel_line', 'col', 'method_name', 'receiver', 'reason']);
    expect(schema.relations.ref.key).toEqual(['from_id', 'rel_line', 'col', 'to_id']);
    expect(schema.relations.registration.key).toEqual(['from_id', 'rel_line', 'col', 'reason']);
    expect(schema.relations.parse_error.key).toEqual(['file']);
    expect(schema.relations.imports.key).toEqual(['file', 'target', 'wildcard']);
  });

  it('parse_error.col is 0-based like every other column', () => {
    expect(schema.relations.parse_error.columns.find(c => c.name === 'col')?.doc).toMatch(/^0-based/);
    for (const rel of Object.values(schema.relations)) {
      for (const c of rel.columns) if ((c.name === 'col' || c.name === 'end_col') && c.doc) expect(c.doc).toMatch(/0-based/);
    }
  });

  it('decl gains the columns reach reads; call gains declaring; files gains partial', () => {
    expect(columnNames(schema.relations.decl)).toEqual([
      'id', 'kind', 'name', 'qualified_name', 'signature', 'file', 'parent_id', 'body_hash',
      'type_only', 'anonymous', 'duplicate', 'contained', 'loads_parent',
    ]);
    expect(columnNames(schema.relations.call)).toEqual(['caller_id', 'callee_id', 'tier', 'method_name', 'rel_line', 'col', 'declaring']);
    expect(columnNames(schema.relations.files)).toEqual(['file', 'path', 'content_hash', 'language', 'partial']);
    expect(schema.relations.registration.columns.find(c => c.name === 'reason')?.values).toEqual([...FACTS_REGISTRATION_REASONS]);
    // Deferred, not in the file.
    const all = Object.values(schema.relations).flatMap(columnNames);
    expect(Object.keys(schema.relations)).not.toContain('registration_bound');
    expect(all).not.toContain('is_static');
    expect(all).not.toContain('body_hash_b');
    expect(columnNames(schema.relations.entries)).toEqual(columnNames(v1.relations.entries));
  });

  it('flow, entries and moved are identical to facts@1; the surviving vocabularies are unchanged', () => {
    for (const n of ['flow', 'entries', 'moved'] as const) {
      expect(schema.relations[n].key, n).toEqual(v1.relations[n].key);
      expect(schema.relations[n].columns, n).toEqual(v1.relations[n].columns);
      expect(FACTS2_RELATIONS[n].columns, n).toEqual(FACTS_RELATIONS[n].columns);
    }
    const vocab = (rel: { columns: ColumnSpec[] }, c: string): string[] | undefined => rel.columns.find(x => x.name === c)?.values;
    expect(vocab(schema.relations.files, 'language')).toEqual(vocab(v1.relations.files, 'language'));
    expect(vocab(schema.relations.decl, 'kind')).toEqual(vocab(v1.relations.decl, 'kind'));
    expect(vocab(schema.relations.call, 'tier')).toEqual(vocab(v1.relations.call, 'tier'));
    expect(vocab(schema.relations.unresolved, 'reason')).toEqual(vocab(v1.relations.unresolved, 'reason'));
  });

  it('leaves facts@1 as it was: its file still names facts@1 and the facts@1 mirror is still the default scheme', () => {
    expect(v1.scheme).toBe('facts@1');
    expect(FACTS_SCHEME).toBe('facts@1');
    expect(Object.keys(v1.relations)).toHaveLength(8);
  });

  it('sortColumns puts the key first, then every other column once', () => {
    for (const name of FACTS2_RELATION_NAMES) {
      const rel = FACTS2_RELATIONS[name];
      const order = sortColumns(rel);
      expect([...order].sort((a, b) => a - b)).toEqual(rel.columns.map((_, i) => i));
      expect(order.slice(0, rel.key.length).map(i => rel.columns[i].name)).toEqual([...rel.key]);
    }
  });
});

describe('facts@2 canonical order is total', () => {
  it('is reflexive, antisymmetric, transitive and total over a generated sample of every relation', () => {
    let seed = 54321;
    const rnd = (n: number): number => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed % n;
    };
    const ids = Array.from({ length: 3 }, (_, i) => idBytes(digest128(['id', String(i)])));
    const strings = ['', 'a', 'b', 'é', '\u{1f600}', 'ab'];
    const cell = (type: string, values?: readonly string[]): FactValue => {
      switch (type) {
        case 'fixed16': return ids[rnd(ids.length)];
        case 'u32': return rnd(3);
        case 'utf8': return strings[rnd(strings.length)];
        case 'bool': return rnd(2) === 1;
        case 'dict': return (values as readonly string[])[rnd(Math.min(3, (values as readonly string[]).length))];
        default: throw new Error(type);
      }
    };
    const sign = (x: number): number => (x < 0 ? -1 : x > 0 ? 1 : 0);
    for (const name of FACTS2_RELATION_NAMES) {
      const rel = FACTS2_RELATIONS[name];
      const rows: FactRow[] = Array.from({ length: 30 }, () => rel.columns.map(c => cell(c.type, c.values)));
      const cmp = rowComparator(rel);
      for (const a of rows) {
        expect(cmp(a, a), name).toBe(0);
        for (const b of rows) {
          const ab = sign(cmp(a, b));
          expect(sign(cmp(b, a)) + ab, name).toBe(0);
          if (ab === 0) expect(a.map(v => (v instanceof Uint8Array ? base32(v) : v)), name).toEqual(b.map(v => (v instanceof Uint8Array ? base32(v) : v)));
          for (const c of rows) {
            const bc = sign(cmp(b, c));
            if (ab <= 0 && bc <= 0) expect(sign(cmp(a, c)), name).toBeLessThanOrEqual(0);
          }
        }
      }
      const sorted = canonicalRows(rel, rows);
      expect(canonicalRows(rel, [...rows].reverse())).toEqual(sorted);
      const set = canonicalSet(rel, [...rows, ...rows]);
      for (let i = 1; i < set.rows.length; i++) expect(cmp(set.rows[i - 1], set.rows[i]), name).toBeLessThan(0);
    }
  });
});
