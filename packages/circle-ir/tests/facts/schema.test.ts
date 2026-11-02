/**
 * `facts@1` (PROPOSED): the schema file is well-formed, the TypeScript mirror
 * agrees with it, and the canonical-order comparator is a total order.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  FACTS_CHUNK_ROWS,
  FACTS_ID_WIDTH,
  FACTS_RELATION_NAMES,
  FACTS_RELATIONS,
  FACTS_SCHEME,
  sortColumns,
  type FactRow,
  type FactValue,
} from '../../src/facts/schema.js';
import { canonicalRows, compareBytes, compareCodePoints, compareValues, idBytes, rowComparator } from '../../src/facts/order.js';
import { base32, digest128 } from '../../src/stable-ids/hash.js';

const here = dirname(fileURLToPath(import.meta.url));

interface SchemaFile {
  scheme: string;
  ids: string;
  id_encoding: { arrow: string; width: number };
  types: Record<string, string>;
  canonical_order: { key_then_remaining_columns: boolean; null_first: boolean; strings: string };
  chunking: { chunk_rows: number; ipc: string };
  relations: Record<string, { key: string[]; columns: { name: string; type: string; nullable: boolean; values?: string[] }[] }>;
}

const schema = JSON.parse(readFileSync(join(here, '..', '..', 'schemas', 'facts@1.json'), 'utf8')) as SchemaFile;

describe('facts@1 schema file', () => {
  it('names the scheme, the id scheme and the id width', () => {
    expect(schema.scheme).toBe(FACTS_SCHEME);
    expect(schema.ids).toBe('ids@0.1');
    expect(schema.id_encoding.arrow).toBe('fixed_size_binary');
    expect(schema.id_encoding.width).toBe(FACTS_ID_WIDTH);
    expect(schema.chunking.chunk_rows).toBe(FACTS_CHUNK_ROWS);
    expect(schema.chunking.ipc).toBe('file');
    expect(schema.canonical_order.key_then_remaining_columns).toBe(true);
    expect(schema.canonical_order.null_first).toBe(true);
    expect(schema.canonical_order.strings).toBe('code-point');
  });

  it('has exactly the eight relations, in the order the TypeScript mirror lists them', () => {
    expect(Object.keys(schema.relations)).toEqual([...FACTS_RELATION_NAMES]);
    expect(FACTS_RELATION_NAMES).toHaveLength(8);
  });

  it('every column is well-formed: known type, unique name, vocabulary on dict columns only, keys are columns', () => {
    const types = new Set(Object.keys(schema.types).filter(k => !k.startsWith('$')));
    for (const [name, rel] of Object.entries(schema.relations)) {
      const names = rel.columns.map(c => c.name);
      expect(new Set(names).size, name).toBe(names.length);
      expect(rel.key.length, name).toBeGreaterThan(0);
      for (const k of rel.key) expect(names, `${name}.${k}`).toContain(k);
      for (const c of rel.columns) {
        expect(types.has(c.type), `${name}.${c.name} type ${c.type}`).toBe(true);
        expect(typeof c.nullable, `${name}.${c.name}`).toBe('boolean');
        if (c.type === 'dict') {
          expect(c.values, `${name}.${c.name}`).toBeDefined();
          expect(new Set(c.values).size).toBe((c.values as string[]).length);
          expect((c.values as string[]).length).toBeLessThanOrEqual(127);
        } else expect(c.values, `${name}.${c.name}`).toBeUndefined();
      }
      // Every id column is an ids@0.1 id and never a key that could be null.
      for (const k of rel.key) expect(rel.columns.find(c => c.name === k)?.nullable, `${name}.${k}`).toBe(false);
    }
  });

  it('the TypeScript mirror matches the file column for column', () => {
    for (const name of FACTS_RELATION_NAMES) {
      const file = schema.relations[name];
      const ts = FACTS_RELATIONS[name];
      expect(ts.key, name).toEqual(file.key);
      expect(ts.columns.map(c => ({ name: c.name, type: c.type, nullable: c.nullable, ...(c.values ? { values: [...c.values] } : {}) })), name)
        .toEqual(file.columns.map(c => ({ name: c.name, type: c.type, nullable: c.nullable, ...(c.values ? { values: c.values } : {}) })));
    }
  });

  it('sortColumns puts the key first, then every other column once', () => {
    for (const name of FACTS_RELATION_NAMES) {
      const rel = FACTS_RELATIONS[name];
      const order = sortColumns(rel);
      expect([...order].sort((a, b) => a - b)).toEqual(rel.columns.map((_, i) => i));
      expect(order.slice(0, rel.key.length).map(i => rel.columns[i].name)).toEqual([...rel.key]);
    }
  });
});

describe('ids@0.1 ids in columns', () => {
  it('round-trips the 26-character base32 form through 16 bytes', () => {
    for (const parts of [['ids@0.1', 'java', 'method', 'a:B.c', '(int)'], ['x'], ['']]) {
      const id = digest128(parts);
      const bytes = idBytes(id);
      expect(bytes).toHaveLength(16);
      expect(base32(bytes)).toBe(id);
    }
  });

  it('rejects anything that is not an id', () => {
    expect(() => idBytes('')).toThrow(/ids@0.1/);
    expect(() => idBytes('abc')).toThrow(/ids@0.1/);
    expect(() => idBytes('ABCDEFGHIJKLMNOPQRSTUVWXYZ')).toThrow(/ids@0.1/);
    // Padding bits set: 'z' (11010 → 2 non-zero low bits) as the 26th character.
    expect(() => idBytes('a'.repeat(25) + 'z')).toThrow(/ids@0.1/);
  });
});

describe('canonical order is total', () => {
  it('compares strings by code point, not UTF-16 code unit', () => {
    // U+FF5E (one code unit, 0xff5e) vs U+1F600 (surrogate pair starting 0xd83d).
    expect('～' < '\u{1f600}').toBe(false); // JS says the emoji is smaller…
    expect(compareCodePoints('～', '\u{1f600}')).toBe(-1); // …code points (and UTF-8 bytes) say otherwise.
    expect(compareCodePoints('a', 'ab')).toBe(-1);
    expect(compareCodePoints('ab', 'a')).toBe(1);
    expect(compareCodePoints('', '')).toBe(0);
    expect(compareCodePoints('b', 'a')).toBe(1);
  });

  it('compares id bytes unsigned and bytewise', () => {
    expect(compareBytes(new Uint8Array([0, 0xff]), new Uint8Array([1, 0]))).toBe(-1);
    expect(compareBytes(new Uint8Array([0x80]), new Uint8Array([0x7f]))).toBe(1);
    expect(compareBytes(new Uint8Array([1]), new Uint8Array([1, 0]))).toBeLessThan(0);
  });

  it('orders null first, false before true, and refuses mixed types', () => {
    expect(compareValues(null, 'a')).toBe(-1);
    expect(compareValues('a', null)).toBe(1);
    expect(compareValues(null, null)).toBe(0);
    expect(compareValues(false, true)).toBe(-1);
    expect(compareValues(3, 10)).toBe(-1);
    expect(() => compareValues(1, 'a')).toThrow(/different types/);
  });

  it('is reflexive, antisymmetric, transitive and total over a generated sample of every relation', () => {
    // A small deterministic generator: enough collisions on key columns to exercise the remaining columns.
    let seed = 12345;
    const rnd = (n: number): number => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed % n;
    };
    const ids = Array.from({ length: 3 }, (_, i) => idBytes(digest128(['id', String(i)])));
    const strings = ['', 'a', 'b', 'é', '\u{1f600}', 'ab'];
    const cell = (type: string, nullable: boolean, values?: readonly string[]): FactValue => {
      if (nullable && rnd(4) === 0) return null;
      switch (type) {
        case 'fixed16': return ids[rnd(ids.length)];
        case 'u32': return rnd(3);
        case 'utf8': return strings[rnd(strings.length)];
        case 'bool': return rnd(2) === 1;
        case 'dict': return (values as readonly string[])[rnd(Math.min(3, (values as readonly string[]).length))];
        default: throw new Error(type);
      }
    };
    for (const name of FACTS_RELATION_NAMES) {
      const rel = FACTS_RELATIONS[name];
      const rows: FactRow[] = Array.from({ length: 40 }, () => rel.columns.map(c => cell(c.type, c.nullable, c.values)));
      const cmp = rowComparator(rel);
      const sign = (x: number): number => (x < 0 ? -1 : x > 0 ? 1 : 0);
      for (const a of rows) {
        expect(cmp(a, a), name).toBe(0);
        for (const b of rows) {
          const ab = sign(cmp(a, b));
          expect(sign(cmp(b, a)) + ab, name).toBe(0);
          // Equal under the comparator means equal cell for cell.
          if (ab === 0) expect(a.map(v => (v instanceof Uint8Array ? base32(v) : v)), name).toEqual(b.map(v => (v instanceof Uint8Array ? base32(v) : v)));
          for (const c of rows) {
            const bc = sign(cmp(b, c));
            if (ab <= 0 && bc <= 0) expect(sign(cmp(a, c)), name).toBeLessThanOrEqual(0);
            if (ab < 0 && bc <= 0) expect(sign(cmp(a, c)), name).toBe(-1);
          }
        }
      }
      // Sorting is idempotent and independent of the input order.
      const sorted = canonicalRows(rel, rows);
      expect(canonicalRows(rel, sorted)).toEqual(sorted);
      expect(canonicalRows(rel, [...rows].reverse())).toEqual(sorted);
    }
  });
});
