/**
 * `facts@1` rows → Arrow IPC file bytes, one file per relation, plus the
 * manifest. The wire form the graph store reads (graph-store design §3).
 *
 * `apache-arrow` is an optional dependency loaded on first use, so the library
 * keeps running where it is not installed (browser bundles leave it external)
 * and nothing is paid until a caller asks for facts. Determinism: Arrow JS
 * writes no timestamps or random ids, dictionary ids are assigned here by
 * column position (never by the library's global counter), the full
 * vocabulary is written as every dictionary, and batches are cut at
 * `FACTS_CHUNK_ROWS` after the canonical sort — two runs over the same facts
 * give identical bytes (locked by `tests/facts/arrow.test.ts`).
 */

import type * as ArrowNs from 'apache-arrow';
import { base32, blake3 } from '../stable-ids/hash.js';
import {
  FACTS_CHUNK_ROWS,
  FACTS_ID_WIDTH,
  FACTS_RELATION_NAMES,
  FACTS_RELATIONS,
  FACTS_SCHEME,
  type FactRow,
  type FactRows,
  type FactsColumn,
  type FactsRelation,
  type FactsRelationName,
} from './schema.js';

export interface FactsArrowOptions {
  /** The engine that produced the facts, e.g. `circle-ir@4.19.0`; written as schema metadata. */
  engine?: string;
  /** The parser the engine ran, e.g. `tree-sitter-java@0.23.5`; written as schema metadata. */
  parser?: string;
  /** The graph scheme the facts were derived from; recorded in the manifest. */
  source?: string;
}

export interface FactsManifestRelation {
  /** The file name the relation is written under: `<relation>.arrow`. */
  file: string;
  rows: number;
  batches: number;
  bytes: number;
  /** blake3 of the IPC file bytes, base32: the cache key (the canonical row digest is the store's). */
  blake3: string;
}

export interface FactsManifest {
  facts: typeof FACTS_SCHEME;
  ids: 'ids@0.1';
  source?: string;
  engine?: string;
  parser?: string;
  chunk_rows: number;
  relations: Record<FactsRelationName, FactsManifestRelation>;
}

export interface FactsArrow {
  scheme: typeof FACTS_SCHEME;
  /** Arrow IPC *file* bytes per relation, in canonical order, `facts@1` schema. */
  relations: Record<FactsRelationName, Uint8Array>;
  manifest: FactsManifest;
}

type Arrow = typeof ArrowNs;

let arrowModule: Promise<Arrow> | undefined;

/** The `apache-arrow` module, loaded once; a clear error when it is not installed. */
export async function loadArrow(): Promise<Arrow> {
  arrowModule ??= import('apache-arrow').catch((e: unknown) => {
    arrowModule = undefined;
    throw new Error(`facts@1: emitting Arrow needs the optional dependency apache-arrow (npm install apache-arrow): ${e instanceof Error ? e.message : String(e)}`);
  });
  return arrowModule;
}

const encoder = new TextEncoder();

function arrowType(arrow: Arrow, c: FactsColumn, dictionaryId: number): ArrowNs.DataType {
  switch (c.type) {
    case 'fixed16': return new arrow.FixedSizeBinary(FACTS_ID_WIDTH);
    case 'u32': return new arrow.Uint32();
    case 'utf8': return new arrow.Utf8();
    case 'bool': return new arrow.Bool();
    case 'dict': return new arrow.Dictionary(new arrow.Utf8(), new arrow.Int8(), dictionaryId, false);
  }
}

function utf8Data(strings: readonly (string | null)[]): { offsets: Int32Array; bytes: Uint8Array; nulls: Uint8Array | null; nullCount: number } {
  const offsets = new Int32Array(strings.length + 1);
  const parts: Uint8Array[] = [];
  let total = 0;
  let nullCount = 0;
  const nulls = new Uint8Array(Math.ceil(strings.length / 8) || 1);
  for (let i = 0; i < strings.length; i++) {
    const s = strings[i];
    if (s === null) nullCount++;
    else {
      nulls[i >> 3] |= 1 << (i & 7);
      const b = encoder.encode(s);
      parts.push(b);
      total += b.length;
    }
    offsets[i + 1] = total;
  }
  const bytes = new Uint8Array(total);
  let o = 0;
  for (const b of parts) {
    bytes.set(b, o);
    o += b.length;
  }
  return { offsets, bytes, nulls: nullCount > 0 ? nulls : null, nullCount };
}

function validity(cells: readonly unknown[]): { nulls: Uint8Array | null; nullCount: number } {
  const nulls = new Uint8Array(Math.ceil(cells.length / 8) || 1);
  let nullCount = 0;
  for (let i = 0; i < cells.length; i++) {
    if (cells[i] === null) nullCount++;
    else nulls[i >> 3] |= 1 << (i & 7);
  }
  return { nulls: nullCount > 0 ? nulls : null, nullCount };
}

function columnData(arrow: Arrow, c: FactsColumn, type: ArrowNs.DataType, rows: readonly FactRow[], index: number, dictionary: ArrowNs.Vector | undefined): ArrowNs.Data {
  const n = rows.length;
  const cells = rows.map(r => r[index]);
  const v = validity(cells);
  if (v.nullCount > 0 && !c.nullable) throw new Error(`facts@1: null in non-nullable column ${c.name}`);
  const nullBitmap = v.nulls ?? undefined;
  switch (c.type) {
    case 'fixed16': {
      const data = new Uint8Array(n * FACTS_ID_WIDTH);
      for (let i = 0; i < n; i++) {
        const b = cells[i];
        if (b === null) continue;
        if (!(b instanceof Uint8Array) || b.length !== FACTS_ID_WIDTH) throw new Error(`facts@1: column ${c.name} expects ${FACTS_ID_WIDTH} id bytes`);
        data.set(b, i * FACTS_ID_WIDTH);
      }
      return arrow.makeData({ type: type as ArrowNs.FixedSizeBinary, length: n, nullCount: v.nullCount, nullBitmap, data });
    }
    case 'u32': {
      const data = new Uint32Array(n);
      for (let i = 0; i < n; i++) {
        const x = cells[i];
        if (x === null) continue;
        if (typeof x !== 'number' || !Number.isInteger(x) || x < 0 || x > 0xffffffff) throw new Error(`facts@1: column ${c.name} expects an unsigned 32-bit integer, got ${String(x)}`);
        data[i] = x;
      }
      return arrow.makeData({ type: type as ArrowNs.Uint32, length: n, nullCount: v.nullCount, nullBitmap, data });
    }
    case 'bool': {
      const data = new Uint8Array(Math.ceil(n / 8) || 1);
      for (let i = 0; i < n; i++) {
        const x = cells[i];
        if (x === null) continue;
        if (typeof x !== 'boolean') throw new Error(`facts@1: column ${c.name} expects a boolean`);
        if (x) data[i >> 3] |= 1 << (i & 7);
      }
      return arrow.makeData({ type: type as ArrowNs.Bool, length: n, nullCount: v.nullCount, nullBitmap, data });
    }
    case 'utf8': {
      const strings = cells.map(x => {
        if (x !== null && typeof x !== 'string') throw new Error(`facts@1: column ${c.name} expects a string`);
        return x;
      });
      const u = utf8Data(strings);
      return arrow.makeData({ type: type as ArrowNs.Utf8, length: n, nullCount: u.nullCount, nullBitmap: u.nulls ?? undefined, valueOffsets: u.offsets, data: u.bytes });
    }
    case 'dict': {
      const vocab = c.values as readonly string[];
      const indices = new Int8Array(n);
      for (let i = 0; i < n; i++) {
        const x = cells[i];
        if (x === null) continue;
        const k = typeof x === 'string' ? vocab.indexOf(x) : -1;
        if (k < 0) throw new Error(`facts@1: ${JSON.stringify(x)} is not in the ${c.name} vocabulary`);
        indices[i] = k;
      }
      return arrow.makeData({ type: type as ArrowNs.Dictionary<ArrowNs.Utf8, ArrowNs.Int8>, length: n, nullCount: v.nullCount, nullBitmap, data: indices, dictionary });
    }
  }
}

/** Arrow IPC file bytes for one relation's rows, which must already be in canonical order. */
export async function relationToArrowIpc(name: FactsRelationName, rows: readonly FactRow[], options: FactsArrowOptions = {}): Promise<{ bytes: Uint8Array; batches: number }> {
  const arrow = await loadArrow();
  const relation: FactsRelation = FACTS_RELATIONS[name];
  const types = relation.columns.map((c, i) => arrowType(arrow, c, i));
  const dictionaries = relation.columns.map(c => {
    if (c.type !== 'dict') return undefined;
    const u = utf8Data(c.values as readonly string[]);
    return arrow.makeVector(arrow.makeData({ type: new arrow.Utf8(), length: u.offsets.length - 1, nullCount: 0, valueOffsets: u.offsets, data: u.bytes }));
  });
  const fields = relation.columns.map((c, i) => new arrow.Field(c.name, types[i], c.nullable));
  const metadata = new Map<string, string>([['facts', FACTS_SCHEME], ['ids', 'ids@0.1']]);
  if (options.engine) metadata.set('engine', options.engine);
  if (options.parser) metadata.set('parser', options.parser);
  const schema = new arrow.Schema(fields, metadata);
  const batches: ArrowNs.RecordBatch[] = [];
  for (let start = 0; start < rows.length; start += FACTS_CHUNK_ROWS) {
    const chunk = rows.slice(start, start + FACTS_CHUNK_ROWS);
    for (const r of chunk) if (r.length !== relation.columns.length) throw new Error(`facts@1: a ${name} row has ${r.length} cells, the relation ${relation.columns.length} columns`);
    const children = relation.columns.map((c, i) => columnData(arrow, c, types[i], chunk, i, dictionaries[i]));
    const struct = arrow.makeData({ type: new arrow.Struct(fields), length: chunk.length, nullCount: 0, children });
    batches.push(new arrow.RecordBatch(schema, struct));
  }
  const table = new arrow.Table(schema, batches);
  const bytes = arrow.RecordBatchFileWriter.writeAll(table).toUint8Array(true);
  return { bytes, batches: batches.length };
}

/** Every relation as IPC file bytes plus the manifest. */
export async function factsToArrow(rows: FactRows, options: FactsArrowOptions = {}): Promise<FactsArrow> {
  const relations = {} as Record<FactsRelationName, Uint8Array>;
  const manifestRelations = {} as Record<FactsRelationName, FactsManifestRelation>;
  for (const name of FACTS_RELATION_NAMES) {
    const { bytes, batches } = await relationToArrowIpc(name, rows[name], options);
    relations[name] = bytes;
    manifestRelations[name] = { file: `${name}.arrow`, rows: rows[name].length, batches, bytes: bytes.length, blake3: base32(blake3(bytes)) };
  }
  const manifest: FactsManifest = {
    facts: FACTS_SCHEME,
    ids: 'ids@0.1',
    ...(options.source ? { source: options.source } : {}),
    ...(options.engine ? { engine: options.engine } : {}),
    ...(options.parser ? { parser: options.parser } : {}),
    chunk_rows: FACTS_CHUNK_ROWS,
    relations: manifestRelations,
  };
  return { scheme: FACTS_SCHEME, relations, manifest };
}
