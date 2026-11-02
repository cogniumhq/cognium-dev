/**
 * `facts@1` tables → Arrow IPC file bytes, one file per relation, plus the
 * manifest. The wire form the graph store reads (graph-store design §3).
 *
 * `apache-arrow` is an optional dependency loaded on first use, so the library
 * keeps running where it is not installed (browser bundles leave it external)
 * and nothing is paid until a caller asks for facts. Determinism: Arrow JS
 * writes no timestamps or random ids, dictionary ids are assigned here by
 * column position (never by the library's global counter), the full
 * vocabulary is written as every dictionary, and batches are cut at
 * `FACTS_CHUNK_ROWS` after the canonical sort — two runs over the same facts
 * give identical bytes (locked by `tests/facts/arrow.test.ts`). Columns arrive
 * as typed arrays (`FactTable`), so a batch is buffer slices, not cells.
 */

import type * as ArrowNs from 'apache-arrow';
import { blake3 } from '../stable-ids/hash.js';
import {
  FACTS_CHUNK_ROWS,
  FACTS_ID_WIDTH,
  FACTS_RELATION_NAMES,
  FACTS_RELATIONS,
  FACTS_SCHEME,
  type FactRow,
  type FactsColumn,
  type FactsRelation,
  type FactsRelationName,
} from './schema.js';
import { canonicalTable, tableFromRows, type FactColumnData, type FactTable } from './table.js';
import type { FactSet } from './java-facts.js';

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
  /** Rows written (a set: after the dedupe). */
  rows: number;
  batches: number;
  bytes: number;
  /** blake3 of the IPC file bytes, hex: the cache key (the canonical row digest is the store's). */
  blake3: string;
  /** Exact duplicate rows dropped after the canonical sort (relations are sets). */
  duplicates_dropped: number;
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

const HEX = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));

/** Lowercase hex of the bytes. */
export function hex(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += HEX[bytes[i]];
  return s;
}

function arrowType(arrow: Arrow, c: FactsColumn, dictionaryId: number): ArrowNs.DataType {
  switch (c.type) {
    case 'fixed16': return new arrow.FixedSizeBinary(FACTS_ID_WIDTH);
    case 'u32': return new arrow.Uint32();
    case 'utf8': return new arrow.Utf8();
    case 'bool': return new arrow.Bool();
    case 'dict': return new arrow.Dictionary(new arrow.Utf8(), new arrow.Int8(), dictionaryId, false);
  }
}

/** Arrow Utf8 buffers for `strings[start, end)`: offsets and the UTF-8 bytes, encoded in place into one buffer. */
function utf8Data(strings: readonly string[], start: number, end: number): { offsets: Int32Array; bytes: Uint8Array } {
  const n = end - start;
  const offsets = new Int32Array(n + 1);
  let bound = 0;
  for (let i = start; i < end; i++) bound += strings[i].length * 3;
  const buffer = new Uint8Array(bound);
  let total = 0;
  for (let i = 0; i < n; i++) {
    const s = strings[start + i];
    if (s.length > 0) total += encoder.encodeInto(s, buffer.subarray(total)).written;
    offsets[i + 1] = total;
  }
  return { offsets, bytes: buffer.subarray(0, total) };
}

function bitmap(flags: Uint8Array, start: number, end: number): Uint8Array {
  const n = end - start;
  const out = new Uint8Array(Math.ceil(n / 8) || 1);
  for (let i = 0; i < n; i++) if (flags[start + i] !== 0) out[i >> 3] |= 1 << (i & 7);
  return out;
}

function columnData(arrow: Arrow, c: FactsColumn, type: ArrowNs.DataType, data: FactColumnData, start: number, end: number, dictionary: ArrowNs.Vector | undefined): ArrowNs.Data {
  const n = end - start;
  switch (c.type) {
    case 'fixed16':
      return arrow.makeData({ type: type as ArrowNs.FixedSizeBinary, length: n, nullCount: 0, data: (data as Uint8Array).subarray(start * FACTS_ID_WIDTH, end * FACTS_ID_WIDTH) });
    case 'u32':
      return arrow.makeData({ type: type as ArrowNs.Uint32, length: n, nullCount: 0, data: (data as Uint32Array).subarray(start, end) });
    case 'bool':
      return arrow.makeData({ type: type as ArrowNs.Bool, length: n, nullCount: 0, data: bitmap(data as Uint8Array, start, end) });
    case 'utf8': {
      const u = utf8Data(data as string[], start, end);
      return arrow.makeData({ type: type as ArrowNs.Utf8, length: n, nullCount: 0, valueOffsets: u.offsets, data: u.bytes });
    }
    case 'dict':
      return arrow.makeData({ type: type as ArrowNs.Dictionary<ArrowNs.Utf8, ArrowNs.Int8>, length: n, nullCount: 0, data: (data as Int8Array).subarray(start, end), dictionary });
  }
}

function isTable(x: FactTable | readonly FactRow[]): x is FactTable {
  return !Array.isArray(x);
}

/**
 * Arrow IPC file bytes for one relation. A `FactTable` is written as given
 * (it must already be canonical: sorted, no duplicates); rows in the row form
 * are put in canonical form first (sorted and deduplicated).
 */
export async function relationToArrowIpc(name: FactsRelationName, input: FactTable | readonly FactRow[], options: FactsArrowOptions = {}): Promise<{ bytes: Uint8Array; batches: number; rows: number; duplicatesDropped: number }> {
  const arrow = await loadArrow();
  const relation: FactsRelation = FACTS_RELATIONS[name];
  let table: FactTable;
  let duplicatesDropped = 0;
  if (isTable(input)) {
    if (input.columns.length !== relation.columns.length) throw new Error(`facts@1: a ${name} table has ${input.columns.length} columns, the relation ${relation.columns.length}`);
    table = input;
  } else {
    const c = canonicalTable(relation, tableFromRows(relation, input).columns, input.length);
    table = c.table;
    duplicatesDropped = c.duplicatesDropped;
  }
  const types = relation.columns.map((c, i) => arrowType(arrow, c, i));
  const dictionaries = relation.columns.map(c => {
    if (c.type !== 'dict') return undefined;
    const vocab = c.values as readonly string[];
    const u = utf8Data(vocab, 0, vocab.length);
    return arrow.makeVector(arrow.makeData({ type: new arrow.Utf8(), length: vocab.length, nullCount: 0, valueOffsets: u.offsets, data: u.bytes }));
  });
  const fields = relation.columns.map((c, i) => new arrow.Field(c.name, types[i], c.nullable));
  const metadata = new Map<string, string>([['facts', FACTS_SCHEME], ['ids', 'ids@0.1']]);
  if (options.engine) metadata.set('engine', options.engine);
  if (options.parser) metadata.set('parser', options.parser);
  const schema = new arrow.Schema(fields, metadata);
  const batches: ArrowNs.RecordBatch[] = [];
  for (let start = 0; start < table.length; start += FACTS_CHUNK_ROWS) {
    const end = Math.min(start + FACTS_CHUNK_ROWS, table.length);
    const children = relation.columns.map((c, i) => columnData(arrow, c, types[i], table.columns[i], start, end, dictionaries[i]));
    const struct = arrow.makeData({ type: new arrow.Struct(fields), length: end - start, nullCount: 0, children });
    batches.push(new arrow.RecordBatch(schema, struct));
  }
  const bytes = arrow.RecordBatchFileWriter.writeAll(new arrow.Table(schema, batches)).toUint8Array(true);
  return { bytes, batches: batches.length, rows: table.length, duplicatesDropped };
}

/**
 * Every relation as IPC file bytes plus the manifest. Takes the emitter's
 * `FactSet` (canonical tables with their dedupe counts) or a record of
 * relations in either form.
 */
export async function factsToArrow(input: FactSet | Readonly<Record<FactsRelationName, FactTable | readonly FactRow[]>>, options: FactsArrowOptions = {}): Promise<FactsArrow> {
  const set = 'relations' in input && 'duplicatesDropped' in input ? (input as FactSet) : undefined;
  const relations = {} as Record<FactsRelationName, Uint8Array>;
  const manifestRelations = {} as Record<FactsRelationName, FactsManifestRelation>;
  for (const name of FACTS_RELATION_NAMES) {
    const data = set ? set.relations[name] : (input as Record<FactsRelationName, FactTable | readonly FactRow[]>)[name];
    const { bytes, batches, rows, duplicatesDropped } = await relationToArrowIpc(name, data, options);
    relations[name] = bytes;
    manifestRelations[name] = {
      file: `${name}.arrow`,
      rows,
      batches,
      bytes: bytes.length,
      blake3: hex(blake3(bytes)),
      duplicates_dropped: set ? set.duplicatesDropped[name] : duplicatesDropped,
    };
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
