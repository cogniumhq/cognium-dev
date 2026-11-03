/**
 * `facts@1` and `facts@2` tables → Arrow IPC file bytes, one file per
 * relation, plus the manifest. The wire form the graph store reads
 * (graph-store design §3). The two schemes share the writer; only the
 * relation table and the `facts` metadata value differ.
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
import { FACTS2_RELATION_NAMES, FACTS2_RELATIONS, FACTS2_SCHEME, type Facts2RelationName, type Facts2Scheme } from './schema2.js';
import { canonicalTable, tableFromRows, type FactColumnData, type FactTable } from './table.js';
import type { FactSet } from './java-facts.js';
import type { Fact2Set } from './facts2.js';

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

/** The `facts@2` manifest: the `facts@1` fields, over the twelve `facts@2` relations. */
export interface Facts2Manifest {
  facts: Facts2Scheme;
  ids: 'ids@0.1';
  source?: string;
  engine?: string;
  parser?: string;
  chunk_rows: number;
  relations: Record<Facts2RelationName, FactsManifestRelation>;
}

export interface Facts2Arrow {
  scheme: Facts2Scheme;
  /** Arrow IPC *file* bytes per relation, in canonical order, `facts@2` schema. */
  relations: Record<Facts2RelationName, Uint8Array>;
  manifest: Facts2Manifest;
}

/** One scheme's relation table, as the writer reads it. */
interface SchemeSpec<S extends string, N extends string> {
  scheme: S;
  names: readonly N[];
  relations: Readonly<Record<N, FactsRelation>>;
}

const FACTS1_SPEC: SchemeSpec<typeof FACTS_SCHEME, FactsRelationName> = { scheme: FACTS_SCHEME, names: FACTS_RELATION_NAMES, relations: FACTS_RELATIONS };
const FACTS2_SPEC: SchemeSpec<Facts2Scheme, Facts2RelationName> = { scheme: FACTS2_SCHEME, names: FACTS2_RELATION_NAMES, relations: FACTS2_RELATIONS };

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

interface RelationIpc {
  bytes: Uint8Array;
  batches: number;
  rows: number;
  duplicatesDropped: number;
}

/**
 * Arrow IPC file bytes for one relation. A `FactTable` is written as given
 * (it must already be canonical: sorted, no duplicates); rows in the row form
 * are put in canonical form first (sorted and deduplicated).
 */
export async function relationToArrowIpc(name: FactsRelationName, input: FactTable | readonly FactRow[], options: FactsArrowOptions = {}): Promise<RelationIpc> {
  return writeRelation(FACTS1_SPEC, name, input, options);
}

/** `relationToArrowIpc` for a `facts@2` relation: the `facts@2` columns and `facts` metadata value. */
export async function relation2ToArrowIpc(name: Facts2RelationName, input: FactTable | readonly FactRow[], options: FactsArrowOptions = {}): Promise<RelationIpc> {
  return writeRelation(FACTS2_SPEC, name, input, options);
}

async function writeRelation<S extends string, N extends string>(spec: SchemeSpec<S, N>, name: N, input: FactTable | readonly FactRow[], options: FactsArrowOptions): Promise<RelationIpc> {
  const arrow = await loadArrow();
  const relation: FactsRelation | undefined = spec.relations[name];
  if (!relation) throw new Error(`${spec.scheme}: no relation ${String(name)}`);
  let table: FactTable;
  let duplicatesDropped = 0;
  if (isTable(input)) {
    if (input.columns.length !== relation.columns.length) throw new Error(`${spec.scheme}: a ${name} table has ${input.columns.length} columns, the relation ${relation.columns.length}`);
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
  const metadata = new Map<string, string>([['facts', spec.scheme], ['ids', 'ids@0.1']]);
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
  const { relations, manifest } = await writeAll(FACTS1_SPEC, input, options);
  return { scheme: FACTS_SCHEME, relations, manifest: { facts: FACTS_SCHEME, ...manifest } };
}

/**
 * Every `facts@2` relation as IPC file bytes plus the manifest. Takes the
 * `facts@2` emitter's `Fact2Set` or a record of the twelve relations in
 * either form.
 */
export async function facts2ToArrow(input: Fact2Set | Readonly<Record<Facts2RelationName, FactTable | readonly FactRow[]>>, options: FactsArrowOptions = {}): Promise<Facts2Arrow> {
  const { relations, manifest } = await writeAll(FACTS2_SPEC, input, options);
  return { scheme: FACTS2_SCHEME, relations, manifest: { facts: FACTS2_SCHEME, ...manifest } };
}

interface SetLike<N extends string> {
  relations: Readonly<Record<N, FactTable>>;
  duplicatesDropped: Readonly<Record<N, number>>;
}

async function writeAll<S extends string, N extends string>(
  spec: SchemeSpec<S, N>,
  input: SetLike<N> | Readonly<Record<N, FactTable | readonly FactRow[]>>,
  options: FactsArrowOptions,
): Promise<{ relations: Record<N, Uint8Array>; manifest: Omit<FactsManifest, 'facts' | 'relations'> & { relations: Record<N, FactsManifestRelation> } }> {
  const set = 'relations' in input && 'duplicatesDropped' in input ? (input as SetLike<N>) : undefined;
  const relations = {} as Record<N, Uint8Array>;
  const manifestRelations = {} as Record<N, FactsManifestRelation>;
  for (const name of spec.names) {
    const data = set ? set.relations[name] : (input as Readonly<Record<N, FactTable | readonly FactRow[]>>)[name];
    if (data === undefined) throw new Error(`${spec.scheme}: relation ${name} is missing`);
    const { bytes, batches, rows, duplicatesDropped } = await writeRelation(spec, name, data, options);
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
  const manifest = {
    ids: 'ids@0.1' as const,
    ...(options.source ? { source: options.source } : {}),
    ...(options.engine ? { engine: options.engine } : {}),
    ...(options.parser ? { parser: options.parser } : {}),
    chunk_rows: FACTS_CHUNK_ROWS,
    relations: manifestRelations,
  };
  return { relations, manifest };
}
