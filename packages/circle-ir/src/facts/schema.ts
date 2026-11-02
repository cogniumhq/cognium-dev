/**
 * `facts@1` — PROPOSED. The fact relations circle-ir owes a graph store, as
 * columns in canonical order keyed by `ids@0.1` (graph-store plan 0.1, T1).
 *
 * This module mirrors `schemas/facts@1.json` field for field;
 * `tests/facts/schema.test.ts` fails when the two drift. The JSON file is the
 * document other implementations read; this module is what the emitter and
 * the comparator run on. Nothing in `analyze()` or `buildJavaGraph()` touches
 * it unless a caller asks for facts.
 */

export const FACTS_SCHEME = 'facts@1' as const;
export type FactsScheme = typeof FACTS_SCHEME;

/** Width in bytes of an `ids@0.1` id in a column (128 bits). */
export const FACTS_ID_WIDTH = 16;

/** Rows per record batch after the canonical sort. */
export const FACTS_CHUNK_ROWS = 65536;

export type FactsColumnType = 'fixed16' | 'u32' | 'utf8' | 'bool' | 'dict';

export interface FactsColumn {
  readonly name: string;
  readonly type: FactsColumnType;
  readonly nullable: boolean;
  /** `dict` columns: the whole vocabulary, in dictionary order. */
  readonly values?: readonly string[];
}

export interface FactsRelation {
  /** Sort keys, in order. The remaining columns follow in schema order. */
  readonly key: readonly string[];
  readonly columns: readonly FactsColumn[];
}

export const FACTS_RELATION_NAMES = ['files', 'decl', 'call', 'unresolved', 'flow', 'imports', 'entries', 'moved'] as const;
export type FactsRelationName = (typeof FACTS_RELATION_NAMES)[number];

export const FACTS_LANGUAGES = ['java', 'typescript', 'javascript', 'python', 'go'] as const;
export const FACTS_DECL_KINDS = ['module', 'type', 'method', 'field', 'function'] as const;
export const FACTS_TIERS = ['exact', 'polymorphic', 'inferred'] as const;
export const FACTS_UNRESOLVED_REASONS = ['external', 'dynamic', 'generated', 'overload-ambiguous', 'parse-error', 'unsupported-language', 'unknown'] as const;
export const FACTS_FLOW_KINDS = ['def-use', 'taint'] as const;
export const FACTS_ENTRY_KINDS = ['main', 'route', 'listener', 'scheduled', 'export', 'bean', 'di', 'reflection', 'lifecycle', 'test', 'osgi-ds', 'extension-point', 'data-declared', 'script'] as const;
export const FACTS_ENTRY_CERTAINTIES = ['declared', 'conventional', 'inferred'] as const;
export const FACTS_MOVE_KINDS = ['moved', 'renamed'] as const;

const col = (name: string, type: FactsColumnType, nullable = false, values?: readonly string[]): FactsColumn =>
  values ? { name, type, nullable, values } : { name, type, nullable };

export const FACTS_RELATIONS: Readonly<Record<FactsRelationName, FactsRelation>> = {
  files: {
    key: ['file_id'],
    columns: [
      col('file_id', 'u32'),
      col('path', 'utf8'),
      col('content_hash', 'fixed16'),
      col('language', 'dict', false, FACTS_LANGUAGES),
    ],
  },
  decl: {
    key: ['id'],
    columns: [
      col('id', 'fixed16'),
      col('kind', 'dict', false, FACTS_DECL_KINDS),
      col('qualified_name', 'utf8'),
      col('signature', 'utf8'),
      col('file_id', 'u32'),
      col('line', 'u32'),
      col('body_hash', 'fixed16', true),
    ],
  },
  call: {
    key: ['caller_id', 'site_file', 'site_line', 'site_col', 'callee_id'],
    columns: [
      col('caller_id', 'fixed16'),
      col('callee_id', 'fixed16'),
      col('tier', 'dict', false, FACTS_TIERS),
      col('method_name', 'utf8'),
      col('site_file', 'u32'),
      col('site_line', 'u32'),
      col('site_col', 'u32'),
    ],
  },
  unresolved: {
    key: ['site_file', 'site_line', 'site_col'],
    columns: [
      col('caller_id', 'fixed16'),
      col('reason', 'dict', false, FACTS_UNRESOLVED_REASONS),
      col('receiver', 'utf8', true),
      col('method_name', 'utf8'),
      col('site_file', 'u32'),
      col('site_line', 'u32'),
      col('site_col', 'u32'),
    ],
  },
  flow: {
    key: ['from_id', 'to_id', 'kind'],
    columns: [
      col('from_id', 'fixed16'),
      col('to_id', 'fixed16'),
      col('kind', 'dict', false, FACTS_FLOW_KINDS),
    ],
  },
  imports: {
    key: ['file_id', 'target'],
    columns: [
      col('file_id', 'u32'),
      col('target', 'utf8'),
      col('wildcard', 'bool'),
    ],
  },
  entries: {
    key: ['decl_id', 'kind', 'source'],
    columns: [
      col('decl_id', 'fixed16'),
      col('kind', 'dict', false, FACTS_ENTRY_KINDS),
      col('source', 'utf8'),
      col('certainty', 'dict', false, FACTS_ENTRY_CERTAINTIES),
    ],
  },
  moved: {
    key: ['old_id', 'new_id'],
    columns: [
      col('old_id', 'fixed16'),
      col('new_id', 'fixed16'),
      col('kind', 'dict', false, FACTS_MOVE_KINDS),
      col('evidence', 'utf8'),
    ],
  },
};

/** The column indexes a relation sorts by: its key columns, then every other column in schema order. */
export function sortColumns(relation: FactsRelation): number[] {
  const names = relation.columns.map(c => c.name);
  const keys = relation.key.map(k => {
    const i = names.indexOf(k);
    if (i < 0) throw new Error(`facts@1: key column ${k} is not a column`);
    return i;
  });
  return [...keys, ...names.map((_, i) => i).filter(i => !keys.includes(i))];
}

/**
 * A cell: 16 id bytes, an unsigned 32-bit integer, a string (utf8 and dict
 * columns alike), a boolean, or null on a nullable column.
 */
export type FactValue = Uint8Array | number | string | boolean | null;

/** One row, cells in schema column order. */
export type FactRow = readonly FactValue[];

export type FactRows = Readonly<Record<FactsRelationName, FactRow[]>>;
