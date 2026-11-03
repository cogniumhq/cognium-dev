/**
 * `facts@2` — the successor of `facts@1`, published as a major in one step.
 * Against `facts@1`: site positions are relative to the enclosing
 * declaration's start line and carry no file (`rel_line`, `col`); declaration
 * positions move to `decl_pos`; a stable file key (`file`, fixed16, a digest
 * of the path) replaces the dense `file_id` in every relation that names a
 * file; `decl` gains `name`, `parent_id` and the structural flags; new
 * relations `decl_pos`, `ref`, `registration`, `parse_error`; and every
 * relation states whether it is store-only (written and read for rendering,
 * not loaded into the engine unless a rule names it).
 *
 * Everything else is as in `facts@1`: 128-bit ids, sets with no nulls, the
 * total canonical order, fixed-size chunks, the column types and the
 * vocabularies that survive.
 *
 * This module mirrors `schemas/facts@2.json` field for field;
 * `tests/facts/schema2.test.ts` fails when the two drift. `facts@1`
 * (`schema.ts`) stays the producer's default: `facts@2` is emitted only when
 * a caller asks for it (`JavaGraphOptions.factsScheme`).
 */

import { digest128Bytes } from '../stable-ids/hash.js';
import { STABLE_ID_SCHEME } from '../stable-ids/types.js';
import {
  FACTS_DECL_KINDS,
  FACTS_ENTRY_CERTAINTIES,
  FACTS_ENTRY_KINDS,
  FACTS_FLOW_KINDS,
  FACTS_LANGUAGES,
  FACTS_MOVE_KINDS,
  FACTS_TIERS,
  FACTS_UNRESOLVED_REASONS,
  type FactRow,
  type FactsColumn,
  type FactsColumnType,
  type FactsRelation,
} from './schema.js';

export const FACTS2_SCHEME = 'facts@2' as const;
export type Facts2Scheme = typeof FACTS2_SCHEME;

/** A `facts@2` relation: a `facts@1` relation shape plus whether a store loads it into the engine. */
export interface Facts2Relation extends FactsRelation {
  /** Written to the snapshot, digested and read back, but not loaded into the engine unless a rule names it. */
  readonly storeOnly: boolean;
}

export const FACTS2_RELATION_NAMES = [
  'files',
  'decl',
  'decl_pos',
  'call',
  'unresolved',
  'ref',
  'registration',
  'parse_error',
  'flow',
  'imports',
  'entries',
  'moved',
] as const;
export type Facts2RelationName = (typeof FACTS2_RELATION_NAMES)[number];

/** Why a registration the recognizers saw could not be tied to a declaration. */
export const FACTS_REGISTRATION_REASONS = ['handler-unresolved', 'manifest-unresolved', 'mount-unresolved'] as const;

/** The parts of a stable file key, `<path>` standing for `files.path`. */
export const FACTS_FILE_KEY_PARTS = [STABLE_ID_SCHEME, 'file', '<path>'] as const;

/**
 * The stable file key of a repository-relative, `/`-separated path:
 * `digest128(["ids@0.1", "file", path])` as 16 bytes. A function of the path
 * and nothing else, so adding, removing or moving one file re-keys only that
 * file's rows.
 */
export function fileKey(path: string): Uint8Array {
  return digest128Bytes([STABLE_ID_SCHEME, 'file', path]);
}

const col = (name: string, type: FactsColumnType, values?: readonly string[]): FactsColumn =>
  values ? { name, type, nullable: false, values } : { name, type, nullable: false };

export const FACTS2_RELATIONS: Readonly<Record<Facts2RelationName, Facts2Relation>> = {
  files: {
    key: ['file'],
    storeOnly: false,
    columns: [
      col('file', 'fixed16'),
      col('path', 'utf8'),
      col('content_hash', 'fixed16'),
      col('language', 'dict', FACTS_LANGUAGES),
      col('partial', 'bool'),
    ],
  },
  decl: {
    key: ['id'],
    storeOnly: false,
    columns: [
      col('id', 'fixed16'),
      col('kind', 'dict', FACTS_DECL_KINDS),
      col('name', 'utf8'),
      col('qualified_name', 'utf8'),
      col('signature', 'utf8'),
      col('file', 'fixed16'),
      col('parent_id', 'fixed16'),
      col('body_hash', 'fixed16'),
      col('type_only', 'bool'),
      col('anonymous', 'bool'),
      col('duplicate', 'bool'),
      col('contained', 'bool'),
      col('loads_parent', 'bool'),
    ],
  },
  decl_pos: {
    key: ['id'],
    storeOnly: true,
    columns: [
      col('id', 'fixed16'),
      col('line', 'u32'),
      col('end_line', 'u32'),
      col('col', 'u32'),
      col('end_col', 'u32'),
    ],
  },
  call: {
    key: ['caller_id', 'rel_line', 'col', 'callee_id'],
    storeOnly: false,
    columns: [
      col('caller_id', 'fixed16'),
      col('callee_id', 'fixed16'),
      col('tier', 'dict', FACTS_TIERS),
      col('method_name', 'utf8'),
      col('rel_line', 'u32'),
      col('col', 'u32'),
      col('declaring', 'bool'),
    ],
  },
  unresolved: {
    key: ['caller_id', 'rel_line', 'col', 'method_name', 'receiver', 'reason'],
    storeOnly: false,
    columns: [
      col('caller_id', 'fixed16'),
      col('reason', 'dict', FACTS_UNRESOLVED_REASONS),
      col('receiver', 'utf8'),
      col('method_name', 'utf8'),
      col('rel_line', 'u32'),
      col('col', 'u32'),
    ],
  },
  ref: {
    key: ['from_id', 'rel_line', 'col', 'to_id'],
    storeOnly: false,
    columns: [
      col('from_id', 'fixed16'),
      col('to_id', 'fixed16'),
      col('rel_line', 'u32'),
      col('col', 'u32'),
    ],
  },
  registration: {
    key: ['from_id', 'rel_line', 'col', 'reason'],
    storeOnly: false,
    columns: [
      col('from_id', 'fixed16'),
      col('reason', 'dict', FACTS_REGISTRATION_REASONS),
      col('evidence', 'utf8'),
      col('rel_line', 'u32'),
      col('col', 'u32'),
    ],
  },
  parse_error: {
    key: ['file'],
    storeOnly: true,
    columns: [
      col('file', 'fixed16'),
      col('line', 'u32'),
      col('col', 'u32'),
      col('node_kind', 'utf8'),
      col('parent_kind', 'utf8'),
    ],
  },
  flow: {
    key: ['from_id', 'to_id', 'kind'],
    storeOnly: false,
    columns: [
      col('from_id', 'fixed16'),
      col('to_id', 'fixed16'),
      col('kind', 'dict', FACTS_FLOW_KINDS),
    ],
  },
  imports: {
    key: ['file', 'target', 'wildcard'],
    storeOnly: false,
    columns: [
      col('file', 'fixed16'),
      col('target', 'utf8'),
      col('wildcard', 'bool'),
    ],
  },
  entries: {
    key: ['decl_id', 'kind', 'source'],
    storeOnly: false,
    columns: [
      col('decl_id', 'fixed16'),
      col('kind', 'dict', FACTS_ENTRY_KINDS),
      col('source', 'utf8'),
      col('certainty', 'dict', FACTS_ENTRY_CERTAINTIES),
    ],
  },
  moved: {
    key: ['old_id', 'new_id'],
    storeOnly: false,
    columns: [
      col('old_id', 'fixed16'),
      col('new_id', 'fixed16'),
      col('kind', 'dict', FACTS_MOVE_KINDS),
      col('evidence', 'utf8'),
    ],
  },
};

/** The store-only relations, in schema order. */
export const FACTS2_STORE_ONLY: readonly Facts2RelationName[] = FACTS2_RELATION_NAMES.filter(n => FACTS2_RELATIONS[n].storeOnly);

export type Fact2Rows = Readonly<Record<Facts2RelationName, FactRow[]>>;
