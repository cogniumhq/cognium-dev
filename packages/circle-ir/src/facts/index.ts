/**
 * `facts@1` and `facts@2`: the fact relations as columns in canonical order
 * (sets, no nulls), keyed by `ids@0.1`, and their Arrow IPC wire form.
 * Opt-in — see `JavaGraphOptions.emitFacts`; `facts@1` is the default scheme,
 * `facts@2` is chosen with `JavaGraphOptions.factsScheme`.
 */

export {
  FACTS_SCHEME,
  FACTS_ID_WIDTH,
  FACTS_CHUNK_ROWS,
  FACTS_RELATION_NAMES,
  FACTS_RELATIONS,
  FACTS_LANGUAGES,
  FACTS_DECL_KINDS,
  FACTS_TIERS,
  FACTS_UNRESOLVED_REASONS,
  FACTS_FLOW_KINDS,
  FACTS_ENTRY_KINDS,
  FACTS_ENTRY_CERTAINTIES,
  FACTS_MOVE_KINDS,
  sortColumns,
} from './schema.js';
export type { FactsScheme, FactsColumnType, FactsColumn, FactsRelation, FactsRelationName, FactValue, FactRow, FactRows } from './schema.js';
export { compareBytes, compareCodePoints, compareValues, rowComparator, canonicalRows, canonicalSet, idBytes } from './order.js';
export { IdDecoder, allocColumn, allocTable, dictIndex, idBytesInto, compareStrings, tableComparator, canonicalTable, keyCollisions, tableRow, tableRows, tableFromRows } from './table.js';
export type { FactColumnData, FactTable } from './table.js';
export { javaGraphFacts, javaGraphFactSet, contentHash, factsEntryKind } from './java-facts.js';
export type { JavaImportRow, JavaFactsInput, FactSet } from './java-facts.js';
export { factsToArrow, relationToArrowIpc, facts2ToArrow, relation2ToArrowIpc, loadArrow, hex } from './arrow.js';
export type { FactsArrow, FactsArrowOptions, FactsManifest, FactsManifestRelation, Facts2Arrow, Facts2Manifest } from './arrow.js';
export {
  FACTS2_SCHEME,
  FACTS2_RELATION_NAMES,
  FACTS2_RELATIONS,
  FACTS2_STORE_ONLY,
  FACTS_REGISTRATION_REASONS,
  FACTS_FILE_KEY_PARTS,
  fileKey,
} from './schema2.js';
export type { Facts2Scheme, Facts2Relation, Facts2RelationName, Fact2Rows } from './schema2.js';
export { javaGraphFact2Set, tsGraphFact2Set } from './facts2.js';
export type { Fact2Set, Facts2Graph, Facts2Input } from './facts2.js';
export { T6Graph, t6RowsFromArrow } from './t6.js';
export type { T6Rows, T6Tier, T6EdgeCounts } from './t6.js';
