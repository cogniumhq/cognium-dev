/**
 * `facts@1`: the fact relations as columns in canonical order (sets, no
 * nulls), keyed by `ids@0.1`, and their Arrow IPC wire form. Opt-in — see
 * `JavaGraphOptions.emitFacts`.
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
export { factsToArrow, relationToArrowIpc, loadArrow, hex } from './arrow.js';
export type { FactsArrow, FactsArrowOptions, FactsManifest, FactsManifestRelation } from './arrow.js';
