/**
 * Navigation queries — callers and callees, each answer carrying how it was
 * reached and each non-answer carrying why. See `navigation-index.ts`.
 */

export { buildNavigationIndex, NavigationIndex } from './navigation-index.js';
export type { NavigationFile, BuildOptions, IndexedCallSite, IndexedTarget } from './navigation-index.js';
export type {
  AnswerEntry,
  CallSite,
  NavigationAnswer,
  Query,
  QueryKind,
  QueryOptions,
  Scope,
  Tier,
  Timing,
  UnresolvedEntry,
  UnresolvedReason,
} from './types.js';

export {
  buildTsCallGraph,
  TS_CALL_EDGES_SCHEME,
  type TsSourceFile,
  type TsCallGraphOptions,
  type TsCallGraph,
  type CallEdge,
  type CallEdgeSite,
  type UnresolvedCall,
  joinRoutePath,
  type TsPackageManifest,
  type TsEntry,
  type UnresolvedRegistration,
  type ReferenceEdge,
  type ImportEdge,
} from './ts-call-edges.js';
export {
  DEFAULT_ENTRY_TABLES,
  type EntryKind,
  type EntryCertainty,
  type EntryTables,
  type RouteRegistrarTable,
  type DecoratorEntryRow,
  type TestRunnerTable,
} from './ts-entry-tables.js';
export {
  buildJavaGraph,
  JAVA_GRAPH_SCHEME,
  type JavaSourceFile,
  type JavaGraphOptions,
  type JavaGraph,
} from './java-graph.js';
export {
  DEFAULT_JAVA_ENTRY_TABLES,
  type JavaEntryTables,
  type JavaAnnotationRow,
  type JavaRouteRow,
  type JavaServletRow,
} from './java-entry-tables.js';
