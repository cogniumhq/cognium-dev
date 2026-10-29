/**
 * Navigation queries — callers and callees, each answer carrying how it was
 * reached and each non-answer carrying why. See `navigation-index.ts`.
 */

export { buildNavigationIndex, NavigationIndex } from './navigation-index.js';
export type { NavigationFile, BuildOptions } from './navigation-index.js';
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
} from './ts-call-edges.js';
