/**
 * Graph facts over stable ids: the reach core and the answers built on it.
 * Experimental and opt-in; `analyze()` does not call them.
 */

export {
  REACH_SCHEME,
  ALL_ENTRY_KINDS,
  ReachGraph,
  reach,
  walkFrom,
  reachedIds,
  couldReach,
  type ReachInput,
  type ReachSite,
  type ReachOptions,
  type ReachResult,
  type ReachFact,
  type ReachPath,
  type PathStep,
  type EdgeRelation,
  type CouldReachSite,
} from './reach.js';
export {
  DEAD_CODE_SCHEME,
  deadCode,
  type DeadCodeVerdict,
  type MayBeLiveReason,
  type DeadCodeFact,
  type DeadCodeOptions,
  type DeadCodeResult,
} from './dead-code.js';
export {
  REMOVAL_REACH_SCHEME,
  removalReach,
  entryIndexDigest,
  type RemovedDeclaration,
  type MoveCandidateRef,
  type RemovalReachOptions,
  type RemovalReachResult,
} from './removal-reach.js';
