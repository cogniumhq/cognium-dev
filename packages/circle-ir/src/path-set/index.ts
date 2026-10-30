/**
 * Path sets: every source-to-sink path of one CWE in an analysed tree, keyed
 * so a path is found again in another version of the tree, and the
 * difference between two versions with unresolved edges counted.
 */
export {
  pathSetOf,
  pathSetDiff,
  diffPathSets,
  pinFacts,
  pathKey,
  declAt,
  changeOf,
  normalizeCwe,
  lineDominates,
  handedNames,
} from './path-set.js';
export { deriveBranchFacts, sideOf } from './branches.js';
export { deriveTemplateFacts, templateEngineOf, expressionNames } from './templates.js';
export type { TemplateFact, TemplateEngine } from './templates.js';
export type { BranchFact, BranchCall, BranchRange, BranchSide } from './branches.js';
export type { PathSetInput, PathSetOptions } from './path-set.js';
export { PATH_KEY_SCHEME } from './types.js';
export type {
  DeclKeyScheme,
  DeclRef,
  PathHop,
  PathEnd,
  PathSource,
  PathSink,
  PathGuard,
  PathUnresolved,
  UnresolvedSite,
  TemplateUse,
  PathState,
  PathEntry,
  PathSet,
  PathChange,
  PathDiffEntry,
  PinFacts,
  PathSetDiff,
} from './types.js';
