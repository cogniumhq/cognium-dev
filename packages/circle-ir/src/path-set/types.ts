/**
 * Types for path sets: every source-to-sink path of one weakness class (CWE)
 * in one analysed tree, keyed so the same path can be found again in another
 * version of the tree.
 */

import type { SinkType, SourceType } from '../types/index.js';

/** Scheme of every path key this module prints. */
export const PATH_KEY_SCHEME = 'path@0.1' as const;

/**
 * How a declaration was identified.
 * - `ids@0.1`: the stable declaration id (TypeScript/JavaScript, when the caller supplies ids).
 * - `qualified@0.1`: `<repo-relative file>#<package.Type$Inner>.<method>(<parameter types>)`
 *   built from the IR's types (Java and any language without stable ids).
 */
export type DeclKeyScheme = 'ids@0.1' | 'qualified@0.1';

export interface DeclRef {
  scheme: DeclKeyScheme;
  /** The stable id, or the qualified key. Never contains a line number. */
  id: string;
  /** Readable name (qualified name); for display only. */
  name: string;
}

export interface PathHop {
  file: string;
  line: number;
  method?: string;
  variable?: string;
}

export interface PathEnd {
  /** Pin-independent anchor: declaration, call shape, ordinal. */
  anchor: string;
  decl: DeclRef;
  file: string;
  /** Line at this pin; not part of any key. */
  line: number;
  code?: string;
}

export interface PathSource extends PathEnd {
  type: SourceType;
}

export interface PathSink extends PathEnd {
  type: SinkType;
  cwe: string;
  /** The sink call as the IR records it (receiver class simple name, method, tainted arguments). */
  call: { class?: string; method?: string; argPositions?: number[] };
}

/** A path's state at one pin. `sanitized` = every variant passes a sanitizer. */
export type PathState = 'absent' | 'sanitized' | 'present';

export interface PathEntry {
  /** `digest128` of scheme, CWE and both anchors. */
  key: string;
  cwe: string;
  source: PathSource;
  sink: PathSink;
  state: Exclude<PathState, 'absent'>;
  /** Distinct (source line, sink line) pairs that share this key at this pin. */
  variants: number;
  /** Hops of the first variant (by source then sink position). */
  hops: PathHop[];
  confidence: number;
}

export interface PathSet {
  scheme: typeof PATH_KEY_SCHEME;
  cwe: string;
  /** Sorted by key. */
  paths: PathEntry[];
  /** Declaration key schemes used, sorted. */
  declKeySchemes: DeclKeyScheme[];
  /** Files holding a source, sink or hop of a path, sorted. */
  files: string[];
}

/** The set change of one key between two pins: a set operation, not a judgement. */
export type PathChange = 'removed' | 'sanitized' | 'unchanged' | 'added' | 'other';

export interface PathDiffEntry {
  key: string;
  state: { before: PathState; after: PathState };
  change: PathChange;
  before?: PathEntry;
  after?: PathEntry;
}

export interface PinFacts {
  pathCount: number;
  unresolved: {
    /** Over the whole tree. */
    total: number;
    byType: Record<'virtual_dispatch' | 'taint_propagation' | 'reflection' | 'dynamic_call', number>;
    /** Restricted to files that hold a source, sink or hop of a class path at either pin. */
    onPathFiles: number;
  };
  /** Cross-file calls with `resolved: false` that start or end in a path file. */
  crossFileCallsUnresolved: number;
  /** `false` when any analysis budget was hit or a path file failed to parse cleanly. */
  complete: boolean;
  /** Names of the budget flags hit, and `parse-error:<file>` for each path file with a partial parse; sorted. */
  flags: string[];
}

export interface PathSetDiff {
  scheme: typeof PATH_KEY_SCHEME;
  cwe: string;
  /** Sorted by key. */
  entries: PathDiffEntry[];
  counts: Record<PathChange, number>;
  pins: { before: PinFacts; after: PinFacts };
}
