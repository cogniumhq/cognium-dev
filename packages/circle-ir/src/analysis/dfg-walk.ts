/**
 * DFG walk primitives.
 *
 * cognium-dev #238 — sanitizer credit failure fix.
 *
 * The taint-propagation engine originally credited a sanitizer only when its
 * line matched the exact line the taint hop was landing on. Idiomatic
 * sanitize-then-sink chains (`safe = escape(x); sink(safe);`) never received
 * credit because `escape` lives on a different line than `sink`.
 *
 * `walkBackwardDefs` performs a bounded backward BFS along the DFG chain from
 * a starting def id, collecting every ancestor def line visited. Callers use
 * that set to check for sanitizer coverage anywhere along the reaching-def
 * chain of a sink use.
 *
 * Cycle-safe via a `visited` Set. Bounded via `maxHops` (default 32).
 */

import type { DFGChain, DFGDef } from '../types/index.js';

export interface BackwardWalkResult {
  /** Every def id visited (including the start). */
  visited: ReadonlySet<number>;
  /** Every distinct line touched by a visited def. */
  lines: ReadonlySet<number>;
  /** True iff the hop cap was reached before the walk fully terminated. */
  hopCapReached: boolean;
}

export interface BackwardWalkOptions {
  /** Max chain hops before termination. Default 32. */
  maxHops?: number;
}

/**
 * Per-file memo for `walkBackwardDefs`. Keyed on `chainsByToDef` identity,
 * so results auto-clear when the caller moves to a new file (each file's
 * `analyze()` builds a fresh `chainsByToDef` map, releasing the previous
 * entry when nothing else references it). Inner key is
 * `${startDefId}|${maxHops}` — same starting def + hop cap within a file
 * returns the cached `BackwardWalkResult` directly.
 *
 * cognium-dev #254 T2#10: multiple sinks in a single file frequently walk
 * back to the same source def; without a memo the DFG chain from that def
 * is re-traversed once per sink. Result Sets are immutable (`ReadonlySet`
 * via the return type), so sharing them across callers is safe.
 */
const walkBackwardDefsMemo = new WeakMap<
  ReadonlyMap<number, DFGChain[]>,
  Map<string, BackwardWalkResult>
>();

/**
 * Bounded backward BFS from `startDefId` along `chainsByToDef`. Every def
 * reached is added to `lines` (via `defById`). Cycle-safe.
 */
export function walkBackwardDefs(
  startDefId: number,
  chainsByToDef: ReadonlyMap<number, DFGChain[]>,
  defById: ReadonlyMap<number, DFGDef>,
  options: BackwardWalkOptions = {}
): BackwardWalkResult {
  const maxHops = options.maxHops ?? 32;

  let perFile = walkBackwardDefsMemo.get(chainsByToDef);
  if (perFile !== undefined) {
    const key = `${startDefId}|${maxHops}`;
    const hit = perFile.get(key);
    if (hit !== undefined) return hit;
  }

  const visited = new Set<number>();
  const lines = new Set<number>();
  let hopCapReached = false;

  const startDef = defById.get(startDefId);
  if (!startDef) {
    return { visited, lines, hopCapReached: false };
  }

  visited.add(startDefId);
  lines.add(startDef.line);

  const queue: number[] = [startDefId];
  let hops = 0;

  while (queue.length > 0) {
    if (hops >= maxHops) {
      hopCapReached = true;
      break;
    }
    hops++;

    const currentId = queue.shift() as number;
    const incoming = chainsByToDef.get(currentId);
    if (!incoming) continue;

    for (const chain of incoming) {
      const fromId = chain.from_def;
      if (visited.has(fromId)) continue;

      visited.add(fromId);
      const fromDef = defById.get(fromId);
      if (fromDef) {
        lines.add(fromDef.line);
      }
      queue.push(fromId);
    }
  }

  const result: BackwardWalkResult = { visited, lines, hopCapReached };

  if (perFile === undefined) {
    perFile = new Map();
    walkBackwardDefsMemo.set(chainsByToDef, perFile);
  }
  perFile.set(`${startDefId}|${maxHops}`, result);

  return result;
}
