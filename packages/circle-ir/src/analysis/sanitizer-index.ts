/**
 * Sanitizer coverage helper — H8 (#254 3.171.0).
 *
 * `TaintSanitizer.sanitizes` is a `SinkType[]` (typically 1–3 entries but
 * up to ~12 for wide-coverage sanitizers). Ten hot sites across
 * taint-propagation, sink-filter, interprocedural, and cross-file passes
 * call `san.sanitizes.includes(sinkType)` inside inner loops that iterate
 * over (sanitizers × sinks × taint checks). On the 500-file langchain4j
 * benchmark that shape accounts for ~6–10% of taint-propagation pass time
 * because `.includes()` is O(n) linear scan.
 *
 * This helper builds and caches a `Set<string>` per sanitizer via a
 * WeakMap. Cache lifetime tracks the sanitizer object itself: no manual
 * invalidation, no memory leak, no API-surface change on `TaintSanitizer`.
 *
 * The `Set<string>` is intentionally typed on `string` (not `SinkType`) so
 * callers that stringify the sink type (`f.sink_type: string`) don't need
 * a cast — matches the shape of the sites already using
 * `(san.sanitizes as readonly string[]).includes(f.sink_type)`.
 */

import type { TaintSanitizer } from '../types/index.js';

const SANITIZER_SET_CACHE: WeakMap<TaintSanitizer, Set<string>> = new WeakMap();

function getSanitizesSet(san: TaintSanitizer): Set<string> {
  let s = SANITIZER_SET_CACHE.get(san);
  if (!s) {
    s = new Set<string>(san.sanitizes as readonly string[]);
    SANITIZER_SET_CACHE.set(san, s);
  }
  return s;
}

/**
 * True when the sanitizer covers the given sink type. O(1) after first
 * call for each sanitizer object (Set-backed lookup vs the prior
 * `Array.prototype.includes` linear scan).
 */
export function sanitizerCoversSink(san: TaintSanitizer, sinkType: string): boolean {
  return getSanitizesSet(san).has(sinkType);
}

/**
 * True when the sanitizer covers at least one sink type. Useful for the
 * "unknown/source sinkType — accept any recognised sanitizer" branch in
 * `checkSanitized` (propagation-context sanitizer check).
 */
export function sanitizerCoversAny(san: TaintSanitizer): boolean {
  // sanitizes is a small array — direct length check avoids Set build for
  // sanitizers we never `has()`-query.
  return san.sanitizes.length > 0;
}
