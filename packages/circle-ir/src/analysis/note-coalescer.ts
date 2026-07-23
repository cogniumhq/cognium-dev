/**
 * Note-level finding coalescer — cognium-dev #143.
 *
 * Groups `SastFinding[]` by `(file, line)` and folds any group of two or
 * more `level === 'note'` findings into a single record. The primary
 * finding is picked deterministically (lexicographic `rule_id`) and
 * the co-located rule_ids are attached as `labels[]`. Every other
 * (`level === 'warning' | 'error'`) finding passes through untouched.
 *
 * Empirical basis (from the OWASP-Benchmark instrumentation capture on
 * cognium-dev#145, comment 2026-07-03):
 *   - 5,481 `(file, line)` locations (31.3% of files) were hit by ≥ 2
 *     distinct advisory rules.
 *   - Most-common pairs:
 *       missing-public-doc + naming-convention   × 2,740
 *       missing-csp-frame-ancestors + missing-x-frame-options × 2,740
 *       unused-variable + variable-shadowing     (co-located)
 *   - HIGH-severity: 0 co-locations in the same capture.
 *
 * Design invariants:
 *   - Additive: consumers that key on `rule_id` continue to work
 *     unchanged. Consumers that surface every co-located rule read
 *     both `rule_id` and `labels`.
 *   - Level-gated: only fires when EVERY finding in the group has
 *     `level === 'note'`. If any group member is `warning` or `error`,
 *     the group passes through un-coalesced — visibility of higher-
 *     severity findings is never diminished.
 *   - Deterministic: sort by `rule_id` inside a group before picking
 *     the primary, so the same input always produces the same output
 *     (test-friendly, diff-friendly, cache-friendly).
 *   - Message preservation: the primary finding's `message` is kept
 *     verbatim. The `labels[]` field is the sole signal that more
 *     rules co-located there.
 *
 * This is the MVP of the reopen. Follow-ups on #143 include a full
 * instrumentation rerun on multi-severity data + a broader
 * medium-severity coalesce policy — both deferred until the data
 * capture is redone.
 */

import type { SastFinding } from '../types/index.js';

/**
 * Coalesce note-level findings at the same `(file, line)` location.
 * Returns a new array; the input is not mutated.
 */
export function coalesceNoteLevelFindings(
  findings: readonly SastFinding[],
): SastFinding[] {
  if (findings.length < 2) return [...findings];

  // Bucket by (file, line). We keep original insertion order so
  // higher-level findings interleaved with note-level findings are
  // preserved in-place; only the note-level subset is folded.
  const groups = new Map<string, SastFinding[]>();
  const order: string[] = [];
  for (const f of findings) {
    const key = `${f.file}\0${f.line}`;
    const bucket = groups.get(key);
    if (bucket) {
      bucket.push(f);
    } else {
      groups.set(key, [f]);
      order.push(key);
    }
  }

  const out: SastFinding[] = [];
  for (const key of order) {
    const bucket = groups.get(key)!;
    if (bucket.length === 1) {
      out.push(bucket[0]);
      continue;
    }

    // Split by level. Only same-key finding groups where EVERY entry
    // is `note` get coalesced; mixed-level groups pass through
    // un-coalesced (visibility of warnings / errors preserved).
    const allNote = bucket.every((f) => f.level === 'note');
    if (!allNote) {
      for (const f of bucket) out.push(f);
      continue;
    }

    // Also skip when every entry has the SAME rule_id — those are
    // duplicate emissions, not multi-rule collisions. Passing them
    // through preserves the existing dedup behaviour handled elsewhere
    // (e.g. taint-matcher's sinkMap dedup). Coalescer's job is only
    // multi-rule folding.
    const uniqueRuleIds = new Set(bucket.map((f) => f.rule_id));
    if (uniqueRuleIds.size < 2) {
      for (const f of bucket) out.push(f);
      continue;
    }

    // Deterministic primary pick: lexicographic rule_id.
    const sorted = [...bucket].sort((a, b) => a.rule_id.localeCompare(b.rule_id));
    const primary = sorted[0];
    const additional = sorted
      .slice(1)
      .map((f) => f.rule_id)
      // Preserve `labels[]` carried on the primary or others from a
      // prior coalesce (idempotent when re-run).
      .concat(...sorted.map((f) => f.labels ?? []));
    // Dedup labels; drop the primary's rule_id if it accidentally
    // appears in a prior labels[] entry.
    const uniqueLabels = Array.from(new Set(additional)).filter(
      (l) => l !== primary.rule_id,
    );

    out.push({ ...primary, labels: uniqueLabels });
  }

  return out;
}
