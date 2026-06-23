/**
 * Confidence-based finding filter (#153 pre-req — speculative-finding
 * suppression infrastructure, 3.94.0).
 *
 * Suppresses findings whose pass marked them as speculative (`confidence`:
 * `'medium'` or `'low'`) unless the consumer opted into `includeSpeculative`,
 * in which case the full unfiltered stream is returned so a downstream
 * verifier can adjudicate them before user presentation.
 *
 * Existing passes (pre-3.94.0) do not set `SastFinding.confidence`. Findings
 * with `confidence === undefined` are treated as `'high'` and always pass
 * through — guaranteeing zero behavioural change for the 40-pass pipeline
 * until a pass opts into the new field.
 */
import type { SastFinding } from '../types/index.js';

/**
 * Apply confidence filtering to a finding stream.
 *
 * @param findings           - The full per-file findings emitted by the pipeline.
 * @param includeSpeculative - When `true`, all findings are preserved (a
 *                             downstream verifier is expected to adjudicate
 *                             the `'medium'`/`'low'` entries). When `false`
 *                             (the default), findings with explicit
 *                             `confidence` of `'medium'` or `'low'` are
 *                             dropped.
 * @returns the (possibly filtered) finding array.
 */
export function applyConfidenceFilter(
  findings: SastFinding[],
  includeSpeculative: boolean,
): SastFinding[] {
  if (includeSpeculative) return findings;
  return findings.filter(isHighConfidence);
}

/**
 * Predicate: a finding is high-confidence if it either omits the `confidence`
 * field (pre-3.94.0 default) or explicitly sets it to `'high'`.
 *
 * Exported for unit tests and for downstream consumers that want to apply the
 * same gating logic post-hoc.
 */
export function isHighConfidence(finding: SastFinding): boolean {
  return finding.confidence === undefined || finding.confidence === 'high';
}
