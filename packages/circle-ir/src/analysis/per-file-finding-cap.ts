/**
 * Defensive per-file finding cap (#142).
 *
 * A single file producing more than `cap` findings is treated as a structural
 * failure rather than a legitimate detection burst. When triggered, this
 * helper drops the original findings array and returns a single
 * `saturated-file` advisory carrying the suppressed count, so the signal
 * stays visible without flooding downstream consumers (text reports, SARIF
 * exporters, the cross-file phase, etc.).
 *
 * Browser-safe: pure data transformation, no Node-only APIs. The logger DI
 * is injected by the caller (see `src/utils/logger.ts`).
 *
 * Rationale & background:
 * - #142 originally proposed a 3-tier scheme (normal / advisory / suppress)
 *   anchored to the (source, sink) coalescing schema in #143. #143 was
 *   closed in 3.92.0 as unjustified by empirical capture (jedis / jib /
 *   eureka cross-file: 0 multi-label coords; OWASP Benchmark per-file:
 *   31 % multi-rule overlap but 0 HIGH-severity multi-rule locations), so
 *   the cap reverts to its original "defensive tripwire" shape: a single
 *   hard threshold with no middle "downgrade to advisory" tier.
 * - The default of 1000 sits well above the realistic per-file ceiling
 *   (~200 findings on jedis-shape facades) and below the structural-failure
 *   floor observed on langchain4j during the #141 investigation
 *   (~10K findings on a single file before the cross-file hang).
 */

import type { SastFinding } from '../types/index.js';
import { logger } from '../utils/logger.js';

/**
 * Default per-file finding cap. Applied when `AnalyzerOptions.perFileFindingCap`
 * is omitted; `0` disables the cap entirely.
 */
export const DEFAULT_PER_FILE_FINDING_CAP = 1000;

/**
 * Rule id and pass name used by the synthetic advisory emitted when the cap
 * fires. Kept in one place so downstream consumers (CLI text formatter,
 * SARIF exporter, dashboards) can match on a stable identifier.
 */
export const SATURATED_FILE_RULE_ID = 'saturated-file';

/**
 * Apply the per-file finding cap.
 *
 * If `findings.length > cap` (and `cap > 0`), returns a single
 * `saturated-file` advisory with `evidence.suppressed_count` recording the
 * dropped count and `evidence.cap` recording the threshold that fired.
 * Otherwise returns the original array unchanged.
 *
 * @param filePath   Source file path for the synthetic advisory.
 * @param findings   Findings produced by the per-file analysis pipeline.
 * @param cap        Threshold; `0` (or negative) disables the cap.
 */
export function applyPerFileFindingCap(
  filePath: string,
  findings: SastFinding[],
  cap: number,
): SastFinding[] {
  if (cap <= 0) return findings;
  if (findings.length <= cap) return findings;

  const suppressedCount = findings.length;

  // Aggregate by_rule / by_severity so the advisory still carries enough
  // structure for a triager to recognise the saturation pattern without
  // re-running the scan with the cap disabled.
  const byRule: Record<string, number> = {};
  const bySeverity: Record<string, number> = {};
  for (const f of findings) {
    byRule[f.rule_id] = (byRule[f.rule_id] ?? 0) + 1;
    bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
  }

  logger.warn(
    `File ${filePath} produced ${suppressedCount} findings (cap=${cap}); ` +
      'suppressing individual findings and emitting saturated-file advisory.',
    { file: filePath, suppressedCount, cap, byRule, bySeverity },
  );

  const advisory: SastFinding = {
    id: `${SATURATED_FILE_RULE_ID}-${filePath}-1`,
    pass: SATURATED_FILE_RULE_ID,
    category: 'maintainability',
    rule_id: SATURATED_FILE_RULE_ID,
    severity: 'low',
    level: 'note',
    message:
      `File suppressed: produced ${suppressedCount} findings, exceeding the ` +
      `per-file cap of ${cap}. This typically indicates cross-product noise, ` +
      'mislabelled sink class, or pathological generated code rather than a ' +
      'legitimate detection burst. Individual findings dropped; re-run with ' +
      '`perFileFindingCap: 0` to bypass the cap if the volume is intentional.',
    file: filePath,
    line: 1,
    evidence: {
      suppressed_count: suppressedCount,
      cap,
      by_rule: byRule,
      by_severity: bySeverity,
    },
  };

  return [advisory];
}
