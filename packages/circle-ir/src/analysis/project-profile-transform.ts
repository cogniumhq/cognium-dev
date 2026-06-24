/**
 * Project-profile severity transform (added in 3.106.0).
 *
 * Post-pipeline hook that adjusts the severity of findings carrying the
 * `library-api-surface:caller-responsibility` tag based on the resolved
 * `ProjectProfile` for the finding's file. Designed to compose with the
 * Sprint 47 `applyLibraryApiSurfaceDowngrade` hook:
 *
 *   findings
 *     → applyConfidenceFilter
 *     → applyLibraryApiSurfaceDowngrade   (uniform CRIT/HIGH → MED)
 *     → applyProjectProfileTransform      (THIS — profile-conditional)
 *     → applyPerFileFindingCap
 *
 * Decision policy (D1=C, D2=Yes, D3=Yes per ADR-008):
 *
 * - `profile = library/<env>` AND tagged AND rule_id ∈ DOWNGRADE_ELIGIBLE
 *     → CRIT-protected bucketing: CRIT→MED, HIGH→LOW, MED→LOW, LOW→LOW
 *
 * - `profile = application/<env>` AND tagged AND original_severity set
 *     → restore original_severity (revert Sprint 47 downgrade)
 *
 * - Anything else → no-op (untagged findings, unknown profile, other
 *   shapes, ineligible sink types).
 *
 * Pillar I: no LLM-themed identifiers. Pure function over the findings
 * array; the resolver callback is supplied by the caller (engine wires it
 * from `analyzeOptions.projectProfile`).
 *
 * See `docs/ARCHITECTURE.md` ADR-008 for the full rationale.
 */

import type { SastFinding, ProjectProfile, Severity, SarifLevel } from '../types/index.js';
import { LIBRARY_API_SURFACE_TAG } from './library-api-surface-downgrade.js';

/**
 * Rule IDs eligible for the library-profile downgrade. Per ADR-008, the
 * "library API boundary" excuse is semantically defensible only for sinks
 * where the caller actually controls what is loaded / compiled /
 * evaluated. Sinks outside this set ignore the profile signal — a library
 * that calls `Runtime.exec(userInput)` or `ObjectInputStream.readObject`
 * on a tainted stream is a bug regardless of project shape.
 */
const DOWNGRADE_ELIGIBLE_RULE_IDS: ReadonlySet<string> = new Set([
  'code_injection',
  'template_injection',
  'xpath_injection',
  'sql_injection',
]);

/**
 * CRIT-protected bucketing for the `library` shape (D1=C). A tagged
 * CRITICAL is still a literal RCE shape and warrants human review even
 * at a library API boundary — never drops below MEDIUM.
 */
function libraryDowngrade(severity: Severity): { severity: Severity; level: SarifLevel } {
  switch (severity) {
    case 'critical': return { severity: 'medium', level: 'warning' };
    case 'high':     return { severity: 'low',    level: 'note' };
    case 'medium':   return { severity: 'low',    level: 'note' };
    case 'low':      return { severity: 'low',    level: 'note' };
  }
}

/**
 * SARIF level inferred from a `Severity` value, used when restoring the
 * pre-downgrade level under `application` profile.
 */
function levelForSeverity(severity: Severity): SarifLevel {
  switch (severity) {
    case 'critical': return 'error';
    case 'high':     return 'error';
    case 'medium':   return 'warning';
    case 'low':      return 'note';
  }
}

/**
 * Resolve a file path to a `ProjectProfile`. Returns `'unknown'` when the
 * caller cannot supply a profile for the file (the safe default — no
 * profile-conditional transform applied).
 */
export type ProfileResolver = (file: string) => ProjectProfile;

/**
 * Apply project-profile-conditional severity transform to tagged
 * findings. Non-mutating — returns a new array; untagged findings,
 * findings under `unknown` profile, and findings whose rule_id is not in
 * the downgrade allowlist all pass through identical (same reference).
 *
 * See `docs/ARCHITECTURE.md` ADR-008 for the composition contract.
 */
export function applyProjectProfileTransform(
  findings: SastFinding[],
  resolveProfile: ProfileResolver,
): SastFinding[] {
  return findings.map(f => {
    if (!f.tags?.includes(LIBRARY_API_SURFACE_TAG)) return f;

    const profile = resolveProfile(f.file);
    if (profile === 'unknown') return f;

    const shape = profile.split('/')[0];

    if (shape === 'library') {
      if (!DOWNGRADE_ELIGIBLE_RULE_IDS.has(f.rule_id)) return f;
      const { severity, level } = libraryDowngrade(f.severity);
      // Skip the rebuild if the transform would be a true no-op.
      if (severity === f.severity && level === f.level) return f;
      return { ...f, severity, level };
    }

    if (shape === 'application') {
      // Restore the pre-Sprint-47 severity. Caller bears the trust under
      // application profile, so the downgrade reasoning inverts.
      if (!f.original_severity) return f;
      if (f.original_severity === f.severity) return f;
      return {
        ...f,
        severity: f.original_severity,
        level: levelForSeverity(f.original_severity),
      };
    }

    // cli / server / plugin shapes: no-op in v1.
    return f;
  });
}
