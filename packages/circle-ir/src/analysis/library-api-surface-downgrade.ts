/**
 * Library-API-surface downgrade hook (added in 3.105.0).
 *
 * Centralized severity adjustment for findings whose sinks live on a
 * *library API boundary* where trust responsibility belongs to the caller
 * rather than the library itself (e.g. JEXL.evaluate, Handlebars.compile,
 * SPI Class.forName loaders, JSR-defined ClassLoader overrides). Such
 * findings remain valid signals (they identify a real exposed surface)
 * but should not be reported at HIGH/CRITICAL because the library author
 * cannot reasonably refactor the API away.
 *
 * The mechanism is decoupled from any specific pass: passes attach the
 * `LIBRARY_API_SURFACE_TAG` to the `TaintSink` (or directly to the emitted
 * `SastFinding.tags`), and this hook runs as a post-processing step in
 * `analyze()` between confidence filtering and the per-file finding cap.
 *
 * Pillar I: tag string is fully generic. No LLM-themed identifiers.
 */

import type { SastFinding } from '../types/index.js';

/**
 * Tag emitted by sink-filter gates for callsites at library API boundaries
 * where trust responsibility belongs to the *caller*. Findings carrying
 * this tag are downgraded to MEDIUM / warning by
 * `applyLibraryApiSurfaceDowngrade`.
 */
export const LIBRARY_API_SURFACE_TAG = 'library-api-surface:caller-responsibility';

/**
 * Centrally downgrade findings tagged as library-API surface to
 * medium / warning. Non-mutating — returns a new array; untagged findings
 * pass through identical (same object reference). LOW findings are left
 * alone (no upgrade); existing MEDIUM findings are returned unchanged.
 *
 * As of 3.106.0 the pre-downgrade severity is preserved on the returned
 * finding as `original_severity` so the downstream
 * `applyProjectProfileTransform` hook can restore it under `application`
 * profile. See `docs/ARCHITECTURE.md` ADR-008.
 */
export function applyLibraryApiSurfaceDowngrade(findings: SastFinding[]): SastFinding[] {
  return findings.map(f => {
    if (!f.tags?.includes(LIBRARY_API_SURFACE_TAG)) return f;
    if (f.severity === 'medium' || f.severity === 'low') return f;
    return {
      ...f,
      original_severity: f.severity,
      severity: 'medium',
      level: 'warning',
    };
  });
}
