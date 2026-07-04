/**
 * LibraryProfileSourceGatePass — cognium-dev #236
 *
 * Under the `library/*` project profile, drops speculative
 * `interprocedural_param` sources from `graph.ir.taint.sources`
 * before flow generation. Rationale:
 *
 *   `TaintMatcher` emits an `interprocedural_param` source for every
 *   public method parameter — the semantics are "this parameter MIGHT
 *   receive attacker-controlled data at some caller". For an
 *   `application/*` codebase that assumption is defensible: unresolved
 *   callers eventually reduce to entry points that the application
 *   itself owns. For a `library/*` codebase it is systematically
 *   wrong: the callers are downstream consumers, and the correct
 *   trust-boundary answer is "the consumer's threat model, not ours".
 *
 *   `external_taint_escape` (CWE-668) is the sink type where this
 *   mismatch surfaces most (35% of Tier 2 H+C findings in the 22-repo
 *   audit), because Scenario B in `InterproceduralPass` synthesises
 *   an `external_taint_escape` sink for every external call carrying
 *   an `interprocedural_param`-tainted argument. Dropping the source
 *   also drops every `interprocedural_param → *` flow that
 *   `TaintPropagationPass.detectParameterSinkFlows` would otherwise
 *   emit.
 *
 * This pass is the source-side companion to the entry-point gate
 * (#128) and the source-semantics gate (#138). Where #128 attempts to
 * reason about individual method signatures ("is this a Spring
 * controller?") and #138 tags per-source metadata, this pass uses the
 * caller-supplied `ProjectProfile` (ADR-008) as a coarser but more
 * reliable classifier: if the caller declares the whole project a
 * library, the presumption of external callers is turned off.
 *
 * Pipeline slot: runs after `SourceSemanticsPass` (so speculative
 * tagging is preserved for observability) and before `SinkFilterPass`
 * / `TaintPropagationPass` (so no dropped source ever reaches the
 * flow generators or Scenario B in `InterproceduralPass`).
 *
 * Dropped sources are **not** re-emitted or silently reclassified —
 * they are removed outright. The pass returns a small diagnostic
 * result recording the profile that triggered it and the number of
 * sources dropped, so downstream consumers (and unit tests) can
 * observe the gate without having to reconstruct the reason.
 *
 * Guardrails:
 *   - Pass is a no-op when `graph.ir.meta.projectProfile` is absent,
 *     `'unknown'`, or does not start with `library/`. Callers that do
 *     not opt in to profile detection get the unmodified source list.
 *   - Only `interprocedural_param` and `constructor_field` sources
 *     are eligible for the drop. Every other `SourceType` is a
 *     concrete taint anchor (`http_param`, `env_input`, `db_input`,
 *     …) and is preserved unconditionally.
 *   - Guarded on `disabledPasses.has('library-profile-source-gate')`
 *     at the pipeline registration site.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { ProjectProfile, SourceType } from '../../types/index.js';

/**
 * Source types eligible for the library-profile drop. These are the
 * SPECULATIVE seeds — sources that represent "this parameter/field
 * MIGHT carry taint from a caller we cannot see", not concrete taint
 * anchors.
 */
const SPECULATIVE_SOURCE_TYPES: ReadonlySet<SourceType> = new Set<SourceType>([
  'interprocedural_param',
  'constructor_field',
]);

export interface LibraryProfileSourceGateResult {
  /**
   * Resolved `ProjectProfile` observed on `graph.ir.meta.projectProfile`
   * at the time this pass ran. `undefined` when no profile was
   * supplied by the caller.
   */
  profile: ProjectProfile | undefined;
  /**
   * Whether the profile matched the library-shape trigger and the
   * gate was applied. `false` for every non-library shape and for
   * `'unknown'` / absent profiles.
   */
  applied: boolean;
  /**
   * Number of speculative sources removed from
   * `graph.ir.taint.sources`. Zero when `applied === false`.
   */
  dropped: number;
  /**
   * Breakdown of drops by `SourceType`. Empty object when
   * `applied === false`.
   */
  droppedByType: Partial<Record<SourceType, number>>;
}

/**
 * Returns true when the resolved profile begins with `library/`
 * (i.e. any `library/production`, `library/dev`, `library/sample`,
 * `library/benchmark`, `library/test` environment binding).
 * `'unknown'` and non-library shapes return false.
 */
function isLibraryShape(profile: ProjectProfile | undefined): boolean {
  if (!profile || profile === 'unknown') return false;
  return profile.startsWith('library/');
}

export class LibraryProfileSourceGatePass
  implements AnalysisPass<LibraryProfileSourceGateResult>
{
  readonly name = 'library-profile-source-gate';
  readonly category = 'security' as const;

  run(ctx: PassContext): LibraryProfileSourceGateResult {
    const { graph } = ctx;
    const profile = graph.ir.meta.projectProfile;

    if (!isLibraryShape(profile)) {
      return {
        profile,
        applied: false,
        dropped: 0,
        droppedByType: {},
      };
    }

    const sources = graph.ir.taint.sources;
    if (sources.length === 0) {
      return {
        profile,
        applied: true,
        dropped: 0,
        droppedByType: {},
      };
    }

    const droppedByType: Partial<Record<SourceType, number>> = {};
    const kept = [];
    for (const src of sources) {
      if (SPECULATIVE_SOURCE_TYPES.has(src.type)) {
        droppedByType[src.type] = (droppedByType[src.type] ?? 0) + 1;
        continue;
      }
      kept.push(src);
    }

    const dropped = sources.length - kept.length;

    // Mutate the array in place so downstream passes see the
    // filtered list. Every existing pass reads `graph.ir.taint.sources`
    // by reference.
    sources.length = 0;
    sources.push(...kept);

    return {
      profile,
      applied: true,
      dropped,
      droppedByType,
    };
  }
}
