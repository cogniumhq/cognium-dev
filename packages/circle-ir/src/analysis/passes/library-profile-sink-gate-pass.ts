/**
 * LibraryProfileSinkGatePass — cognium-dev #232
 *
 * Sink-side companion to `LibraryProfileSourceGatePass` (#236,
 * shipped 3.151.0). Under the `library/*` project profile, drops
 * sinks whose entire vulnerability class is off-topic for library
 * code — currently just `log_injection` (CWE-117).
 *
 * Motivation:
 *
 *   `log_injection` requires a downstream log-viewer that interprets
 *   attacker-controlled log content — the exploit ("log forging",
 *   HTML/ANSI injection into a log renderer, log-based privilege
 *   escalation) is exercised at the application-integration boundary,
 *   not inside a library. A library that calls `Logger.info(x)` where
 *   `x` originated from an HTTP parameter has not committed a defect:
 *   the consuming application decides where those log records are
 *   rendered and how their content is escaped.
 *
 *   Empirically, `log_injection` was ~10% of H+C findings on the
 *   Tier 2 8-repo library cohort (402 findings in the audit
 *   summarised in cognium-ai#189 §1). The signal is systemically
 *   noisy for library code and provides no actionable
 *   application-security value.
 *
 * Where #236 dropped speculative `interprocedural_param` sources
 * (which removed the entire `external_taint_escape` Scenario-B
 * synthesis path), this pass drops the sinks themselves. `log_injection`
 * has real, non-speculative sources (`http_param`, `env_input`,
 * `db_input`, …) that flow into concrete sink calls (`Logger.info`,
 * `logging.info`, `console.log`, …); the source-side gate does not
 * remove them. The *sink class* is what is off-topic here.
 *
 * Pipeline slot: runs after `CliMainReflectionSuppressPass` (so
 * every sink-side categorisation / suppression pass fires first)
 * and before `TaintPropagationPass` (so no dropped sink ever
 * reaches the flow generators).
 *
 * Guardrails:
 *   - Pass is a no-op when `graph.ir.meta.projectProfile` is absent,
 *     `'unknown'`, or does not start with `library/`. Callers that do
 *     not opt in to profile detection get the unmodified sink list.
 *   - Only `log_injection` is eligible in 3.152.0. Every other
 *     `SinkType` (`sql_injection`, `command_injection`, `xss`,
 *     `path_traversal`, `deserialization`, …) is preserved
 *     unconditionally. Extending the drop set is a deliberate
 *     one-line change in `DROPPED_SINK_TYPES`.
 *   - Guarded on `disabledPasses.has('library-profile-sink-gate')`
 *     at the pipeline registration site.
 *
 * Scope note (Rust log macros): `LanguageSourcesPass` emits
 * `rule_id: 'log_injection'` findings directly for Rust log macros
 * (`info!`, `println!`, `eprintln!`, …). Those findings bypass the
 * sink pipeline entirely and therefore bypass this pass. Deferred
 * to a follow-up if the harness rerun shows material Rust
 * residuals; the Tier 2 8-repo cohort is Java-heavy.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { ProjectProfile, SinkType, TaintSink } from '../../types/index.js';
import type { SinkFilterResult } from './sink-filter-pass.js';

/**
 * Sink types eligible for the library-profile drop. Seeded with
 * `log_injection` (CWE-117) in 3.152.0. Extending this set is a
 * deliberate, reviewable change.
 */
const DROPPED_SINK_TYPES: ReadonlySet<SinkType> = new Set<SinkType>([
  'log_injection',
]);

export interface LibraryProfileSinkGateResult {
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
   * Number of sinks removed from the authoritative sink list. Zero
   * when `applied === false`.
   */
  dropped: number;
  /**
   * Breakdown of drops by `SinkType`. Empty object when
   * `applied === false`.
   */
  droppedByType: Partial<Record<SinkType, number>>;
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

export class LibraryProfileSinkGatePass
  implements AnalysisPass<LibraryProfileSinkGateResult>
{
  readonly name = 'library-profile-sink-gate';
  readonly category = 'security' as const;

  run(ctx: PassContext): LibraryProfileSinkGateResult {
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

    // Authoritative sink list mirrors the fetch pattern in
    // `SinkSemanticsPass`: prefer `SinkFilterResult.sinks` (what
    // `analyzer.ts` assembles the final `taint.sinks` from), fall
    // back to `graph.ir.taint.sinks` for stand-alone unit tests
    // that don't run `SinkFilterPass`.
    const sinks: TaintSink[] = ctx.hasResult('sink-filter')
      ? ctx.getResult<SinkFilterResult>('sink-filter').sinks
      : graph.ir.taint.sinks;

    if (sinks.length === 0) {
      return {
        profile,
        applied: true,
        dropped: 0,
        droppedByType: {},
      };
    }

    const droppedByType: Partial<Record<SinkType, number>> = {};
    const kept: TaintSink[] = [];
    for (const sink of sinks) {
      if (DROPPED_SINK_TYPES.has(sink.type)) {
        droppedByType[sink.type] = (droppedByType[sink.type] ?? 0) + 1;
        continue;
      }
      kept.push(sink);
    }

    const dropped = sinks.length - kept.length;

    // Mutate the array in place so downstream passes see the
    // filtered list. Preserves array identity for any consumer that
    // captured a reference before this pass ran.
    if (dropped > 0) {
      sinks.length = 0;
      sinks.push(...kept);
    }

    return {
      profile,
      applied: true,
      dropped,
      droppedByType,
    };
  }
}
