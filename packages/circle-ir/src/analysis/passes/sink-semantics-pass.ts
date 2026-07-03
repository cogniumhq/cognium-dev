/**
 * SinkSemanticsPass — cognium-dev #139 Tier A
 *
 * Consults a curated `<ClassName>#<methodName>` → `real_class` +
 * `overrides` registry (`configs/sink-semantics.json`) and drops
 * sinks whose emitted `SinkType` label disagrees with the registry's
 * declared real-behavior classification.
 *
 * Motivation: the taint-matcher's `configs/sinks/*.yaml` patterns
 * often use method-only matches (no class filter) which produce FPs
 * when unrelated classes happen to share a method name. Canonical
 * example:
 *
 *     public byte[] get(byte[] key) {
 *       return connection.executeCommand(commandObjects.get(key));
 *     }
 *
 * The `executeCommand` pattern in `configs/sinks/command.yaml` has no
 * `class` filter, so `Jedis.executeCommand(...)` — Redis wire-protocol
 * serialization — is flagged as `command_injection`. The registry
 * fixes this by listing `Jedis#executeCommand → drop
 * command_injection` (with `real_class: db_protocol` as a documenting
 * label).
 *
 * The gate is deliberately narrow (~8 seed entries as of 3.144.0);
 * each entry is class-scoped so `Runtime.exec`, `ProcessBuilder.start`,
 * `Statement.execute`, `Class.forName`, and `Method.invoke` remain
 * unaffected. Unresolved receivers (`sink.class === undefined`) fall
 * through — the gate is false-negative-safe.
 *
 * Pipeline slot: runs after `SinkFilterPass` (so unrelated FP
 * suppressions have already fired) and before `TaintPropagationPass`
 * (so the flow generators never see the dropped sinks).
 *
 * Tier B (speculative verifier on disagreements) is explicitly OUT
 * of scope for circle-ir. Any speculative-verification layer belongs
 * in cognium-ai / circle-ir-ai; results from that layer can be
 * promoted to Tier A registry entries by hand.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { SinkSemanticsEntry } from '../../types/config.js';
import type { SinkType, TaintSink } from '../../types/index.js';
import type { SinkFilterResult } from './sink-filter-pass.js';

export interface SinkSemanticsResult {
  /** Number of sinks dropped by the registry gate this run. */
  droppedCount: number;
  /** Number of registry entries loaded (0 = gate inactive). */
  registrySize: number;
}

/**
 * Build a signature → overrides lookup map from a flat entry list.
 * Signature format: `<ClassName>#<methodName>` (simple names only;
 * case-sensitive).
 */
function buildRegistry(
  entries: readonly SinkSemanticsEntry[],
): Map<string, Set<SinkType>> {
  const registry = new Map<string, Set<SinkType>>();
  for (const entry of entries) {
    const existing = registry.get(entry.signature);
    if (existing) {
      // Last-write-wins for duplicate signatures; also union the
      // overrides so multiple files can extend the same signature.
      for (const t of entry.overrides) existing.add(t);
    } else {
      registry.set(entry.signature, new Set(entry.overrides));
    }
  }
  return registry;
}

export class SinkSemanticsPass
  implements AnalysisPass<SinkSemanticsResult>
{
  readonly name = 'sink-semantics';
  readonly category = 'security' as const;

  run(ctx: PassContext): SinkSemanticsResult {
    const { graph, config } = ctx;
    const entries = config.sinkSemantics ?? [];
    if (entries.length === 0) {
      // No registry loaded — nothing to do. Preserves legacy callers
      // that construct a TaintConfig without `sinkSemantics`.
      return { droppedCount: 0, registrySize: 0 };
    }

    const registry = buildRegistry(entries);
    // Authoritative sink list in the real pipeline is
    // `SinkFilterResult.sinks` — that is what `analyzer.ts` assembles
    // the final `taint.sinks` from and what `TaintPropagationPass` /
    // `InterproceduralPass` consume. `graph.ir.taint.sinks` starts
    // empty and is never populated by the pipeline. Prefer the
    // sink-filter result; fall back to `graph.ir.taint.sinks` for
    // stand-alone unit-test harnesses that don't run `SinkFilterPass`.
    const sinks: TaintSink[] = ctx.hasResult('sink-filter')
      ? ctx.getResult<SinkFilterResult>('sink-filter').sinks
      : graph.ir.taint.sinks;

    let droppedCount = 0;
    const kept = sinks.filter((sink) => {
      // Unresolved receiver → registry cannot apply. Preserve the
      // sink so the normal flow generator still processes it.
      if (!sink.class || !sink.method) return true;
      const signature = `${sink.class}#${sink.method}`;
      const overrides = registry.get(signature);
      if (!overrides) return true;
      if (overrides.has(sink.type)) {
        droppedCount++;
        return false;
      }
      return true;
    });

    // Mutate in place so downstream passes (TaintPropagationPass)
    // see the reduced sink set. Preserves array identity for any
    // consumer that captured a reference before this pass ran.
    if (droppedCount > 0) {
      sinks.length = 0;
      sinks.push(...kept);
    }

    return { droppedCount, registrySize: registry.size };
  }
}
