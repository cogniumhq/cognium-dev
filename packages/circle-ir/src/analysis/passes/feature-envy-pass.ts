/**
 * Pass #87: feature-envy (CWE-1060, category: architecture)
 *
 * @deprecated NOT REGISTERED IN THE DEFAULT PIPELINE
 *
 * This pass was removed from the default AnalysisPipeline in v3.14.0 because
 * the call-count heuristic (external_max ≥ 4 AND margin > 2) fires trivially
 * on legitimate delegation patterns — facades, controllers, service classes —
 * and its fix suggestion ("move this method to OtherClass") is incorrect when
 * the method's design intent is orchestration rather than feature envy.
 * Confirming true feature envy requires understanding design intent, which is
 * LLM territory.
 *
 * The raw signals this pass relies on are already present in CircleIR:
 *   • ir.calls   — per-callsite receiver, receiver_type, location.line
 *   • ir.types   — per-method start_line / end_line to scope the calls
 *
 * This file is retained so that circle-ir-ai can consume the per-method
 * call-count breakdown and apply semantic reasoning to distinguish genuine
 * feature envy from intentional delegation.
 *
 * Detects methods that call another class's methods far more often than
 * their own class's — a sign that the method "envies" the other class
 * and should probably be moved there.
 *
 * Detection strategy:
 *   1. For each method in each class, collect all call sites in its line range.
 *   2. Separate calls into:
 *        internal — receiver is 'this' / 'self' / null (own class)
 *        external — receiver_type != own class name (other classes)
 *   3. Find the external type with the most calls (external_max).
 *   4. Emit a note when:
 *        external_max >= 4  (at least 4 calls to another class)
 *      AND
 *        external_max > internal + 2  (clearly prefers the other class)
 *
 * Languages: Java, TypeScript, Python. Bash / Rust — skipped.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';

/** Minimum external calls to flag feature envy (avoids trivial utility calls). */
const MIN_EXTERNAL_CALLS = 4;

/** How many more calls to external type than own type to flag. */
const ENVY_MARGIN = 2;

export interface FeatureEnvyResult {
  envyMethods: Array<{
    className: string;
    methodName: string;
    line: number;
    enviedClass: string;
    externalCalls: number;
    internalCalls: number;
  }>;
}

export class FeatureEnvyPass implements AnalysisPass<FeatureEnvyResult> {
  readonly name = 'feature-envy';
  readonly category = 'architecture' as const;

  run(ctx: PassContext): FeatureEnvyResult {
    const { graph, language } = ctx;

    if (language === 'bash' || language === 'rust') {
      return { envyMethods: [] };
    }

    const file = graph.ir.meta.file;
    const envyMethods: FeatureEnvyResult['envyMethods'] = [];

    for (const type of graph.ir.types) {
      if (type.kind !== 'class') continue;
      const ownName = type.name;

      for (const method of type.methods) {
        const start = method.start_line;
        const end = method.end_line;

        // Collect calls within this method's line range
        const callsInMethod = graph.ir.calls.filter(
          c => c.location.line >= start && c.location.line <= end,
        );

        if (callsInMethod.length === 0) continue;

        let internalCalls = 0;
        const externalCallCounts = new Map<string, number>();

        for (const call of callsInMethod) {
          const receiver = call.receiver?.toLowerCase();
          const receiverType = call.receiver_type;

          // Internal: receiver is 'this'/'self', null, or the own type
          if (
            receiver == null ||
            receiver === 'this' ||
            receiver === 'self' ||
            receiverType == null ||
            receiverType === ownName
          ) {
            internalCalls++;
            continue;
          }

          // External: strip generic parameters from receiver_type
          const extType = receiverType.replace(/<.*>/, '').trim();
          if (extType && extType !== ownName) {
            externalCallCounts.set(extType, (externalCallCounts.get(extType) ?? 0) + 1);
          }
        }

        if (externalCallCounts.size === 0) continue;

        // Find the most-called external type
        let enviedClass = '';
        let externalMax = 0;
        for (const [typeName, count] of externalCallCounts) {
          if (count > externalMax) {
            externalMax = count;
            enviedClass = typeName;
          }
        }

        if (externalMax < MIN_EXTERNAL_CALLS) continue;
        if (externalMax <= internalCalls + ENVY_MARGIN) continue;

        envyMethods.push({
          className: ownName,
          methodName: method.name,
          line: method.start_line,
          enviedClass,
          externalCalls: externalMax,
          internalCalls,
        });

        ctx.addFinding({
          id: `feature-envy-${file}-${method.start_line}`,
          pass: this.name,
          category: this.category,
          rule_id: this.name,
          cwe: 'CWE-1060',
          severity: 'low',
          level: 'note',
          message:
            `Feature Envy: \`${ownName}.${method.name}()\` makes ${externalMax} calls to ` +
            `\`${enviedClass}\` vs ${internalCalls} calls to own class`,
          file,
          line: method.start_line,
          fix:
            `Consider moving \`${method.name}\` to \`${enviedClass}\`, ` +
            `or introducing a collaborator object`,
          evidence: {
            envied_class: enviedClass,
            external_calls: externalMax,
            internal_calls: internalCalls,
          },
        });
      }
    }

    return { envyMethods };
  }
}
