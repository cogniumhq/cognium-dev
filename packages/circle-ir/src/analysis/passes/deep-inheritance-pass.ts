/**
 * Pass #29: deep-inheritance (CWE-1086, category: architecture)
 *
 * Detects class inheritance chains deeper than the configured threshold
 * (default: 5). Deep inheritance hierarchies increase coupling, make code
 * harder to understand, and indicate a design smell (violation of composition
 * over inheritance).
 *
 * Detection strategy:
 *   1. Build a parentMap: className → parentName from `ir.types[*].extends`.
 *   2. For each class with a known `start_line`, walk up the parentMap
 *      counting depth. Stop at depth 20 to defend against cycles.
 *   3. If depth > THRESHOLD, emit a finding at the class `start_line`.
 *
 * Languages: Java, JavaScript/TypeScript, Python. Rust/Bash do not have
 * class inheritance — skipped.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';

const DEPTH_THRESHOLD = 5;
const CYCLE_GUARD = 20;

export interface DeepInheritanceResult {
  deepClasses: Array<{ className: string; depth: number; line: number }>;
}

export class DeepInheritancePass implements AnalysisPass<DeepInheritanceResult> {
  readonly name = 'deep-inheritance';
  readonly category = 'architecture' as const;

  run(ctx: PassContext): DeepInheritanceResult {
    const { graph, language } = ctx;

    if (language === 'rust' || language === 'bash') {
      return { deepClasses: [] };
    }

    const file = graph.ir.meta.file;
    const types = graph.ir.types;

    if (types.length === 0) return { deepClasses: [] };

    // Build parentMap: class name → parent class name
    const parentMap = new Map<string, string>();
    for (const typeInfo of types) {
      if (typeInfo.extends) {
        // Strip generic parameters (e.g., "BaseRepo<User>" → "BaseRepo")
        const parentName = typeInfo.extends.replace(/<.*>/, '').trim();
        if (parentName) {
          parentMap.set(typeInfo.name, parentName);
        }
      }
    }

    const deepClasses: DeepInheritanceResult['deepClasses'] = [];

    for (const typeInfo of types) {
      if (typeInfo.kind !== 'class') continue;
      if (typeInfo.start_line <= 0) continue;

      // Walk up the inheritance chain
      let depth = 0;
      let current: string | undefined = parentMap.get(typeInfo.name);
      const visited = new Set<string>([typeInfo.name]);

      while (current !== undefined && depth < CYCLE_GUARD) {
        depth++;
        if (visited.has(current)) break; // cycle guard
        visited.add(current);
        current = parentMap.get(current);
      }

      if (depth > DEPTH_THRESHOLD) {
        deepClasses.push({ className: typeInfo.name, depth, line: typeInfo.start_line });

        ctx.addFinding({
          id: `deep-inheritance-${file}-${typeInfo.start_line}`,
          pass: this.name,
          category: this.category,
          rule_id: this.name,
          cwe: 'CWE-1086',
          severity: 'low',
          level: 'warning',
          message:
            `Deep inheritance: class \`${typeInfo.name}\` has inheritance depth ${depth} (threshold: ${DEPTH_THRESHOLD})`,
          file,
          line: typeInfo.start_line,
          fix:
            `Refactor to prefer composition over inheritance. ` +
            `Consider extracting shared behaviour into interfaces or mixins.`,
          evidence: { depth, threshold: DEPTH_THRESHOLD },
        });
      }
    }

    return { deepClasses };
  }
}
