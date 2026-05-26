/**
 * Pass: missing-override (#64)
 *
 * Detects Java methods that override a parent class method but lack the
 * @Override annotation. Without @Override the compiler cannot catch signature
 * mismatches introduced by a parent-class refactoring.
 *
 * Detection strategy:
 *   1. Build a map of class → method names from all types in the IR.
 *   2. Build a parent map: class name → direct parent class name (strip generics).
 *   3. For each class that has a parent in the same file, walk the inheritance
 *      chain (max 10 hops, cycle guard) to collect all ancestor method names.
 *   4. For each non-constructor, non-private, non-static, non-abstract method
 *      whose name appears in the ancestor set — if @Override is absent → finding.
 *
 * Language: Java only.
 * Dedup: at most one finding per class:method pair.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';

export interface MissingOverrideResult {
  findings: number;
}

export class MissingOverridePass implements AnalysisPass<MissingOverrideResult> {
  readonly name = 'missing-override';
  readonly category = 'maintainability' as const;

  run(ctx: PassContext): MissingOverrideResult {
    const { graph, language } = ctx;

    if (language !== 'java') return { findings: 0 };

    const { types } = graph.ir;
    const file = graph.ir.meta.file;

    if (types.length === 0) return { findings: 0 };

    // Build map: class name → Set<method name>
    const methodsByClass = new Map<string, Set<string>>();
    for (const type of types) {
      methodsByClass.set(type.name, new Set(type.methods.map(m => m.name)));
    }

    // Build parent map: class name → direct parent class name (generics stripped)
    const parentMap = new Map<string, string>();
    for (const type of types) {
      if (type.extends) {
        const parent = type.extends.replace(/<[^>]*>/g, '').trim();
        parentMap.set(type.name, parent);
      }
    }

    if (parentMap.size === 0) return { findings: 0 };

    // Walk inheritance chain to collect all ancestor method names
    const getAncestorMethods = (className: string): Set<string> => {
      const methods = new Set<string>();
      const visited  = new Set<string>();
      let current = parentMap.get(className);
      let hops = 0;
      while (current && !visited.has(current) && hops < 10) {
        visited.add(current);
        const parentMethods = methodsByClass.get(current);
        if (parentMethods) {
          for (const m of parentMethods) methods.add(m);
        }
        current = parentMap.get(current);
        hops++;
      }
      return methods;
    };

    const dedup = new Set<string>();
    let count = 0;

    for (const type of types) {
      if (!parentMap.has(type.name)) continue;

      const ancestorMethods = getAncestorMethods(type.name);
      if (ancestorMethods.size === 0) continue;

      for (const method of type.methods) {
        // Skip constructors (same name as class)
        if (method.name === type.name) continue;
        // Skip private / static / abstract methods
        if (method.modifiers.includes('private')) continue;
        if (method.modifiers.includes('static')) continue;
        if (method.modifiers.includes('abstract')) continue;

        if (!ancestorMethods.has(method.name)) continue;
        if (method.annotations.includes('Override')) continue;

        const key = `${type.name}:${method.name}`;
        if (dedup.has(key)) continue;
        dedup.add(key);

        count++;
        ctx.addFinding({
          id: `missing-override-${file}-${method.start_line}`,
          pass: this.name,
          category: this.category,
          rule_id: 'missing-override',
          severity: 'low',
          level: 'warning',
          message:
            `Method \`${method.name}()\` in \`${type.name}\` overrides a parent method ` +
            `but lacks @Override`,
          file,
          line: method.start_line,
          fix: 'Add @Override to make the intent explicit and catch signature mismatches at compile time',
          evidence: { className: type.name, methodName: method.name },
        });
      }
    }

    return { findings: count };
  }
}
