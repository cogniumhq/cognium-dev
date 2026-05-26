/**
 * Pass: unused-interface-method (#66)
 *
 * Detects interface methods that are never called anywhere in the current file.
 * This is a conservative single-file check: if a method is called at all (even
 * through a different receiver), it is not flagged.
 *
 * Detection strategy:
 *   1. Collect all method names called anywhere in the file.
 *   2. For each interface type, for each method whose name does not appear in
 *      the called-method set → emit finding.
 *
 * Note: This analysis is intentionally conservative. Cross-file callers are
 * not checked; downstream consumers should suppress findings for public APIs.
 *
 * Languages: Java, TypeScript.
 * Dedup: at most one finding per interface:method pair.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';

export interface UnusedInterfaceMethodResult {
  findings: number;
}

export class UnusedInterfaceMethodPass implements AnalysisPass<UnusedInterfaceMethodResult> {
  readonly name = 'unused-interface-method';
  readonly category = 'maintainability' as const;

  run(ctx: PassContext): UnusedInterfaceMethodResult {
    const { graph, language } = ctx;

    if (language !== 'java' && language !== 'typescript') return { findings: 0 };

    const { types, calls } = graph.ir;
    const file = graph.ir.meta.file;

    // Collect all method names that appear in at least one call in this file
    const calledMethods = new Set(calls.map(c => c.method_name));

    const dedup = new Set<string>();
    let count = 0;

    for (const type of types) {
      if (type.kind !== 'interface') continue;

      for (const method of type.methods) {
        if (calledMethods.has(method.name)) continue;

        const key = `${type.name}:${method.name}`;
        if (dedup.has(key)) continue;
        dedup.add(key);

        count++;
        ctx.addFinding({
          id: `unused-interface-method-${file}-${method.start_line}`,
          pass: this.name,
          category: this.category,
          rule_id: 'unused-interface-method',
          severity: 'low',
          level: 'note',
          message:
            `Interface method \`${method.name}()\` in \`${type.name}\` is never called ` +
            `in this file`,
          file,
          line: method.start_line,
          fix: 'Remove this method or verify it is used from other files; unused interface methods inflate the public API',
          evidence: { interfaceName: type.name, methodName: method.name },
        });
      }
    }

    return { findings: count };
  }
}
