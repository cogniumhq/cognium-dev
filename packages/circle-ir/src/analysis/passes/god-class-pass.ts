/**
 * Pass #86: god-class (CWE-1060, category: architecture)
 *
 * Detects "God Class" anti-pattern: a class that does too much, is poorly
 * cohesive, and is heavily coupled to external types. These classes are hard
 * to test, maintain, and evolve.
 *
 * Three CK metrics are computed inline (the metrics pipeline runs separately
 * and its results are not available here):
 *
 *   WMC  — Weighted Methods per Class: Σ v(G) per method, where v(G) is
 *           McCabe cyclomatic complexity = CFG edges − nodes + 2.
 *           Fallback = 1 per method when CFG data is absent.
 *
 *   LCOM2 — Lack of Cohesion of Methods (0–1 scale):
 *           (P − Q) / max(1, m*(m−1)/2)
 *           P = method pairs sharing no fields, Q = pairs sharing ≥1 field.
 *           Field access is inferred from DFG defs/uses whose variable name
 *           matches a declared field name (name-match heuristic).
 *
 *   CBO  — Coupling Between Objects: count of distinct external type names
 *           referenced in parameter types, field types, or call receiver_type
 *           within the class, excluding primitives and same-class references.
 *
 * A finding is emitted when at least 2 of the 3 thresholds are exceeded:
 *   WMC > 47   (SonarQube default)
 *   LCOM2 > 0.8
 *   CBO > 14   (SATD threshold)
 *
 * Languages: Java, TypeScript, Python. Bash / Rust — skipped.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';

const WMC_THRESHOLD  = 47;
const LCOM2_THRESHOLD = 0.8;
const CBO_THRESHOLD  = 14;

/** Java / TypeScript primitive type names to exclude from CBO. */
const PRIMITIVES = new Set([
  'void', 'boolean', 'byte', 'short', 'int', 'long', 'float', 'double', 'char',
  'string', 'number', 'boolean', 'object', 'any', 'never', 'unknown',
  'String', 'Integer', 'Long', 'Double', 'Boolean', 'Object', 'Number',
  'null', 'undefined',
]);

export interface GodClassResult {
  godClasses: Array<{
    className: string;
    line: number;
    wmc: number;
    lcom2: number;
    cbo: number;
  }>;
}

export class GodClassPass implements AnalysisPass<GodClassResult> {
  readonly name = 'god-class';
  readonly category = 'architecture' as const;

  run(ctx: PassContext): GodClassResult {
    const { graph, language } = ctx;

    if (language === 'bash' || language === 'rust') {
      return { godClasses: [] };
    }

    const file = graph.ir.meta.file;
    const godClasses: GodClassResult['godClasses'] = [];

    for (const type of graph.ir.types) {
      if (type.kind !== 'class') continue;
      if (type.methods.length < 2) continue;

      const wmc  = this.computeWMC(graph.ir.cfg.blocks, graph.ir.cfg.edges, type);
      const lcom2 = this.computeLCOM2(graph.ir.dfg, type);
      const cbo   = this.computeCBO(graph.ir.calls, type);

      const violations = [
        wmc  > WMC_THRESHOLD,
        lcom2 > LCOM2_THRESHOLD,
        cbo  > CBO_THRESHOLD,
      ].filter(Boolean).length;

      if (violations < 2) continue;

      godClasses.push({ className: type.name, line: type.start_line, wmc, lcom2, cbo });

      const lcom2Str = lcom2.toFixed(2);
      ctx.addFinding({
        id: `god-class-${file}-${type.start_line}`,
        pass: this.name,
        category: this.category,
        rule_id: this.name,
        cwe: 'CWE-1060',
        severity: 'medium',
        level: 'warning',
        message:
          `God class detected: \`${type.name}\` exceeds ${violations}/3 thresholds ` +
          `(WMC=${wmc}, LCOM2=${lcom2Str}, CBO=${cbo})`,
        file,
        line: type.start_line,
        fix:
          'Break into focused classes: extract cohesive method groups into separate types. ' +
          'Apply Single Responsibility Principle.',
        evidence: { wmc, lcom2: parseFloat(lcom2Str), cbo },
      });
    }

    return { godClasses };
  }

  /** Compute WMC = Σ v(G) for all methods. v(G) = edges − nodes + 2. */
  private computeWMC(
    blocks: Array<{ id: number; start_line: number; end_line: number }>,
    edges: Array<{ from: number; to: number }>,
    type: { methods: Array<{ start_line: number; end_line: number }> },
  ): number {
    let wmc = 0;

    for (const method of type.methods) {
      // Find CFG blocks within this method's line range
      const methodBlockIds = new Set(
        blocks
          .filter(b => b.start_line >= method.start_line && b.end_line <= method.end_line)
          .map(b => b.id),
      );

      if (methodBlockIds.size === 0) {
        // No CFG data — fallback complexity of 1
        wmc += 1;
        continue;
      }

      // Count edges between blocks within this method
      const methodEdges = edges.filter(
        e => methodBlockIds.has(e.from) && methodBlockIds.has(e.to),
      );

      const n = methodBlockIds.size;
      const e = methodEdges.length;
      const vG = Math.max(1, e - n + 2);
      wmc += vG;
    }

    return wmc;
  }

  /**
   * Compute LCOM2 = (P − Q) / max(1, m*(m−1)/2) clamped to [0, 1].
   * Uses DFG variable names intersected with declared field names.
   */
  private computeLCOM2(
    dfg: { defs: Array<{ variable: string; line: number }>; uses: Array<{ variable: string; line: number }> },
    type: {
      fields: Array<{ name: string }>;
      methods: Array<{ start_line: number; end_line: number }>;
    },
  ): number {
    const m = type.methods.length;
    if (m < 2) return 0;

    const fieldNames = new Set(type.fields.map(f => f.name));
    if (fieldNames.size === 0) return 0;

    // For each method, collect the set of field names it accesses (def or use)
    const methodFields: Set<string>[] = type.methods.map(method => {
      const accessed = new Set<string>();
      const start = method.start_line;
      const end = method.end_line;

      for (const def of dfg.defs) {
        if (def.line >= start && def.line <= end && fieldNames.has(def.variable)) {
          accessed.add(def.variable);
        }
      }
      for (const use of dfg.uses) {
        if (use.line >= start && use.line <= end && fieldNames.has(use.variable)) {
          accessed.add(use.variable);
        }
      }
      return accessed;
    });

    let P = 0; // pairs with no shared fields
    let Q = 0; // pairs with >= 1 shared field

    for (let i = 0; i < m; i++) {
      for (let j = i + 1; j < m; j++) {
        const shared = [...methodFields[i]].some(f => methodFields[j].has(f));
        if (shared) {
          Q++;
        } else {
          P++;
        }
      }
    }

    const total = (m * (m - 1)) / 2;
    const raw = (P - Q) / Math.max(1, total);
    return Math.min(1, Math.max(0, raw));
  }

  /**
   * Compute CBO = count of distinct external type names referenced in the class.
   * Sources: call receiver_type, method parameter types, field types.
   */
  private computeCBO(
    calls: Array<{ receiver_type?: string | null; location: { line: number } }>,
    type: {
      name: string;
      fields: Array<{ type: string | null }>;
      methods: Array<{ parameters: Array<{ type: string | null }>; start_line: number; end_line: number }>;
    },
  ): number {
    const externalTypes = new Set<string>();
    const ownName = type.name.toLowerCase();

    const addType = (t: string | null | undefined) => {
      if (!t) return;
      // Strip generic parameters: List<String> → List
      const base = t.replace(/<.*>/, '').replace(/\[\]/g, '').replace(/\?/g, '').trim();
      if (!base) return;
      if (PRIMITIVES.has(base)) return;
      if (base.toLowerCase() === ownName) return;
      externalTypes.add(base);
    };

    // Field types
    for (const field of type.fields) {
      addType(field.type);
    }

    // Method parameter types
    for (const method of type.methods) {
      for (const param of method.parameters) {
        addType(param.type);
      }
    }

    // Call receiver types within this class's line range
    const classStart = type.methods.reduce(
      (mn, m) => Math.min(mn, m.start_line), Infinity,
    );
    const classEnd = type.methods.reduce(
      (mx, m) => Math.max(mx, m.end_line), 0,
    );

    for (const call of calls) {
      const ln = call.location.line;
      if (ln >= classStart && ln <= classEnd) {
        addType(call.receiver_type ?? null);
      }
    }

    return externalTypes.size;
  }
}
