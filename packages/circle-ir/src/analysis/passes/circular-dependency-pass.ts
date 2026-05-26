/**
 * Pass #68: circular-dependency (project-level)
 *
 * Detects cycles in the module import graph using Tarjan's SCC algorithm.
 * Circular dependencies create tight coupling, hamper tree-shaking, and can
 * cause subtle initialization-order bugs.
 *
 * This is a project-level pass — it does NOT extend AnalysisPass.
 * It is invoked from analyzeProject() after all per-file analyses are complete.
 *
 * Category: architecture | Severity: medium | Level: warning | CWE-1047
 */

import type { SastFinding } from '../../types/index.js';
import type { ProjectGraph } from '../../graph/project-graph.js';
import type { ImportGraph } from '../../graph/import-graph.js';

export class CircularDependencyPass {
  run(_projectGraph: ProjectGraph, importGraph: ImportGraph): SastFinding[] {
    const findings: SastFinding[] = [];
    const cycles = importGraph.findCycles();

    for (const cycle of cycles) {
      // Sort for determinism; use alphabetically-first file as anchor
      const sorted = [...cycle].sort();
      const anchor = sorted[0];

      const finding: SastFinding = {
        id:       `circular-dependency-${anchor.replace(/[^a-z0-9]/gi, '-')}`,
        pass:     'circular-dependency',
        category: 'architecture',
        rule_id:  'circular-dependency',
        cwe:      'CWE-1047',
        severity: 'medium',
        level:    'warning',
        message:  `Circular import dependency detected involving ${cycle.size} modules: ${sorted.join(' → ')}.`,
        file:     anchor,
        line:     1,
        evidence: { cycle: sorted, size: cycle.size },
      };
      findings.push(finding);
    }

    return findings;
  }
}
