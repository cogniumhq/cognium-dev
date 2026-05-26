/**
 * Pass #71: orphan-module (project-level)
 *
 * Flags modules that have no incoming import edges and are not recognized
 * entry points. Orphan modules are likely dead code, leftover scaffolding,
 * or files that were accidentally disconnected from the project.
 *
 * This is a project-level pass — it does NOT extend AnalysisPass.
 * It is invoked from analyzeProject() after all per-file analyses are complete.
 *
 * Entry points (excluded from flagging): filename base matches
 * /^(index|main|app|server|mod)$/i
 *
 * Category: architecture | Severity: low | Level: note | CWE: none
 */

import type { SastFinding } from '../../types/index.js';
import type { ProjectGraph } from '../../graph/project-graph.js';
import type { ImportGraph } from '../../graph/import-graph.js';

export class OrphanModulePass {
  run(_projectGraph: ProjectGraph, importGraph: ImportGraph): SastFinding[] {
    const findings: SastFinding[] = [];
    const orphans = importGraph.findOrphans();

    for (const file of orphans) {
      const finding: SastFinding = {
        id:       `orphan-module-${file.replace(/[^a-z0-9]/gi, '-')}`,
        pass:     'orphan-module',
        category: 'architecture',
        rule_id:  'orphan-module',
        severity: 'low',
        level:    'note',
        message:  `Module '${file}' has no incoming imports and is not a known entry point. It may be dead code.`,
        file,
        line:     1,
        evidence: { file },
      };
      findings.push(finding);
    }

    return findings;
  }
}
