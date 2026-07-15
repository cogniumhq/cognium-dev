/**
 * `explain_finding` tool — enrich a single SastFinding with CWE metadata,
 * remediation guidance, and sanitizer alternatives.
 */

import { z } from 'zod';
import { RULE_DEFINITIONS, type SinkType } from 'circle-ir';
import { resolve } from 'path';
import type { ToolContext, ToolResult } from './types.js';
import { textResult, errorResult } from './types.js';
import { truncateString } from '../util/serialize.js';

export const explainFindingInputShape = {
  project_root: z.string().describe('Absolute path to the project root that was previously scanned.'),
  finding_id: z.string().describe('The `id` field of a SastFinding returned by `scan`.'),
} as const;

export const explainFindingConfig = {
  title: 'Explain finding',
  description:
    'Return full context for a single SastFinding: CWE metadata (name, short/full description, remediation, ' +
    'CVSS-like score), source-code snippet, and — if the finding is a taint sink — the list of sanitizers ' +
    'that would neutralize it. Use before proposing a fix so the LLM cites authoritative rule content.',
  inputSchema: explainFindingInputShape,
} as const;

export function makeExplainFindingHandler(ctx: ToolContext) {
  return async (args: { project_root: string; finding_id: string }): Promise<ToolResult> => {
    const projectRoot = resolve(args.project_root);
    // Try every cached option-set for this root.
    // We don't know which option-set was used at scan time, so we scan them all.
    for (const opts of enumerateCachedOptionSets(ctx, projectRoot)) {
      const { analysis } = await ctx.cache.getOrCompute(projectRoot, opts);
      for (const fa of analysis.files) {
        for (const f of fa.analysis.findings ?? []) {
          if (f.id !== args.finding_id) continue;
          const rule = f.rule_id in RULE_DEFINITIONS
            ? RULE_DEFINITIONS[f.rule_id as SinkType]
            : undefined;
          return textResult({
            finding: {
              ...f,
              message: truncateString(f.message),
              snippet: truncateString(f.snippet),
              fix: truncateString(f.fix),
            },
            rule: rule
              ? {
                name: rule.name,
                shortDescription: rule.shortDescription,
                fullDescription: rule.fullDescription,
                remediation: rule.remediation,
                cvssScore: rule.cvssScore,
                severityLevel: rule.severityLevel,
                cwe: rule.cwe,
              }
              : { note: 'No RULE_DEFINITIONS entry — this rule_id is a quality/reliability pass, not a taint sink. Consult PASSES.md via `cognium://passes` resource for canonical metadata.' },
          });
        }
      }
    }
    return errorResult(`Finding not found: ${args.finding_id}. Call \`scan\` first (or with the same option-set that produced the id).`);
  };
}

function enumerateCachedOptionSets(_ctx: ToolContext, _projectRoot: string): Array<{ language?: string; disabledPasses?: string[]; crossFileBudgetMs?: number }> {
  // MVP: only try the default option-set. If none is cached, the caller
  // is instructed to run `scan` first.
  return [{}];
}
