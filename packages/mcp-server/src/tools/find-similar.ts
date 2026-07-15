/**
 * `find_similar` tool — given a finding id (from a prior `scan`), return
 * every other finding in the same project that shares the same
 * `rule_id` + `sink_type` (or matches by structural similarity of the
 * source→sink pair).
 *
 * Answers "did I miss this pattern anywhere else in the code?" — a
 * common LLM follow-up after triaging one issue.
 */

import { z } from 'zod';
import { resolve } from 'path';
import type { ToolContext, ToolResult } from './types.js';
import { textResult, errorResult } from './types.js';
import { truncateArray, truncateString, MAX_FINDINGS } from '../util/serialize.js';

export const findSimilarInputShape = {
  project_root: z.string().describe('Absolute path to the project root.'),
  finding_id: z.string()
    .describe('Anchor finding id (from `scan` output). Similar findings are relative to this one.'),
  match_by: z.enum(['rule_and_sink', 'rule', 'sink']).optional()
    .describe('Similarity axis: `rule_and_sink` (default) matches rule_id + taint sink_type, `rule` matches rule_id only, `sink` matches sink_type only.'),
  max_results: z.number().int().min(1).max(200).optional()
    .describe('Cap on returned findings. Defaults to 50.'),
} as const;

export const findSimilarConfig = {
  title: 'Find structurally similar findings',
  description:
    'Given one SastFinding id, return other findings in the same project that share the same rule_id ' +
    'and/or taint sink type. Use after triaging a finding to catch the same vulnerability pattern ' +
    'elsewhere without re-scanning or re-prompting.',
  inputSchema: findSimilarInputShape,
} as const;

export function makeFindSimilarHandler(ctx: ToolContext) {
  return async (args: {
    project_root: string;
    finding_id: string;
    match_by?: 'rule_and_sink' | 'rule' | 'sink';
    max_results?: number;
  }): Promise<ToolResult> => {
    const root = resolve(args.project_root);
    const { analysis, cacheHit } = await ctx.cache.getOrCompute(root, {});
    const matchBy = args.match_by ?? 'rule_and_sink';
    const cap = Math.min(args.max_results ?? 50, MAX_FINDINGS);

    // Locate anchor.
    let anchor: { rule_id: string; sink_type?: string; file: string; line: number } | null = null;
    for (const fa of analysis.files) {
      for (const f of fa.analysis.findings ?? []) {
        if (f.id === args.finding_id) {
          const sink = fa.analysis.taint?.flows?.find((fl) => fl.sink_line === f.line);
          anchor = {
            rule_id: f.rule_id,
            sink_type: sink?.sink_type,
            file: fa.file,
            line: f.line,
          };
          break;
        }
      }
      if (anchor) break;
    }
    if (!anchor) {
      return errorResult(
        `Finding not found: ${args.finding_id}. Call \`scan\` first, then pass an id from its output.`,
      );
    }

    // Collect matches (exclude the anchor itself).
    const matches: Array<Record<string, unknown>> = [];
    for (const fa of analysis.files) {
      for (const f of fa.analysis.findings ?? []) {
        if (f.id === args.finding_id) continue;
        const sink = fa.analysis.taint?.flows?.find((fl) => fl.sink_line === f.line);
        const sinkType = sink?.sink_type;

        const ruleMatch = f.rule_id === anchor.rule_id;
        const sinkMatch = sinkType && anchor.sink_type && sinkType === anchor.sink_type;

        let isMatch = false;
        if (matchBy === 'rule_and_sink') isMatch = Boolean(ruleMatch && (anchor.sink_type ? sinkMatch : true));
        else if (matchBy === 'rule') isMatch = ruleMatch;
        else if (matchBy === 'sink') isMatch = Boolean(sinkMatch);

        if (!isMatch) continue;
        matches.push({
          id: f.id,
          rule_id: f.rule_id,
          category: f.category,
          severity: f.severity,
          file: fa.file,
          line: f.line,
          sink_type: sinkType,
          message: truncateString(f.message, 512),
          snippet: truncateString(f.snippet, 512),
        });
      }
    }

    const { items, truncated, totalCount } = truncateArray(matches, cap);

    return textResult({
      projectRoot: root,
      cacheHit,
      anchor: {
        id: args.finding_id,
        rule_id: anchor.rule_id,
        sink_type: anchor.sink_type,
        file: anchor.file,
        line: anchor.line,
      },
      matchBy,
      totalMatches: totalCount,
      truncated,
      similar: items,
    });
  };
}
