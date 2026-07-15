/**
 * `list_reachable_sinks` tool — enumerate every sink of a given category
 * that has a demonstrated taint flow (per-file or cross-file). Filters
 * out sinks that are lexically present but not reachable from any source.
 *
 * Answers "which SQL sinks in this project actually receive tainted
 * data?" — the deterministic answer an LLM cannot produce alone.
 */

import { z } from 'zod';
import { resolve } from 'path';
import type { ToolContext, ToolResult } from './types.js';
import { textResult } from './types.js';
import { truncateArray, truncateString, MAX_FINDINGS } from '../util/serialize.js';

export const listReachableSinksInputShape = {
  project_root: z.string().describe('Absolute path to the project root.'),
  sink_type: z.string().optional()
    .describe('Restrict to this sink category (e.g. "sql_injection", "command_injection", "xss").'),
  language: z.enum(['java', 'javascript', 'typescript', 'python', 'go', 'rust', 'bash', 'html'])
    .optional()
    .describe('Restrict to one language.'),
  min_confidence: z.number().min(0).max(1).optional()
    .describe('Minimum flow confidence to include (0.0 - 1.0). Defaults to include all.'),
} as const;

export const listReachableSinksConfig = {
  title: 'List reachable sinks (with taint flow)',
  description:
    'List every sink of the requested category that has an actual taint flow reaching it (per-file OR ' +
    'cross-file). Sinks with no reaching flow are excluded — this is the crucial difference vs. plain ' +
    '"list all method calls named `Runtime.exec`". Use before proposing fixes so the LLM only inspects ' +
    'sinks that are truly reachable from attacker-controlled input.',
  inputSchema: listReachableSinksInputShape,
} as const;

interface ReachableSink {
  file: string;
  language: string;
  sink_type: string;
  sink_line: number;
  source_type?: string;
  source_line?: number;
  confidence?: number;
  sanitized?: boolean;
  scope: 'per-file' | 'cross-file';
  path_id?: string;
  path_hops?: number;
  snippet?: string;
}

export function makeListReachableSinksHandler(ctx: ToolContext) {
  return async (args: {
    project_root: string;
    sink_type?: string;
    language?: string;
    min_confidence?: number;
  }): Promise<ToolResult> => {
    const root = resolve(args.project_root);
    const { analysis, cacheHit } = await ctx.cache.getOrCompute(root, {});

    const minLevel = args.min_confidence ?? 0;
    const passesConfidence = (c?: number) => {
      if (c === undefined) return true;
      return c >= minLevel;
    };

    const reachable: ReachableSink[] = [];

    // Per-file taint flows.
    for (const fa of analysis.files) {
      const lang = fa.analysis.meta.language;
      if (args.language && lang !== args.language) continue;
      for (const flow of fa.analysis.taint?.flows ?? []) {
        if (args.sink_type && flow.sink_type !== args.sink_type) continue;
        if (!passesConfidence(flow.confidence)) continue;
        reachable.push({
          file: fa.file,
          language: lang,
          sink_type: flow.sink_type,
          sink_line: flow.sink_line,
          source_type: flow.source_type,
          source_line: flow.source_line,
          confidence: flow.confidence,
          sanitized: flow.sanitized,
          scope: 'per-file',
        });
      }
    }

    // Cross-file taint paths (indexed on the analysis root).
    for (const path of analysis.taint_paths) {
      if (args.sink_type && path.sink.type !== args.sink_type) continue;
      // Language filter is best-effort: find the file's language via the sink file.
      if (args.language) {
        const fa = analysis.files.find((f) => f.file === path.sink.file);
        if (!fa) continue;
        if (fa.analysis.meta.language !== args.language) continue;
      }
      if (!passesConfidence(path.confidence)) continue;
      reachable.push({
        file: path.sink.file,
        language: analysis.files.find((f) => f.file === path.sink.file)?.analysis.meta.language ?? 'unknown',
        sink_type: path.sink.type,
        sink_line: path.sink.line,
        source_type: path.source.type,
        source_line: path.source.line,
        confidence: path.confidence,
        scope: 'cross-file',
        path_id: path.id,
        path_hops: path.hops.length,
        snippet: truncateString(path.sink.code, 512),
      });
    }

    const byType: Record<string, number> = {};
    const byLanguage: Record<string, number> = {};
    for (const r of reachable) {
      byType[r.sink_type] = (byType[r.sink_type] ?? 0) + 1;
      byLanguage[r.language] = (byLanguage[r.language] ?? 0) + 1;
    }

    const { items, truncated, totalCount } = truncateArray(reachable, MAX_FINDINGS);

    return textResult({
      projectRoot: root,
      cacheHit,
      filters: {
        sink_type: args.sink_type ?? 'any',
        language: args.language ?? 'any',
        min_confidence: args.min_confidence ?? 'any',
      },
      totalReachable: totalCount,
      truncated,
      bySinkType: byType,
      byLanguage,
      sinks: items,
    });
  };
}
