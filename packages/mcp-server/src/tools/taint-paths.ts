/**
 * `taint_paths` tool — list cross-file taint flows with optional filters.
 */

import { z } from 'zod';
import { resolve } from 'path';
import type { ToolContext, ToolResult } from './types.js';
import { textResult } from './types.js';
import { truncateArray, truncateString, MAX_TAINT_PATHS } from '../util/serialize.js';

export const taintPathsInputShape = {
  project_root: z.string().describe('Absolute path to the project root.'),
  source_file: z.string().optional().describe('Only paths whose source is in this file.'),
  sink_file: z.string().optional().describe('Only paths whose sink is in this file.'),
  sink_type: z.string().optional()
    .describe('Only paths with this sink type (e.g. "sql_injection", "command_injection").'),
  max_paths: z.number().int().min(1).max(500).optional()
    .describe('Cap on returned paths. Defaults to 50.'),
} as const;

export const taintPathsConfig = {
  title: 'List cross-file taint paths',
  description:
    'List cross-file taint flows in a previously-scanned project, filtered by source file, sink file, or ' +
    'sink type. Use to enumerate every attacker-reachable data flow between files. Requires that `scan` ' +
    'has been called on the project root.',
  inputSchema: taintPathsInputShape,
} as const;

export function makeTaintPathsHandler(ctx: ToolContext) {
  return async (args: {
    project_root: string;
    source_file?: string;
    sink_file?: string;
    sink_type?: string;
    max_paths?: number;
  }): Promise<ToolResult> => {
    const root = resolve(args.project_root);
    const { analysis, cacheHit, analysisMs } = await ctx.cache.getOrCompute(root, {});
    const cap = args.max_paths ?? 50;

    let paths = analysis.taint_paths;
    if (args.source_file) paths = paths.filter(p => p.source.file === args.source_file || p.source.file.endsWith(args.source_file!));
    if (args.sink_file) paths = paths.filter(p => p.sink.file === args.sink_file || p.sink.file.endsWith(args.sink_file!));
    if (args.sink_type) paths = paths.filter(p => p.sink.type === args.sink_type);

    const { items, truncated, totalCount } = truncateArray(paths, Math.min(cap, MAX_TAINT_PATHS));

    return textResult({
      projectRoot: root,
      cacheHit,
      analysisMs,
      crossFileBudgetExceeded: analysis.cross_file_budget_exceeded === true,
      totalMatching: totalCount,
      truncated,
      paths: items.map(p => ({
        id: p.id,
        source: { ...p.source, code: truncateString(p.source.code, 512) },
        sink: { ...p.sink, code: truncateString(p.sink.code, 512) },
        hops: p.hops.map(h => ({ ...h, code: truncateString(h.code, 256) })),
        sanitizers_in_path: p.sanitizers_in_path,
        confidence: p.confidence,
      })),
    });
  };
}
