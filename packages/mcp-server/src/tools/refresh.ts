/**
 * `refresh` tool — manual cache invalidation. The server auto-invalidates
 * on file mtime change, but callers may want to force a re-scan (e.g.
 * after a git checkout or when developing analyzer rules).
 */

import { z } from 'zod';
import { resolve } from 'path';
import type { ToolContext, ToolResult } from './types.js';
import { textResult } from './types.js';

export const refreshInputShape = {
  project_root: z.string().optional()
    .describe('Absolute path to the project root to invalidate. If omitted, every cached project is cleared.'),
} as const;

export const refreshConfig = {
  title: 'Refresh analysis cache',
  description:
    'Invalidate cached analysis for one project (when `project_root` is provided) or every cached project ' +
    '(when omitted). The next tool call that needs analysis will re-run `analyzeProject`. Use after a git ' +
    'checkout, dependency change, or when authoring / testing analyzer rules.',
  inputSchema: refreshInputShape,
} as const;

export function makeRefreshHandler(ctx: ToolContext) {
  return async (args: { project_root?: string }): Promise<ToolResult> => {
    if (args.project_root) {
      const abs = resolve(args.project_root);
      const removed = ctx.cache.invalidate(abs);
      return textResult({
        projectRoot: abs,
        entriesRemoved: removed,
        cacheSizeAfter: ctx.cache.size(),
      });
    }
    const removed = ctx.cache.clear();
    return textResult({
      cleared: 'all',
      entriesRemoved: removed,
      cacheSizeAfter: ctx.cache.size(),
    });
  };
}
