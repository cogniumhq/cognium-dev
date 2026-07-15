/**
 * `list_entry_points` tool — enumerate attacker-reachable entry points.
 */

import { z } from 'zod';
import { resolve } from 'path';
import type { ToolContext, ToolResult } from './types.js';
import { textResult } from './types.js';
import { truncateArray, MAX_ENTRY_POINTS } from '../util/serialize.js';

export const listEntryPointsInputShape = {
  project_root: z.string().describe('Absolute path to the project root.'),
  language: z.enum(['java', 'javascript', 'typescript', 'python', 'go', 'rust', 'bash', 'html'])
    .optional()
    .describe('Restrict to a single language.'),
} as const;

export const listEntryPointsConfig = {
  title: 'List attacker-reachable entry points',
  description:
    'Enumerate all entry-point methods (HTTP route handlers, middlewares, event listeners, cron/queue ' +
    'consumers) grouped by framework and language. Sourced from circle-ir `runtime_registrations` — the ' +
    'call-graph edges that framework registration establishes but the raw AST does not surface. Answers ' +
    '"what is the attack surface of this codebase?"',
  inputSchema: listEntryPointsInputShape,
} as const;

export function makeListEntryPointsHandler(ctx: ToolContext) {
  return async (args: {
    project_root: string;
    language?: 'java' | 'javascript' | 'typescript' | 'python' | 'go' | 'rust' | 'bash' | 'html';
  }): Promise<ToolResult> => {
    const root = resolve(args.project_root);
    const { analysis, cacheHit } = await ctx.cache.getOrCompute(root, {});

    const entryPoints: Array<Record<string, unknown>> = [];
    for (const fa of analysis.files) {
      if (args.language && fa.analysis.meta.language !== args.language) continue;
      for (const reg of fa.analysis.runtime_registrations ?? []) {
        entryPoints.push({
          file: fa.file,
          language: fa.analysis.meta.language,
          kind: reg.kind,
          framework: reg.framework,
          method: reg.handler.name,
          handlerLine: reg.handler.line,
          registrar: {
            method: reg.registrar.method,
            receiver: reg.registrar.receiver,
            line: reg.registrar.line,
          },
          route: reg.path,
        });
      }
    }

    const byFramework = countBy(entryPoints, e => String(e.framework ?? 'unknown'));
    const byLanguage = countBy(entryPoints, e => String(e.language ?? 'unknown'));
    const byKind = countBy(entryPoints, e => String(e.kind ?? 'unknown'));

    const { items, truncated, totalCount } = truncateArray(entryPoints, MAX_ENTRY_POINTS);

    return textResult({
      projectRoot: root,
      cacheHit,
      totalEntryPoints: totalCount,
      truncated,
      byFramework,
      byLanguage,
      byKind,
      entryPoints: items,
    });
  };
}

function countBy<T>(items: T[], key: (t: T) => string): Record<string, number> {
  const out: Record<string, number> = {};
  for (const i of items) {
    const k = key(i);
    out[k] = (out[k] ?? 0) + 1;
  }
  return out;
}
