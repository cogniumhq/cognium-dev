/**
 * `describe_source` tool — enumerate taint-source patterns known to
 * circle-ir for a given source category (e.g. `http_param`, `http_header`,
 * `db_result`, `env`, `file`).
 *
 * Used by an LLM to answer "where would attacker-controlled data enter
 * this codebase from `http_body`?" without guessing framework APIs.
 */

import { z } from 'zod';
import type { ToolContext, ToolResult } from './types.js';
import { textResult, errorResult } from './types.js';
import { loadSourceCatalog } from '../resources/catalogs.js';

export const describeSourceInputShape = {
  source_type: z.string()
    .describe('Source category, e.g. "http_param", "http_header", "http_body", "http_cookie", "db_result", "env", "file".'),
  language: z.enum(['java', 'javascript', 'typescript', 'python', 'go', 'rust', 'bash', 'html'])
    .optional()
    .describe('Restrict patterns to this language.'),
} as const;

export const describeSourceConfig = {
  title: 'Describe taint source category',
  description:
    'Return every taint-source pattern (method / class / property / annotation) that circle-ir treats as ' +
    'a source of the given category. Use when the LLM needs to know "which framework APIs count as an ' +
    'HTTP body source?" or "what constitutes an env-var source?"',
  inputSchema: describeSourceInputShape,
} as const;

export function makeDescribeSourceHandler(_ctx: ToolContext) {
  return async (args: { source_type: string; language?: string }): Promise<ToolResult> => {
    const catalog = loadSourceCatalog();
    const matches = catalog.filter((s) => {
      if (s.type !== args.source_type) return false;
      if (args.language && s.languages && !s.languages.includes(args.language as never)) return false;
      return true;
    });

    if (matches.length === 0) {
      const known = [...new Set(catalog.map((s) => s.type))].sort();
      return errorResult(
        `No source patterns for source_type "${args.source_type}"` +
        (args.language ? ` in language "${args.language}"` : '') +
        `. Known source types: ${known.join(', ')}`,
      );
    }

    return textResult({
      source_type: args.source_type,
      language: args.language ?? 'any',
      totalPatterns: matches.length,
      patterns: matches.slice(0, 200).map((s) => ({
        method: s.method,
        class: s.class,
        property: s.property,
        object: s.object,
        annotation: s.annotation,
        methodAnnotation: s.methodAnnotation,
        severity: s.severity,
        returnTainted: s.returnTainted,
        paramTainted: s.paramTainted,
        propertyTainted: s.propertyTainted,
        languages: s.languages,
        note: s.note,
      })),
      truncated: matches.length > 200,
    });
  };
}
