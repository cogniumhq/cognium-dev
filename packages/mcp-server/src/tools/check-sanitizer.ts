/**
 * `check_sanitizer` tool — deterministic yes/no on whether a function
 * qualifies as a sanitizer for a given sink type.
 *
 * Grounds LLM claims like "this is escaped by DOMPurify.sanitize" —
 * replaces guesswork with a lookup against circle-ir's YAML catalog.
 */

import { z } from 'zod';
import type { ToolContext, ToolResult } from './types.js';
import { textResult } from './types.js';
import { loadSanitizerCatalog } from '../resources/catalogs.js';

export const checkSanitizerInputShape = {
  function_qualified_name: z.string()
    .describe('Fully-qualified function name to check, e.g. "org.owasp.esapi.Encoder.encodeForHTML" or "DOMPurify.sanitize".'),
  sink_type: z.string()
    .describe('Sink category to check against, e.g. "xss", "sql_injection", "command_injection".'),
  language: z.enum(['java', 'javascript', 'typescript', 'python', 'go', 'rust', 'bash', 'html'])
    .optional()
    .describe('Language of the function under check. When omitted, all languages are searched.'),
} as const;

export const checkSanitizerConfig = {
  title: 'Check sanitizer validity',
  description:
    'Verify that a function is a recognized sanitizer for a specific sink type in circle-ir\'s YAML ' +
    'catalog. Returns { isValidSanitizer, matchedRule, notes, alternatives } so an LLM can ground its ' +
    '"this input is safe because it was escaped" reasoning.',
  inputSchema: checkSanitizerInputShape,
} as const;

export function makeCheckSanitizerHandler(_ctx: ToolContext) {
  return async (args: {
    function_qualified_name: string;
    sink_type: string;
    language?: string;
  }): Promise<ToolResult> => {
    const catalog = loadSanitizerCatalog();
    const fq = args.function_qualified_name;
    const fqLower = fq.toLowerCase();
    const fqLast = fq.split(/[.:]/).pop() ?? fq;
    const sinkType = args.sink_type;

    const matches = catalog.filter(entry => {
      // Sink type must match or entry must be typeless (applies to all).
      if (entry.sinkType && entry.sinkType !== sinkType) return false;
      if (args.language && entry.language && entry.language !== args.language) return false;

      const patternMatches = entry.patterns.some(pat => {
        const p = pat.toLowerCase();
        return p === fqLower
          || fqLower.endsWith('.' + p)
          || fqLower.endsWith(':' + p)
          || fqLast.toLowerCase() === p;
      });
      return patternMatches;
    });

    if (matches.length === 0) {
      // Suggest alternatives from the catalog for this sink.
      const alternatives = catalog
        .filter(e => (!args.language || !e.language || e.language === args.language) && (!e.sinkType || e.sinkType === sinkType))
        .flatMap(e => e.patterns)
        .slice(0, 20);

      return textResult({
        isValidSanitizer: false,
        function: fq,
        sink_type: sinkType,
        language: args.language ?? 'any',
        notes:
          `No sanitizer entry matches "${fq}" for sink_type "${sinkType}". This does NOT mean the function ` +
          `is unsafe — it may be a project-specific wrapper. But circle-ir will not treat it as a sanitizer ` +
          `during taint analysis, so a source→sink flow through it will be flagged.`,
        alternatives,
      });
    }

    return textResult({
      isValidSanitizer: true,
      function: fq,
      sink_type: sinkType,
      language: args.language ?? 'any',
      matchedRules: matches.map(m => ({
        pattern: m.patterns,
        sinkType: m.sinkType ?? 'any',
        language: m.language ?? 'any',
        source: m.source,
      })),
      notes:
        'circle-ir will treat any taint flowing through this function as sanitized for the given sink ' +
        'type. A downstream sink call will not fire.',
    });
  };
}
