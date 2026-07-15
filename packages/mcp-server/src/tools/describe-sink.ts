/**
 * `describe_sink` tool — sink category metadata (CWE, remediation, sanitizers).
 */

import { z } from 'zod';
import { RULE_DEFINITIONS, type SinkType } from 'circle-ir';
import type { ToolContext, ToolResult } from './types.js';
import { textResult, errorResult } from './types.js';
import { loadSanitizerCatalog } from '../resources/catalogs.js';

export const describeSinkInputShape = {
  sink_type: z.string()
    .describe('Sink category, e.g. "sql_injection", "command_injection", "xss", "path_traversal".'),
  language: z.enum(['java', 'javascript', 'typescript', 'python', 'go', 'rust', 'bash', 'html'])
    .optional()
    .describe('Restrict sanitizer suggestions to this language.'),
} as const;

export const describeSinkConfig = {
  title: 'Describe sink category',
  description:
    'Return canonical metadata for a taint sink category: CWE identifier, short + full description, ' +
    'recommended remediation, CVSS-like severity score, and the list of sanitizer functions that would ' +
    'neutralize the sink. Use when the LLM needs authoritative information about a vulnerability class.',
  inputSchema: describeSinkInputShape,
} as const;

export function makeDescribeSinkHandler(_ctx: ToolContext) {
  return async (args: { sink_type: string; language?: string }): Promise<ToolResult> => {
    const rule = RULE_DEFINITIONS[args.sink_type as SinkType];
    if (!rule) {
      return errorResult(
        `Unknown sink_type "${args.sink_type}". Known types: ${Object.keys(RULE_DEFINITIONS).join(', ')}`,
      );
    }
    const sanitizers = loadSanitizerCatalog()
      .filter(e => (!e.sinkType || e.sinkType === args.sink_type)
        && (!args.language || !e.language || e.language === args.language))
      .flatMap(e => e.patterns);

    return textResult({
      sink_type: args.sink_type,
      cwe: rule.cwe,
      name: rule.name,
      shortDescription: rule.shortDescription,
      fullDescription: rule.fullDescription,
      remediation: rule.remediation,
      cvssScore: rule.cvssScore,
      severityLevel: rule.severityLevel,
      language: args.language ?? 'any',
      sanitizers: [...new Set(sanitizers)].slice(0, 50),
      sanitizerCount: sanitizers.length,
    });
  };
}
