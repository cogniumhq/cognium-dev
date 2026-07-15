/**
 * Shared types for tool handlers.
 */

import type { ProjectCache } from '../cache.js';

export interface ToolContext {
  cache: ProjectCache;
}

/**
 * MCP `CallToolResult`-compatible shape. We construct the JSON payload
 * ourselves so tools have full control over serialization + truncation.
 */
export interface ToolResult {
  content: Array<{ type: 'text'; text: string }>;
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
}

export function textResult(payload: unknown, structured?: Record<string, unknown>): ToolResult {
  const text = typeof payload === 'string' ? payload : JSON.stringify(payload, null, 2);
  const result: ToolResult = { content: [{ type: 'text', text }] };
  if (structured) result.structuredContent = structured;
  return result;
}

export function errorResult(message: string): ToolResult {
  return {
    content: [{ type: 'text', text: `Error: ${message}` }],
    isError: true,
  };
}
