/**
 * Shared types for tool handlers.
 */

import type { ProjectCache } from '../cache.js';
import type { Enablement } from '../enablement.js';

export interface ToolContext {
  /** One analysis cache for the whole server, shared by every tool. */
  cache: ProjectCache;
  /**
   * What this install may offer. Present so an optional module can decide,
   * at registration time, which of its own tools to register, and check
   * again at call time before doing anything an endpoint or a licence is
   * needed for. The floor tools never consult it.
   */
  enablement: Enablement;
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
