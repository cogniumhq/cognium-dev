/**
 * Size-bounded serialization helpers.
 *
 * MCP tool responses go into the LLM context window. Every response body
 * must be capped so a large scan doesn't blow the client's context budget
 * or exceed the MCP transport's message size limit.
 */

/** Max characters for any single string field surfaced in a tool response. */
export const MAX_STRING_LEN = 2048;

/** Max entries in an unpaginated `findings[]` before truncation. */
export const MAX_FINDINGS = 500;

/** Max entries in an unpaginated `taint_paths[]` before truncation. */
export const MAX_TAINT_PATHS = 200;

/** Max entries in an unpaginated `entry_points[]` before truncation. */
export const MAX_ENTRY_POINTS = 500;

/** Truncate a string to `MAX_STRING_LEN`, appending a marker. */
export function truncateString(s: string | undefined, max = MAX_STRING_LEN): string | undefined {
  if (s === undefined || s === null) return undefined;
  if (s.length <= max) return s;
  return s.slice(0, max - 20) + '… [truncated]';
}

/** Truncate an array, returning both the slice and a truncation marker. */
export function truncateArray<T>(items: T[], max: number): {
  items: T[];
  truncated: boolean;
  totalCount: number;
} {
  if (items.length <= max) {
    return { items, truncated: false, totalCount: items.length };
  }
  return {
    items: items.slice(0, max),
    truncated: true,
    totalCount: items.length,
  };
}

/**
 * Compact JSON serialization for MCP `text` content blocks. Uses 2-space
 * indent for LLM readability but keeps arrays inline for large collections.
 */
export function toJson(value: unknown): string {
  return JSON.stringify(value, null, 2);
}
