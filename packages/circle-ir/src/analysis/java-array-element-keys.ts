/**
 * cognium-dev#476 — shared keys for Java array element taint (`arr[0]`, `grid[0][0]`, …).
 */

export function javaArrayElementStorageKey(
  base: string,
  indices: string[],
): { arrayName: string; indexKey: string } {
  if (indices.length === 1) {
    return { arrayName: base, indexKey: indices[0] };
  }
  const prefix = indices.slice(0, -1).join('@');
  return {
    arrayName: `${base}@${prefix}`,
    indexKey: indices[indices.length - 1],
  };
}

export function parseJavaArrayAccessExpression(expr: string | undefined): {
  base: string;
  arrayName: string;
  indexKey: string;
  displayVar: string;
} | null {
  const trimmed = expr?.trim();
  if (!trimmed) return null;
  const m = trimmed.match(/^(\w+)((?:\[\d+\])+)$/);
  if (!m) return null;
  const base = m[1];
  const indices = [...m[2].matchAll(/\[(\d+)\]/g)].map(part => part[1]);
  if (indices.length === 0) return null;
  const { arrayName, indexKey } = javaArrayElementStorageKey(base, indices);
  return { base, arrayName, indexKey, displayVar: trimmed };
}
