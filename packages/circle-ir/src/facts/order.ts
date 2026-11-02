/**
 * The `facts@1` canonical order: a total order on the rows of one relation,
 * so two runs over the same facts put them in the same sequence and the
 * bytes that follow are identical.
 *
 * Cells compare by type — id bytes unsigned bytewise, integers numerically,
 * strings by Unicode code point (which is UTF-8 byte order, so a Rust reader
 * sorting the raw bytes agrees), booleans false before true, null before any
 * value (a dead branch: `facts@1` has no nullable column) — and rows by the
 * key columns first, then every remaining column in schema order. Two rows
 * compare equal only when every cell is equal; relations are sets, so equal
 * rows collapse to one (`canonicalSet`).
 */

import { FACTS_ID_WIDTH, type FactRow, type FactValue, type FactsRelation, sortColumns } from './schema.js';

/** Unsigned bytewise order; a shorter array that is a prefix sorts first. */
export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return a.length - b.length;
}

/** Code point order (UTF-8 byte order), not UTF-16 code unit order. */
export function compareCodePoints(a: string, b: string): number {
  if (a === b) return 0;
  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) {
    const ca = a.codePointAt(i) as number;
    const cb = b.codePointAt(j) as number;
    if (ca !== cb) return ca < cb ? -1 : 1;
    i += ca > 0xffff ? 2 : 1;
    j += cb > 0xffff ? 2 : 1;
  }
  if (i < a.length) return 1;
  return j < b.length ? -1 : 0;
}

/** Order on one cell; the two cells must be of the same column. */
export function compareValues(a: FactValue, b: FactValue): number {
  if (a === null) return b === null ? 0 : -1;
  if (b === null) return 1;
  if (typeof a === 'number' && typeof b === 'number') return a < b ? -1 : a > b ? 1 : 0;
  if (typeof a === 'string' && typeof b === 'string') return compareCodePoints(a, b);
  if (typeof a === 'boolean' && typeof b === 'boolean') return a === b ? 0 : a ? 1 : -1;
  if (a instanceof Uint8Array && b instanceof Uint8Array) return compareBytes(a, b);
  throw new Error(`facts@1: cells of different types in one column (${typeof a} vs ${typeof b})`);
}

/** The row comparator of a relation: key columns, then the remaining columns in schema order. */
export function rowComparator(relation: FactsRelation): (a: FactRow, b: FactRow) => number {
  const order = sortColumns(relation);
  return (a, b) => {
    for (const i of order) {
      const c = compareValues(a[i], b[i]);
      if (c !== 0) return c;
    }
    return 0;
  };
}

/** `rows` sorted in canonical order (a new array); duplicates kept. */
export function canonicalRows(relation: FactsRelation, rows: readonly FactRow[]): FactRow[] {
  return [...rows].sort(rowComparator(relation));
}

/**
 * `rows` as a canonical set: sorted, exact duplicates (equal under the total
 * order) dropped and counted. The row-form reference for what the emitter
 * does on columns (`canonicalTable`).
 */
export function canonicalSet(relation: FactsRelation, rows: readonly FactRow[]): { rows: FactRow[]; duplicatesDropped: number } {
  const cmp = rowComparator(relation);
  const sorted = [...rows].sort(cmp);
  const out: FactRow[] = [];
  for (const r of sorted) {
    if (out.length > 0 && cmp(out[out.length - 1], r) === 0) continue;
    out.push(r);
  }
  return { rows: out, duplicatesDropped: rows.length - out.length };
}

const BASE32 = 'abcdefghijklmnopqrstuvwxyz234567';
const BASE32_VALUE = new Map([...BASE32].map((c, i) => [c, i] as const));

/**
 * The 16 bytes of an `ids@0.1` id (26 lowercase base32 characters, RFC 4648
 * unpadded, the last character carrying 2 zero padding bits).
 */
export function idBytes(id: string): Uint8Array {
  if (id.length !== 26) throw new Error(`facts@1: not an ids@0.1 id: ${JSON.stringify(id)}`);
  const out = new Uint8Array(FACTS_ID_WIDTH);
  let buffer = 0;
  let bits = 0;
  let n = 0;
  for (const c of id) {
    const v = BASE32_VALUE.get(c);
    if (v === undefined) throw new Error(`facts@1: not an ids@0.1 id: ${JSON.stringify(id)}`);
    buffer = (buffer << 5) | v;
    bits += 5;
    if (bits >= 8) {
      out[n++] = (buffer >>> (bits - 8)) & 0xff;
      bits -= 8;
      buffer &= (1 << bits) - 1;
    }
  }
  // 26 × 5 = 130 bits: 128 bits of id and 2 padding bits, which must be zero.
  if (bits !== 2 || buffer !== 0) throw new Error(`facts@1: not an ids@0.1 id: ${JSON.stringify(id)}`);
  return out;
}
