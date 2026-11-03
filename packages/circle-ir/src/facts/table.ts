/**
 * `facts@1` relations as columns: one typed array (or string array) per
 * schema column, never an object per row. The emitter builds these straight
 * from the graph, sorts a row-index permutation once with a comparator over
 * the columns, drops adjacent duplicates (relations are sets) and gathers the
 * kept rows — the shape Arrow wants, so the IPC encoder copies buffers
 * instead of visiting cells. The row form (`FactRow`) stays as the reference
 * for the comparator and for tests; `tableFromRows` / `tableRow` convert.
 */

import { FACTS_ID_WIDTH, type FactRow, type FactValue, type FactsColumn, type FactsColumnType, type FactsRelation, sortColumns } from './schema.js';
import { compareCodePoints } from './order.js';

/**
 * One column's cells, by schema type: `fixed16` → `Uint8Array` of 16 × rows
 * bytes; `u32` → `Uint32Array`; `utf8` → `string[]`; `bool` → `Uint8Array`
 * of 0/1 per row; `dict` → `Int8Array` of vocabulary indexes.
 */
export type FactColumnData = Uint8Array | Uint32Array | Int8Array | string[];

export interface FactTable {
  readonly length: number;
  /** One entry per schema column, in schema order. */
  readonly columns: readonly FactColumnData[];
}

/** An empty column of the right shape for `n` rows. */
export function allocColumn(c: FactsColumn, n: number): FactColumnData {
  switch (c.type) {
    case 'fixed16': return new Uint8Array(n * FACTS_ID_WIDTH);
    case 'u32': return new Uint32Array(n);
    case 'utf8': return new Array<string>(n);
    case 'bool': return new Uint8Array(n);
    case 'dict': return new Int8Array(n);
  }
}

/** Empty columns for a relation with `n` rows. */
export function allocTable(relation: FactsRelation, n: number): FactColumnData[] {
  return relation.columns.map(c => allocColumn(c, n));
}

/** `value → index` for a dictionary column's vocabulary. */
export function dictIndex(c: FactsColumn): Map<string, number> {
  return new Map((c.values ?? []).map((v, i) => [v, i] as const));
}

const BASE32_VALUE = new Int8Array(128).fill(-1);
for (let i = 0; i < 32; i++) BASE32_VALUE['abcdefghijklmnopqrstuvwxyz234567'.charCodeAt(i)] = i;

/**
 * Decode an `ids@0.1` id (26 lowercase base32 characters, 130 bits with 2
 * zero padding bits) into 16 bytes at `out[offset..]`, allocating nothing.
 */
export function idBytesInto(id: string, out: Uint8Array, offset: number): void {
  if (id.length !== 26) throw new Error(`facts@1: not an ids@0.1 id: ${JSON.stringify(id)}`);
  let buffer = 0;
  let bits = 0;
  let n = offset;
  for (let i = 0; i < 26; i++) {
    const code = id.charCodeAt(i);
    const v = code < 128 ? BASE32_VALUE[code] : -1;
    if (v < 0) throw new Error(`facts@1: not an ids@0.1 id: ${JSON.stringify(id)}`);
    buffer = (buffer << 5) | v;
    bits += 5;
    if (bits >= 8) {
      out[n++] = (buffer >>> (bits - 8)) & 0xff;
      bits -= 8;
      buffer &= (1 << bits) - 1;
    }
  }
  if (bits !== 2 || buffer !== 0) throw new Error(`facts@1: not an ids@0.1 id: ${JSON.stringify(id)}`);
}

/**
 * Decodes ids into columns through a cache: a snapshot's ids repeat (every
 * call edge names its caller and callee), so an id is decoded once into a
 * pool and copied from there after.
 */
export class IdDecoder {
  private pool = new Uint8Array(FACTS_ID_WIDTH * 1024);
  private readonly offsets = new Map<string, number>();
  private used = 0;

  /** Write the 16 bytes of `id` at `out[offset..]`. */
  put(id: string, out: Uint8Array, offset: number): void {
    let at = this.offsets.get(id);
    if (at === undefined) {
      if (this.used + FACTS_ID_WIDTH > this.pool.length) {
        const bigger = new Uint8Array(this.pool.length * 2);
        bigger.set(this.pool);
        this.pool = bigger;
      }
      at = this.used;
      idBytesInto(id, this.pool, at);
      this.used += FACTS_ID_WIDTH;
      this.offsets.set(id, at);
    }
    const pool = this.pool;
    for (let k = 0; k < FACTS_ID_WIDTH; k++) out[offset + k] = pool[at + k];
  }
}

/** Dictionary index → rank in code-point order of the vocabulary (the order the contract sorts dict columns by). */
function dictRanks(c: FactsColumn): Int8Array {
  const vocab = c.values ?? [];
  const sorted = [...vocab].sort(compareCodePoints);
  const ranks = new Int8Array(vocab.length);
  vocab.forEach((v, i) => { ranks[i] = sorted.indexOf(v); });
  return ranks;
}

/**
 * Code-point order on two strings, fast path first: equal references, then
 * the first differing UTF-16 unit, corrected only where a surrogate meets a
 * non-surrogate (the one case where unit order and code-point order differ).
 */
export function compareStrings(a: string, b: string): number {
  if (a === b) return 0;
  const n = Math.min(a.length, b.length);
  let i = 0;
  while (i < n && a.charCodeAt(i) === b.charCodeAt(i)) i++;
  if (i === n) return a.length - b.length;
  const ca = a.charCodeAt(i);
  const cb = b.charCodeAt(i);
  const sa = ca >= 0xd800 && ca < 0xe000;
  const sb = cb >= 0xd800 && cb < 0xe000;
  if (sa === sb) return ca - cb;
  return (a.codePointAt(i) as number) - (b.codePointAt(i) as number);
}

type IndexComparator = (a: number, b: number) => number;

function columnComparator(c: FactsColumn, data: FactColumnData): IndexComparator {
  switch (c.type) {
    case 'fixed16': {
      const d = data as Uint8Array;
      return (a, b) => {
        let x = a * FACTS_ID_WIDTH;
        let y = b * FACTS_ID_WIDTH;
        for (let k = 0; k < FACTS_ID_WIDTH; k++, x++, y++) {
          const diff = d[x] - d[y];
          if (diff !== 0) return diff;
        }
        return 0;
      };
    }
    case 'u32':
    case 'bool': {
      const d = data as Uint32Array | Uint8Array;
      return (a, b) => d[a] - d[b];
    }
    case 'utf8': {
      const d = data as string[];
      return (a, b) => compareStrings(d[a], d[b]);
    }
    case 'dict': {
      const d = data as Int8Array;
      const ranks = dictRanks(c);
      return (a, b) => ranks[d[a]] - ranks[d[b]];
    }
  }
}

/**
 * The relation's canonical order as a comparator on row indexes of `columns`:
 * key columns, then every remaining column in schema order. Total over the
 * cells, so `0` means the two rows are equal cell for cell.
 */
export function tableComparator(relation: FactsRelation, columns: readonly FactColumnData[]): IndexComparator {
  const cmps = sortColumns(relation).map(i => columnComparator(relation.columns[i], columns[i]));
  const n = cmps.length;
  return (a, b) => {
    for (let k = 0; k < n; k++) {
      const c = cmps[k](a, b);
      if (c !== 0) return c;
    }
    return 0;
  };
}

/** The rows `idx` names, gathered into new columns in that order. */
function gather(relation: FactsRelation, columns: readonly FactColumnData[], idx: ArrayLike<number>): FactColumnData[] {
  const n = idx.length;
  return relation.columns.map((c, ci) => {
    const src = columns[ci];
    const dst = allocColumn(c, n);
    if (c.type === 'fixed16') {
      const s = src as Uint8Array;
      const d = dst as Uint8Array;
      for (let i = 0, to = 0; i < n; i++) {
        // A plain copy loop: `set(subarray())` would allocate a view per cell.
        for (let from = idx[i] * FACTS_ID_WIDTH, end = from + FACTS_ID_WIDTH; from < end; from++, to++) d[to] = s[from];
      }
    } else if (c.type === 'utf8') {
      const s = src as string[];
      const d = dst as string[];
      for (let i = 0; i < n; i++) d[i] = s[idx[i]];
    } else {
      const s = src as Uint32Array | Uint8Array | Int8Array;
      const d = dst as Uint32Array | Uint8Array | Int8Array;
      for (let i = 0; i < n; i++) d[i] = s[idx[i]];
    }
    return dst;
  });
}

const INDEX_BITS = 24;
const INDEX_RANGE = 2 ** INDEX_BITS;
const KEY_BITS = 29;
const KEY_RANGE = 2 ** KEY_BITS;

/**
 * The sort key of a row as a byte string, for the native sort: the key
 * columns then the remaining columns in schema order, each column's bytes in
 * an order that agrees with the comparator — a `fixed16` as its 16 bytes,
 * a `u32` big-endian, a `dict` as its code-point rank, a `bool` as 0/1 — up
 * to the first `utf8` column, which has no fixed width and ends the string.
 * `bitsAt(level)` reads 29-bit slices of it, so a relation whose leading
 * column is an id (`flow`, `call`, `decl`, …) sorts natively level after
 * level instead of falling back to the comparator for every tie on the first
 * 29 bits — and on real data the ties are the rule: one `call` caller has
 * many edges, one `flow` definition many uses.
 */
function copyFixed16(d: Uint8Array, buf: Uint8Array, at: number, stride: number, rows: number): void {
  for (let row = 0, o = at, f = 0; row < rows; row++, o += stride, f += FACTS_ID_WIDTH) {
    for (let k = 0; k < FACTS_ID_WIDTH; k++) buf[o + k] = d[f + k];
  }
}

function copyU32(d: Uint32Array, buf: Uint8Array, at: number, stride: number, rows: number): void {
  for (let row = 0, o = at; row < rows; row++, o += stride) {
    const v = d[row];
    buf[o] = v >>> 24;
    buf[o + 1] = (v >>> 16) & 0xff;
    buf[o + 2] = (v >>> 8) & 0xff;
    buf[o + 3] = v & 0xff;
  }
}

function copyRanks(d: Int8Array, ranks: Int8Array, buf: Uint8Array, at: number, stride: number, rows: number): void {
  for (let row = 0, o = at; row < rows; row++, o += stride) buf[o] = ranks[d[row]];
}

function copyBytes(d: Uint8Array, buf: Uint8Array, at: number, stride: number, rows: number): void {
  for (let row = 0, o = at; row < rows; row++, o += stride) buf[o] = d[row];
}

class KeyBytes {
  /** Total key bytes before the first `utf8` column. */
  readonly length: number;
  /** Row-major key strings, `length` bytes per row. */
  private readonly buf: Uint8Array;
  private readonly cache = new Map<number, Uint32Array>();

  constructor(relation: FactsRelation, columns: readonly FactColumnData[], private readonly rows: number) {
    const parts: { i: number; type: FactsColumnType; width: number }[] = [];
    let length = 0;
    for (const i of sortColumns(relation)) {
      const c = relation.columns[i];
      if (c.type === 'utf8') break;
      const width = c.type === 'fixed16' ? FACTS_ID_WIDTH : c.type === 'u32' ? 4 : 1;
      parts.push({ i, type: c.type, width });
      length += width;
    }
    this.length = length;
    this.complete = parts.length === relation.columns.length;
    const buf = new Uint8Array(rows * length);
    let at = 0;
    for (const { i, type, width } of parts) {
      const c = relation.columns[i];
      if (type === 'fixed16') copyFixed16(columns[i] as Uint8Array, buf, at, length, rows);
      else if (type === 'u32') copyU32(columns[i] as Uint32Array, buf, at, length, rows);
      else if (type === 'dict') copyRanks(columns[i] as Int8Array, dictRanks(c), buf, at, length, rows);
      else copyBytes(columns[i] as Uint8Array, buf, at, length, rows);
      at += width;
    }
    this.buf = buf;
  }

  /** True when the key string covers every column (no `utf8`), so equal key strings are equal rows. */
  readonly complete: boolean;

  /** Rows `a` and `b` have the same key string. */
  equal(a: number, b: number): boolean {
    const { buf, length } = this;
    for (let x = a * length, y = b * length, end = x + length; x < end; x++, y++) if (buf[x] !== buf[y]) return false;
    return true;
  }

  /** Number of 29-bit levels the key string holds. */
  get levels(): number {
    return Math.ceil((this.length * 8) / KEY_BITS);
  }

  /** Bits `[29·level, 29·level + 29)` of every row's key string (zero past its end), or `undefined` when the level is past the end. */
  bitsAt(level: number): Uint32Array | undefined {
    if (level >= this.levels) return undefined;
    let bits = this.cache.get(level);
    if (bits) return bits;
    bits = new Uint32Array(this.rows);
    const bitStart = level * KEY_BITS;
    const q = bitStart >> 3;
    const r = bitStart & 7;
    // Five bytes hold any 29-bit window at any bit offset; exact as a double (< 2^40).
    const shift = 2 ** (40 - r - KEY_BITS);
    const { buf, length } = this;
    const b = (o: number, k: number): number => (k < length ? buf[o + k] : 0);
    for (let row = 0, o = 0; row < this.rows; row++, o += length) {
      const v = b(o, q) * 2 ** 32 + b(o, q + 1) * 2 ** 24 + b(o, q + 2) * 2 ** 16 + b(o, q + 3) * 2 ** 8 + b(o, q + 4);
      bits[row] = Math.floor(v / shift) % KEY_RANGE;
    }
    this.cache.set(level, bits);
    return bits;
  }
}

/**
 * Up to 29 bits per row that agree with the leading sort column(s) when the
 * leading column is a `u32`: the leading `u32` with the next `u32` key
 * packed below it when both are small enough (`file_id` < 2^13 and the line
 * < 2^16), else the leading `u32` alone when it is under 2^29. `undefined`
 * when a value does not fit. (An id-led relation reads `KeyBytes` instead.)
 */
function u32KeyBits(relation: FactsRelation, columns: readonly FactColumnData[], length: number): Uint32Array | undefined {
  const order = sortColumns(relation);
  const a = columns[order[0]] as Uint32Array;
  const second = order.length > 1 && relation.columns[order[1]].type === 'u32' ? (columns[order[1]] as Uint32Array) : undefined;
  let maxA = 0;
  let maxB = 0;
  for (let i = 0; i < length; i++) {
    if (a[i] > maxA) maxA = a[i];
    if (second && second[i] > maxB) maxB = second[i];
  }
  const keys = new Uint32Array(length);
  if (second && maxA < 0x2000 && maxB < 0x10000) {
    for (let i = 0; i < length; i++) keys[i] = (a[i] << 16) | second[i];
    return keys;
  }
  if (maxA < KEY_RANGE) {
    keys.set(a);
    return keys;
  }
  return undefined;
}

/** Sort `idx[start, end)` with the comparator, in place: insertion for a short run, a native sort of a copy otherwise. */
function sortRun(idx: number[], start: number, end: number, cmp: IndexComparator): void {
  const n = end - start;
  if (n === 2) {
    if (cmp(idx[start], idx[start + 1]) > 0) {
      const t = idx[start];
      idx[start] = idx[start + 1];
      idx[start + 1] = t;
    }
  } else if (n <= 16) {
    for (let a = start + 1; a < end; a++) {
      const v = idx[a];
      let b = a - 1;
      while (b >= start && cmp(idx[b], v) > 0) { idx[b + 1] = idx[b]; b--; }
      idx[b + 1] = v;
    }
  } else {
    const sorted = idx.slice(start, end).sort(cmp);
    for (let k = 0; k < n; k++) idx[start + k] = sorted[k];
  }
}

/**
 * The canonical permutation of the rows: sorted by the total order. Rows are
 * packed as `keyBits · 2^24 + index` into a `Float64Array` (53 bits, exact)
 * and sorted natively — no comparator call per comparison. Rows that tie on
 * those bits are sorted the same way on the next 29 bits of the key string
 * (`KeyBytes`), level after level, in place on a scratch array; only runs
 * that are still tied when the key string ends (a `utf8` column, or equal
 * rows) go to the comparator. Falls back to a comparator sort when the rows
 * do not fit the packing.
 */
function canonicalPermutation(relation: FactsRelation, columns: readonly FactColumnData[], length: number, cmp: IndexComparator): { idx: number[]; keys?: KeyBytes } {
  const idx: number[] = new Array<number>(length);
  const first = relation.columns[sortColumns(relation)[0]];
  const keys = first.type === 'fixed16' || first.type === 'dict' || first.type === 'bool' ? new KeyBytes(relation, columns, length) : undefined;
  const bits0 = length < INDEX_RANGE ? (keys ? keys.bitsAt(0) : first.type === 'u32' ? u32KeyBits(relation, columns, length) : undefined) : undefined;
  if (!bits0) {
    for (let i = 0; i < length; i++) idx[i] = i;
    idx.sort(cmp);
    return { idx, keys };
  }
  const packed = new Float64Array(length);
  for (let i = 0; i < length; i++) packed[i] = bits0[i] * INDEX_RANGE + i;
  packed.sort();
  for (let i = 0; i < length; i++) idx[i] = packed[i] % INDEX_RANGE;

  // Refine `idx[start, end)` — rows equal on levels < `level` — by the bits at `level`.
  const refine = (start: number, end: number, level: number): void => {
    const bits = keys?.bitsAt(level);
    if (!bits) {
      sortRun(idx, start, end, cmp);
      return;
    }
    const n = end - start;
    if (n <= 16) {
      // Insertion sort on the bits, in place: most runs are one id used a few times.
      for (let a = start + 1; a < end; a++) {
        const v = idx[a];
        const bv = bits[v];
        let b = a - 1;
        while (b >= start && bits[idx[b]] > bv) { idx[b + 1] = idx[b]; b--; }
        idx[b + 1] = v;
      }
    } else {
      const scratch = packed.subarray(0, n);
      for (let k = 0; k < n; k++) scratch[k] = bits[idx[start + k]] * INDEX_RANGE + idx[start + k];
      scratch.sort();
      for (let k = 0; k < n; k++) idx[start + k] = scratch[k] % INDEX_RANGE;
    }
    let runStart = start;
    for (let i = start + 1; i <= end; i++) {
      if (i < end && bits[idx[i]] === bits[idx[runStart]]) continue;
      if (i - runStart > 1) refine(runStart, i, level + 1);
      runStart = i;
    }
  };
  // `packed` is reused as the scratch below: the sorted order is in `idx` by now.
  let runStart = 0;
  for (let i = 1; i <= length; i++) {
    if (i < length && bits0[idx[i]] === bits0[idx[runStart]]) continue;
    if (i - runStart > 1) refine(runStart, i, 1);
    runStart = i;
  }
  return { idx, keys };
}

/**
 * Canonical form of a relation's rows: sorted in the total order, exact
 * duplicates dropped (relations are sets) and counted. Sorts a permutation
 * once and gathers; the input columns are not modified.
 */
export function canonicalTable(relation: FactsRelation, columns: readonly FactColumnData[], length: number): { table: FactTable; duplicatesDropped: number } {
  if (columns.length !== relation.columns.length) throw new Error(`facts@1: ${columns.length} columns for a relation of ${relation.columns.length}`);
  const cmp = tableComparator(relation, columns);
  const { idx, keys } = canonicalPermutation(relation, columns, length, cmp);
  // Adjacent equal rows: same key string (and, when a utf8 column lies past it, equal under the comparator too).
  const same = keys
    ? keys.complete
      ? (a: number, b: number): boolean => keys.equal(a, b)
      : (a: number, b: number): boolean => keys.equal(a, b) && cmp(a, b) === 0
    : (a: number, b: number): boolean => cmp(a, b) === 0;
  let kept = 0;
  for (let i = 0; i < length; i++) {
    if (kept > 0 && same(idx[kept - 1], idx[i])) continue;
    idx[kept++] = idx[i];
  }
  idx.length = kept;
  return { table: { length: kept, columns: gather(relation, columns, idx) }, duplicatesDropped: length - kept };
}

/** Adjacent rows of a canonical table that are equal on the key columns alone (what a store's key check would refuse). */
export function keyCollisions(relation: FactsRelation, table: FactTable): number {
  const keyIdx = relation.key.map(k => relation.columns.findIndex(c => c.name === k));
  const cmps = keyIdx.map(i => columnComparator(relation.columns[i], table.columns[i]));
  let collisions = 0;
  for (let i = 1; i < table.length; i++) {
    if (cmps.every(c => c(i - 1, i) === 0)) collisions++;
  }
  return collisions;
}

/** Row `i` of a table as cells in schema order. */
export function tableRow(relation: FactsRelation, table: FactTable, i: number): FactRow {
  if (i < 0 || i >= table.length) throw new RangeError(`facts@1: row ${i} of ${table.length}`);
  return relation.columns.map((c, ci): FactValue => {
    const d = table.columns[ci];
    switch (c.type) {
      case 'fixed16': return (d as Uint8Array).slice(i * FACTS_ID_WIDTH, (i + 1) * FACTS_ID_WIDTH);
      case 'u32': return (d as Uint32Array)[i];
      case 'utf8': return (d as string[])[i];
      case 'bool': return (d as Uint8Array)[i] !== 0;
      case 'dict': return (c.values as readonly string[])[(d as Int8Array)[i]];
    }
  });
}

/** Every row of a table, in table order. */
export function tableRows(relation: FactsRelation, table: FactTable): FactRow[] {
  return Array.from({ length: table.length }, (_, i) => tableRow(relation, table, i));
}

/**
 * Columns from rows in the row form, cells checked against their column
 * (`null` is refused: `facts@1` has no nullable column). The rows keep their
 * order; pass the result through `canonicalTable` for the canonical form.
 */
export function tableFromRows(relation: FactsRelation, rows: readonly FactRow[]): FactTable {
  const n = rows.length;
  const columns = allocTable(relation, n);
  const dicts = relation.columns.map(c => (c.type === 'dict' ? dictIndex(c) : undefined));
  for (let i = 0; i < n; i++) {
    const r = rows[i];
    if (r.length !== relation.columns.length) throw new Error(`facts@1: a row has ${r.length} cells, the relation ${relation.columns.length} columns`);
    for (let ci = 0; ci < relation.columns.length; ci++) {
      const c = relation.columns[ci];
      const x = r[ci];
      if (x === null) throw new Error(`facts@1: null in non-nullable column ${c.name}`);
      switch (c.type) {
        case 'fixed16':
          if (!(x instanceof Uint8Array) || x.length !== FACTS_ID_WIDTH) throw new Error(`facts@1: column ${c.name} expects ${FACTS_ID_WIDTH} id bytes`);
          (columns[ci] as Uint8Array).set(x, i * FACTS_ID_WIDTH);
          break;
        case 'u32':
          if (typeof x !== 'number' || !Number.isInteger(x) || x < 0 || x > 0xffffffff) throw new Error(`facts@1: column ${c.name} expects an unsigned 32-bit integer, got ${String(x)}`);
          (columns[ci] as Uint32Array)[i] = x;
          break;
        case 'utf8':
          if (typeof x !== 'string') throw new Error(`facts@1: column ${c.name} expects a string`);
          (columns[ci] as string[])[i] = x;
          break;
        case 'bool':
          if (typeof x !== 'boolean') throw new Error(`facts@1: column ${c.name} expects a boolean`);
          (columns[ci] as Uint8Array)[i] = x ? 1 : 0;
          break;
        case 'dict': {
          const k = typeof x === 'string' ? (dicts[ci] as Map<string, number>).get(x) : undefined;
          if (k === undefined) throw new Error(`facts@1: ${JSON.stringify(x)} is not in the ${c.name} vocabulary`);
          (columns[ci] as Int8Array)[i] = k;
          break;
        }
      }
    }
  }
  return { length: n, columns };
}
