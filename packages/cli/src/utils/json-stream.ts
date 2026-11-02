/**
 * Write a value as pretty JSON without building it as one string (cognium-dev#1079).
 *
 * `JSON.stringify(report, null, 2)` on a large `depcalls` / `deadcode` / `reach` /
 * `entries` report passed V8's maximum string length ("Invalid string length") and held
 * the whole report twice in memory. `jsonChunks` yields the same text as
 * `JSON.stringify(value, null, 2)`, byte for byte: the top levels of the value are walked
 * here, and each element below `depth` is stringified on its own and re-indented.
 */
import { closeSync, openSync, writeSync } from 'fs';
import { writeStdout } from './options.js';

const SKIP = Symbol('skip');

/** The value `JSON.stringify` would serialise for `v` (toJSON applied), or SKIP. */
function prepare(v: unknown, key: string): unknown {
  if (v !== null && typeof v === 'object' && typeof (v as { toJSON?: unknown }).toJSON === 'function') {
    v = (v as { toJSON: (k: string) => unknown }).toJSON(key);
  }
  if (v === undefined || typeof v === 'function' || typeof v === 'symbol') return SKIP;
  return v;
}

function leaf(v: unknown, pad: string): string {
  const s = JSON.stringify(v, null, 2);
  return pad === '' ? s : s.replace(/\n/g, '\n' + pad);
}

/**
 * The text of `JSON.stringify(value, null, 2)`, in pieces. Objects and arrays are walked
 * down to `depth` levels; below that each value is one `JSON.stringify` call, so no piece
 * is larger than one element of a top-level collection.
 */
export function* jsonChunks(value: unknown, depth = 3): Generator<string> {
  const v = prepare(value, '');
  if (v === SKIP) return; // JSON.stringify(undefined) is undefined: nothing to write
  yield* walk(v, depth, '');
}

/** `v` is already prepared (toJSON applied, never SKIP). */
function* walk(v: unknown, depth: number, pad: string): Generator<string> {
  if (depth <= 0 || v === null || typeof v !== 'object') { yield leaf(v, pad); return; }
  const inner = pad + '  ';
  if (Array.isArray(v)) {
    if (v.length === 0) { yield '[]'; return; }
    yield '[';
    for (let i = 0; i < v.length; i++) {
      yield (i === 0 ? '\n' : ',\n') + inner;
      const el = prepare(v[i], String(i));
      if (el === SKIP) yield 'null';
      else yield* walk(el, depth - 1, inner);
    }
    yield '\n' + pad + ']';
    return;
  }
  let first = true;
  for (const k of Object.keys(v as object)) {
    const el = prepare((v as Record<string, unknown>)[k], k);
    if (el === SKIP) continue;
    yield (first ? '{\n' : ',\n') + inner + JSON.stringify(k) + ': ';
    first = false;
    yield* walk(el, depth - 1, inner);
  }
  yield first ? '{}' : '\n' + pad + '}';
}

/**
 * Write `value` as `JSON.stringify(value, null, 2) + '\n'` to `file` (synchronous writes
 * on one descriptor, buffered to ~1 MB) or to stdout when `file` is undefined.
 */
export function writeJson(value: unknown, file?: string): void {
  const LIMIT = 1 << 20;
  let buf: string[] = [];
  let size = 0;
  const fd = file !== undefined ? openSync(file, 'w') : -1;
  const flush = (): void => {
    if (size === 0) return;
    const text = buf.join('');
    if (fd >= 0) writeSync(fd, text); else writeStdout(text);
    buf = []; size = 0;
  };
  try {
    for (const piece of jsonChunks(value)) {
      buf.push(piece); size += piece.length;
      if (size >= LIMIT) flush();
    }
    buf.push('\n'); size += 1;
    flush();
  } finally {
    if (fd >= 0) closeSync(fd);
  }
}
