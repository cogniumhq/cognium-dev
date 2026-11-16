// Near misses: shapes that look like prototype pollution but are not. No finding.
import type { Request, Response } from 'express';

type Bag = Record<string, unknown>;

// Shallow copy: no recursion, so `__proto__` only changes `out`'s own prototype.
export function shallowCopy(src: Bag): Bag {
  const out: Bag = {};
  for (const k in src) out[k] = src[k];
  return out;
}

// Trie insert: one character cannot spell `__proto__`.
export function insertWord(root: Bag, word: string): void {
  let node = root;
  for (const ch of word) {
    node[ch] = node[ch] || {};
    node = node[ch] as Bag;
  }
  node.end = true;
}

// Get by path: walks, never writes.
export function getByPath(obj: Bag, path: string): unknown {
  let cur: unknown = obj;
  for (const p of path.split('.')) cur = (cur as Bag)?.[p];
  return cur;
}

// Null-prototype target.
const counters = Object.create(null) as Record<string, Record<string, number>>;
export function count(req: Request, res: Response): void {
  const { group, name } = req.query as Record<string, string>;
  counters[group][name] = (counters[group][name] ?? 0) + 1;
  res.sendStatus(204);
}

// One request key only.
const flags: Record<string, Bag> = { ui: {} };
export function setFlag(req: Request, res: Response): void {
  const name = req.body.name;
  flags.ui[name] = true;
  res.sendStatus(204);
}

// Recursive merge that guards with Object.hasOwn on a prototype-less target.
export function mergeInto(target: Bag, source: Bag): Bag {
  for (const key of Object.keys(source)) {
    if (key === '__proto__') continue;
    target[key] = typeof source[key] === 'object' ? mergeInto({}, source[key] as Bag) : source[key];
  }
  return target;
}

// Deep clone: recursion only on the source, every write goes to a fresh object.
export function deepClone(src: Bag): Bag {
  const out: Bag = {};
  for (const k of Object.keys(src)) {
    out[k] = src[k] && typeof src[k] === 'object' ? deepClone(src[k] as Bag) : src[k];
  }
  return out;
}
