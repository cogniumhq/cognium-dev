// The same helpers with the prototype keys rejected: no finding.
import type { Request, Response } from 'express';

type Bag = Record<string, unknown>;

const BLOCKED = new Set(['__proto__', 'constructor', 'prototype']);

export function deepMerge(target: Bag, source: Bag): Bag {
  for (const key in source) {
    if (BLOCKED.has(key)) continue;
    const value = source[key];
    if (value && typeof value === 'object') {
      if (!target[key]) target[key] = {};
      deepMerge(target[key] as Bag, value as Bag);
    } else {
      target[key] = value;
    }
  }
  return target;
}

export function applyDefaults(dst: Bag, src: Bag): void {
  Object.keys(src).forEach((name) => {
    if (name === '__proto__' || name === 'constructor' || name === 'prototype') return;
    if (typeof src[name] === 'object') {
      dst[name] = dst[name] ?? {};
      applyDefaults(dst[name] as Bag, src[name] as Bag);
    } else {
      dst[name] = src[name];
    }
  });
}

function isSafeKey(k: string): boolean {
  return !BLOCKED.has(k);
}

export function setByPath(obj: Bag, path: string, value: unknown): void {
  const parts = path.split('.');
  let cur: Bag = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    const p = parts[i];
    if (!isSafeKey(p)) return;
    cur[p] = cur[p] || {};
    cur = cur[p] as Bag;
  }
  cur[parts[parts.length - 1]] = value;
}

const preferences: Map<string, Map<string, unknown>> = new Map();

export function updatePreference(req: Request, res: Response): void {
  const { section, field, value } = req.body;
  const bucket = preferences.get(section) ?? new Map<string, unknown>();
  bucket.set(field, value);
  preferences.set(section, bucket);
  res.sendStatus(204);
}
