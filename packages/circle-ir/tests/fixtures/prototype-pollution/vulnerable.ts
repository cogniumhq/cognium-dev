// Prototype pollution (CWE-1321): every line marked FLAG gives exactly one finding.
import type { Request, Response } from 'express';

type Bag = Record<string, unknown>;

export function deepMerge(target: Bag, source: Bag): Bag {
  for (const key in source) {
    const value = source[key];
    if (value && typeof value === 'object') {
      if (!target[key]) target[key] = {}; // FLAG recursive-merge
      deepMerge(target[key] as Bag, value as Bag);
    } else {
      target[key] = value;
    }
  }
  return target;
}

export function applyDefaults(dst: Bag, src: Bag): void {
  Object.keys(src).forEach((name) => {
    if (typeof src[name] === 'object') {
      dst[name] = dst[name] ?? {}; // FLAG recursive-merge
      applyDefaults(dst[name] as Bag, src[name] as Bag);
    } else {
      dst[name] = src[name];
    }
  });
}

export function setByPath(obj: Bag, path: string, value: unknown): void {
  const parts = path.split('.');
  let cur: Bag = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    const p = parts[i];
    cur[p] = cur[p] || {}; // FLAG set-by-path
    cur = cur[p] as Bag;
  }
  cur[parts[parts.length - 1]] = value;
}

const preferences: Record<string, Bag> = {};

export function updatePreference(req: Request, res: Response): void {
  const { section, field, value } = req.body;
  preferences[section][field] = value; // FLAG request-keys
  res.sendStatus(204);
}
