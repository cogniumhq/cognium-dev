// CWE-1333 near misses: must produce no `redos-regex-literal` finding.
import type { Request, Response } from 'express';

declare const db: { findUser(id: string): Promise<{ email: string }> };
declare function normalise(s: string): string;

const NESTED = /^(a+)+$/;

// A nested regex, but the value is not from the request.
export function constantInput(_req: Request, res: Response) {
  res.json({ ok: NESTED.test('aaaa') });
}

// The value comes from the database, not the request.
export async function dbValue(req: Request, res: Response) {
  const user = await db.findUser(req.params.id);
  res.json({ ok: /^([a-z0-9]+)*@x\.com$/.test(user.email) });
}

// A helper's result is not followed.
export function helperValue(req: Request, res: Response) {
  const v = normalise(req.query.v as string);
  res.json({ ok: /^(a+)+$/.test(v) });
}

// The repeated body has a required separator: linear.
export function separated(req: Request, res: Response) {
  res.json({ ok: /^(\d+,)*\d+$/.test(req.query.list as string) });
}

// Nothing mandatory after the group: the first try succeeds.
export function unanchored(req: Request, res: Response) {
  res.json({ ok: /(a+)+/.test(req.query.q as string) });
}

// Bounded repetition.
export function bounded(req: Request, res: Response) {
  res.json({ ok: /^(a{1,3}){1,4}$/.test(req.query.q as string) });
}

// Backreference: skipped.
export function backref(req: Request, res: Response) {
  res.json({ ok: /^((a+)\2)+$/.test(req.query.q as string) });
}

// A plain linear regex on a request value.
export function linear(req: Request, res: Response) {
  res.json({ ok: /^[a-z0-9_-]{3,32}$/.test(req.body.username) });
}

// The length of the request value, not the value.
export function lengthOnly(req: Request, res: Response) {
  res.json({ ok: /^(1+)+$/.test(String(req.query.q.length)) });
}

// A parameter of a helper, not a request handler.
export function check(value: string): boolean {
  return /^(\w+\s?)*$/.test(value);
}

// `req` that is not a parameter.
const req = { query: { q: 'aaa' } };
export const moduleLevel = /^(a+)+$/.test(req.query.q);
