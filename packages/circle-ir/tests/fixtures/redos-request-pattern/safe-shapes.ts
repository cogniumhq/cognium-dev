// CWE-1333 near misses: the request value is the subject, not the pattern.
// Must produce no `redos` flow.
import type { Request, Response } from 'express';

export function subject(req: Request, res: Response) {
  const ok = (req.query.q as string).match(/^[a-z]+$/);
  res.json({ ok, b: /^\d{1,4}$/.test(req.body.code), c: new RegExp('^[a-z]+$').test(req.params.name) });
}
