// CWE-1333 fixture: request values matched against regexes that backtrack
// exponentially. Every line marked FLAG must give exactly one
// `redos-regex-literal` finding.
import express, { type Request, type Response } from 'express';

const app = express();

const EMAIL_RE = /^([a-zA-Z0-9]+[-._]?)+@example\.com$/;

export function checkEmail(req: Request, res: Response) {
  const email = req.query.email as string;
  const ok = /^([a-zA-Z0-9]+)*@example\.com$/.test(email); // FLAG
  res.json({ ok });
}

export function checkSignupEmail(req: Request, res: Response) {
  const { email } = req.body;
  res.json({ ok: EMAIL_RE.test(email) }); // FLAG
}

export function slugify(req: Request, res: Response) {
  const title = String(req.body.title).trim();
  res.send(title.replace(/^(\w+\s?)*$/, '-')); // FLAG
}

export function parseHeader(req: Request, res: Response) {
  const m = req.headers['x-trace'] ? /^(\d+)+-x$/.exec(req.headers['x-trace'] as string) : null; // FLAG
  res.json({ m });
}

export function tags(request: Request, res: Response) {
  const raw = request.params.tags;
  const list = raw;
  res.json(list.match(/^(([a-z])+,?)+;$/)); // FLAG
}

app.get('/check', checkEmail);
app.post('/signup', checkSignupEmail);
app.post('/slug', slugify);
app.get('/trace', parseHeader);
app.get('/tags/:tags', tags);
