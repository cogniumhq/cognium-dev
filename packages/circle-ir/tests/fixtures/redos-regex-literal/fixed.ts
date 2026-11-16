// CWE-1333 fixture: the same handlers as vulnerable.ts with each regex
// rewritten so every input character has one way to match. Must produce no
// `redos-regex-literal` finding.
import express, { type Request, type Response } from 'express';

const app = express();

const EMAIL_RE = /^[a-zA-Z0-9]+(?:[-._][a-zA-Z0-9]+)*@example\.com$/;

export function checkEmail(req: Request, res: Response) {
  const email = req.query.email as string;
  const ok = /^[a-zA-Z0-9]+@example\.com$/.test(email);
  res.json({ ok });
}

export function checkSignupEmail(req: Request, res: Response) {
  const { email } = req.body;
  res.json({ ok: EMAIL_RE.test(email) });
}

export function slugify(req: Request, res: Response) {
  const title = String(req.body.title).trim();
  res.send(title.replace(/^\w+(?:\s\w+)*$/, '-'));
}

export function parseHeader(req: Request, res: Response) {
  const m = req.headers['x-trace'] ? /^\d+-x$/.exec(req.headers['x-trace'] as string) : null;
  res.json({ m });
}

export function tags(request: Request, res: Response) {
  const raw = request.params.tags;
  const list = raw;
  res.json(list.match(/^[a-z]+(?:,[a-z]+)*;$/));
}

app.get('/check', checkEmail);
app.post('/signup', checkSignupEmail);
app.post('/slug', slugify);
app.get('/trace', parseHeader);
app.get('/tags/:tags', tags);
