// CWE-1333 fixture: a request value used as the pattern of a regex. Every
// line marked FLAG must give exactly one `redos` flow.
import express, { type Request, type Response } from 'express';

const app = express();

export function search(req: Request, res: Response) {
  const re = new RegExp(req.query.pattern as string); // FLAG
  res.json({ ok: re.test('catalogue') });
}

export function filter(req: Request, res: Response) {
  res.json({ ok: new RegExp(String(req.body.filter), 'i').test('x') }); // FLAG
}

export function highlight(req: Request, res: Response) {
  const term = req.params.term;
  const re = new RegExp(term, 'g'); // FLAG
  res.send('text'.replace(re, '<b>$&</b>'));
}

app.get('/search', search);
app.post('/filter', filter);
app.get('/highlight/:term', highlight);
