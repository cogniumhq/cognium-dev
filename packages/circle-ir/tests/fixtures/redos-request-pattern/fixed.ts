// CWE-1333 fixture: the same handlers as vulnerable.ts with the request value
// escaped before it becomes a pattern. Must produce no `redos` flow.
import express, { type Request, type Response } from 'express';
import escapeStringRegexp from 'escape-string-regexp';
import _ from 'lodash';

const app = express();

export function search(req: Request, res: Response) {
  const re = new RegExp(escapeStringRegexp(req.query.pattern as string));
  res.json({ ok: re.test('catalogue') });
}

export function filter(req: Request, res: Response) {
  res.json({ ok: new RegExp(_.escapeRegExp(String(req.body.filter)), 'i').test('x') });
}

export function highlight(req: Request, res: Response) {
  const term = escapeStringRegexp(req.params.term);
  const re = new RegExp(term, 'g');
  res.send('text'.replace(re, '<b>$&</b>'));
}

app.get('/search', search);
app.post('/filter', filter);
app.get('/highlight/:term', highlight);
