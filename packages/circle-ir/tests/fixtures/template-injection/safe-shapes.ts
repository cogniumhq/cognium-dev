// CWE-1336 near misses: must produce no `template_injection` finding.
import { readFileSync } from 'node:fs';
import type { Request, Response } from 'express';
import ejs from 'ejs';
import Handlebars from 'handlebars';
import pug from 'pug';

const PAGE = readFileSync('views/page.ejs', 'utf8');

// A template read from disk, request data as context.
export function page(req: Request, res: Response) {
  const q = req.query.q as string;
  res.send(ejs.render(PAGE, { q }));
}

// A template file rendered by name.
export function file(req: Request, res: Response) {
  const name = req.params.name;
  ejs.renderFile('views/profile.ejs', { name }, (_e: unknown, html: string) => res.send(html));
}

// The tainted name only appears inside the template text.
export function greeting(req: Request, res: Response) {
  const user = req.query.user as string;
  res.send(Handlebars.compile('Hi {{user}}, user, welcome')({ user }));
}

// A constant template built from constants.
const HEADER = '<header>';
export function header(req: Request, res: Response) {
  const title = req.query.title as string;
  res.send(pug.render(`${HEADER}h1= title`, { title }));
}
