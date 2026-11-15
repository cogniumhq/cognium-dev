import type { Request, Response } from 'express';
import express from 'express';
const app = express();
const ALLOWED = { home: '/', account: '/account' };
app.get('/login/done', function finish(req: Request, res: Response) {
  const target = ALLOWED[String(req.query.next)];
  if (!target) { res.status(400).end(); return; }
  res.redirect(target);
});
