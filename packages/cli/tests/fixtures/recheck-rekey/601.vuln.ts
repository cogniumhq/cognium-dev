import type { Request, Response } from 'express';
import express from 'express';
const app = express();
app.get('/login/done', function finish(req: Request, res: Response) {
  const next = req.query.next;
  res.redirect(next);
});
