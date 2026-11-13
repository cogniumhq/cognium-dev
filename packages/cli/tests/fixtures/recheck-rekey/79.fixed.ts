import type { Request, Response } from 'express';
import express from 'express';
import escapeHtml from 'escape-html';
const app = express();
app.get('/hello', function hello(req: Request, res: Response) {
  const name = req.query.name;
  res.send('<h1>Hello ' + escapeHtml(name) + '</h1>');
});
