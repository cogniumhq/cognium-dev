import type { Request, Response } from 'express';
import express from 'express';
const app = express();
app.get('/hello', function hello(req: Request, res: Response) {
  const name = req.query.name;
  res.send('<h1>Hello ' + name + '</h1>');
});
