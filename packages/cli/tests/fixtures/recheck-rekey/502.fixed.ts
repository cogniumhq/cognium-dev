import type { Request, Response } from 'express';
import express from 'express';
const app = express();
app.post('/profile', function load(req: Request, res: Response) {
  const profile = { name: String(req.body.name) };
  res.json({ name: profile.name });
});
