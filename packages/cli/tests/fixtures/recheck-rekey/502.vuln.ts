import type { Request, Response } from 'express';
import express from 'express';
import serialize from 'node-serialize';
const app = express();
app.post('/profile', function load(req: Request, res: Response) {
  const data = req.body.data;
  const profile = serialize.unserialize(data);
  res.json({ name: profile.name });
});
