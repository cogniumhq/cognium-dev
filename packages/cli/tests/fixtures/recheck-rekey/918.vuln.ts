import type { Request, Response } from 'express';
import express from 'express';
import axios from 'axios';
const app = express();
app.get('/fetch', async function proxy(req: Request, res: Response) {
  const url = req.query.url;
  const r = await axios.get(url);
  res.send(r.data);
});
