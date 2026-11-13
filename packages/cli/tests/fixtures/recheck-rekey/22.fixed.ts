import type { Request, Response } from 'express';
import express from 'express';
import fs from 'fs';
import path from 'path';
const app = express();
const BASE = '/srv/files';
app.get('/file', function readFile(req: Request, res: Response) {
  const name = path.basename(String(req.query.name));
  const full = path.resolve(BASE, name);
  if (!full.startsWith(BASE + path.sep)) { res.status(400).end(); return; }
  fs.readFile(full, (e, d) => res.send(d));
});
