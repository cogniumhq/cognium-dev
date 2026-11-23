import type { Request, Response } from 'express';
import express from 'express';
import fs from 'fs';
import path from 'path';
const app = express();
app.get('/file', function readFile(req: Request, res: Response) {
  const name = req.query.name;
  fs.readFile(path.join('/srv/files', name), (e, d) => res.send(d));
});
