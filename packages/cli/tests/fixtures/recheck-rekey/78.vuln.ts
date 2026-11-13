import type { Request, Response } from 'express';
import express from 'express';
import { exec } from 'child_process';
const app = express();
app.get('/ping', function ping(req: Request, res: Response) {
  const host = req.query.host;
  exec('ping -c 1 ' + host, (err, out) => res.send(out));
});
