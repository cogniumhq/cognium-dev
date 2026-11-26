// CWE-117 near miss (#1305 E2): the catch logs the request's own value, next to
// or instead of the error. Every line marked FLAG must give a `log_injection` flow.
import express, { type Request, type Response } from 'express';
import winston from 'winston';

const logger = winston.createLogger({});
const app = express();

function save(name: string): void {
  if (!name) throw new Error('name required');
}

export function create(req: Request, res: Response) {
  const name = req.body.name as string;
  try {
    save(name);
  } catch (e) {
    logger.error('create ' + name + ' failed: ' + (e as Error).message); // FLAG
  }
  res.send('ok');
}

export function update(req: Request, res: Response) {
  try {
    save(req.query.name as string);
  } catch (err) {
    console.error(`update failed for ${req.query.name}`); // FLAG
  }
  res.send('ok');
}

app.post('/create', create);
app.put('/update', update);
