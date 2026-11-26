// CWE-117 fixture (#1305 E2): a request value is passed to code that may throw,
// and the catch logs the program's own error. The caught `Error` (its message,
// or the error itself) is not the request value: no line here may give a
// `log_injection` flow.
import express, { type Request, type Response } from 'express';
import winston from 'winston';

const logger = winston.createLogger({});
const app = express();

function save(name: string): void {
  if (!name) throw new Error('name required');
}

export function create(req: Request, res: Response) {
  try {
    save(req.body.name);
  } catch (e) {
    console.error('create failed: ' + (e as Error).message);
  }
  res.send('ok');
}

export function update(req: Request, res: Response) {
  try {
    save(req.query.name as string);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.warn(`update failed: ${msg}`);
  }
  res.send('ok');
}

export function remove(req: Request, res: Response) {
  try {
    save(req.params.id);
  }
  catch (err) {
    logger.error('remove failed', err);
  }
  res.send('ok');
}

export function rename(req: Request, res: Response) {
  try {
    save(req.body.to);
  } catch ({ message }) {
    console.log(`rename failed: ${message}`);
  }
  res.send('ok');
}

app.post('/create', create);
app.put('/update', update);
app.delete('/remove/:id', remove);
app.post('/rename', rename);
