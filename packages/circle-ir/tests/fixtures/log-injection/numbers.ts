// CWE-117 fixture (#1305 E2): a request value turned into a number before it is
// logged. A number has no CR/LF, so it cannot split or forge a log entry: no
// line here may give a `log_injection` flow.
import express, { type Request, type Response } from 'express';
import winston from 'winston';

const logger = winston.createLogger({});
const app = express();

export function page(req: Request, res: Response) {
  const n = parseInt(req.query.page as string, 10);
  console.log('page ' + n);
  res.send('ok');
}

export function price(req: Request, res: Response) {
  const p = parseFloat(req.body.price);
  logger.info(`price ${p}`);
  res.send('ok');
}

export function limit(req: Request, res: Response) {
  const v = Number(req.query.limit);
  console.info('limit', v);
  res.send('ok');
}

export function big(req: Request, res: Response) {
  const id = BigInt(req.params.id);
  logger.warn('id ' + id);
  res.send('ok');
}

export function count(req: Request, res: Response) {
  const items = req.body.items as string[];
  const k = items.length;
  console.log(`items: ${k}`);
  res.send('ok');
}

app.get('/page', page);
app.post('/price', price);
app.get('/limit', limit);
app.get('/big/:id', big);
app.post('/count', count);
