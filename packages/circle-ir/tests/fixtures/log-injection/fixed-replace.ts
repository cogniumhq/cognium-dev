// CWE-117 fixture: the same handlers as vulnerable.ts with CR/LF stripped
// before the value is logged. Must produce no `log_injection` flow.
import express, { type Request, type Response } from 'express';
import winston from 'winston';

const logger = winston.createLogger({});
const app = express();

export function login(req: Request, res: Response) {
  const user = String(req.query.user).replace(/[\r\n]/g, '');
  console.log('login attempt for ' + user);
  res.send('ok');
}

export function search(req: Request, res: Response) {
  const term = String(req.body.term).replace(/[\r\n]/g, '');
  logger.info(`search for ${term}`);
  res.json({ results: [] });
}

app.get('/login', login);
app.post('/search', search);
