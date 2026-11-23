// CWE-117 fixture: the same handlers as vulnerable.ts with the value logged
// through JSON.stringify, which escapes CR/LF. Must produce no `log_injection` flow.
import express, { type Request, type Response } from 'express';
import winston from 'winston';

const logger = winston.createLogger({});
const app = express();

export function login(req: Request, res: Response) {
  const user = req.query.user as string;
  console.log('login attempt for ' + JSON.stringify(user));
  res.send('ok');
}

export function search(req: Request, res: Response) {
  const term = req.body.term as string;
  logger.info(`search for ${JSON.stringify(term)}`);
  res.json({ results: [] });
}

app.get('/login', login);
app.post('/search', search);
