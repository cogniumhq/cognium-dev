// CWE-117 fixture: request values written unchanged to a log call, so a
// value carrying CR/LF can forge log entries. Every line marked FLAG must give
// one `log_injection` flow.
import express, { type Request, type Response } from 'express';
import winston from 'winston';

const logger = winston.createLogger({});
const app = express();

export function login(req: Request, res: Response) {
  const user = req.query.user as string;
  console.log('login attempt for ' + user); // FLAG
  res.send('ok');
}

export function search(req: Request, res: Response) {
  const term = req.body.term as string;
  logger.info(`search for ${term}`); // FLAG
  res.json({ results: [] });
}

app.get('/login', login);
app.post('/search', search);
