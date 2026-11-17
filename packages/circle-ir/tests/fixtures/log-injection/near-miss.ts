// CWE-117 near miss: a .replace that removes no CR/LF is not a fix. Every
// line marked FLAG must still give one `log_injection` flow.
import express, { type Request, type Response } from 'express';
import winston from 'winston';

const logger = winston.createLogger({});
const app = express();

export function login(req: Request, res: Response) {
  const user = String(req.query.user).replace('a', 'a');
  console.log('login attempt for ' + user); // FLAG
  res.send('ok');
}

export function search(req: Request, res: Response) {
  const term = String(req.body.term).replace('a', 'a');
  logger.info(`search for ${term}`); // FLAG
  res.json({ results: [] });
}

app.get('/login', login);
app.post('/search', search);
