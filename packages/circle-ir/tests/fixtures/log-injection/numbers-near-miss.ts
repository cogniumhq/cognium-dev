// CWE-117 near miss (#1305 E2): looks numeric, but the logged value is still the
// request's string. Every line marked FLAG must give one `log_injection` flow.
import express, { type Request, type Response } from 'express';

const app = express();

export function checked(req: Request, res: Response) {
  const raw = req.query.page as string;
  const n = parseInt(raw, 10);
  if (Number.isNaN(n)) res.status(400);
  console.log('page ' + raw); // FLAG
  res.send('ok');
}

export function padded(req: Request, res: Response) {
  const raw = req.query.id as string;
  console.log('id ' + raw.padStart(8, '0')); // FLAG
  res.send('ok');
}

app.get('/checked', checked);
app.get('/padded', padded);
