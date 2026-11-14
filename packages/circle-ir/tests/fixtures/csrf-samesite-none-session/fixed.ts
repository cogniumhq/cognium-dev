// CWE-352 fixture: vulnerable.ts with the session cookie kept same-site
// (`sameSite: 'lax'`). Must produce no `csrf-samesite-none-session`
// finding.
import express, { type Request, type Response } from 'express';
import session from 'express-session';

declare const accounts: { transfer(from: string, to: string, amount: number): void };

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(session({ secret: process.env.SESSION_SECRET ?? '', resave: false, saveUninitialized: false, cookie: { sameSite: 'lax', secure: true, httpOnly: true } }));

app.post('/transfer', (req: Request, res: Response) => {
  accounts.transfer(String(req.session.id), String(req.body.to), Number(req.body.amount));
  res.redirect('/');
});

app.delete('/payees/:id', (req: Request, res: Response) => {
  res.sendStatus(204);
});

export default app;
