// CWE-352 fixture: a session cookie sent cross-site (`sameSite: 'none'`) and
// state-changing routes with no defence. The line marked FLAG must give
// exactly one CWE-352 finding (no defence may be named in this file).
import express, { type Request, type Response } from 'express';
import session from 'express-session';

declare const accounts: { transfer(from: string, to: string, amount: number): void };

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(session({ secret: process.env.SESSION_SECRET ?? '', resave: false, saveUninitialized: false, cookie: { sameSite: 'none', secure: true, httpOnly: true } })); // FLAG

app.post('/transfer', (req: Request, res: Response) => {
  accounts.transfer(String(req.session.id), String(req.body.to), Number(req.body.amount));
  res.redirect('/');
});

app.delete('/payees/:id', (req: Request, res: Response) => {
  res.sendStatus(204);
});

export default app;
