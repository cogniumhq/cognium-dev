// CWE-352 near miss: sameSite 'none' with a CSRF token middleware: no finding.
import express, { type Request, type Response } from 'express';
import session from 'express-session';
import { doubleCsrf } from 'csrf-csrf';

const { doubleCsrfProtection } = doubleCsrf({ getSecret: () => 'x' });
const app = express();
app.use(session({ secret: 's', cookie: { sameSite: 'none', secure: true } }));
app.use(doubleCsrfProtection);
app.post('/transfer', (_req: Request, res: Response) => { res.end(); });
export default app;
