// CWE-352 near miss: sameSite 'none' with an origin check: no finding.
import express, { type Request, type Response, type NextFunction } from 'express';
import session from 'express-session';

const app = express();
app.use(session({ secret: 's', cookie: { sameSite: 'none', secure: true } }));
app.use((req: Request, res: Response, next: NextFunction) => {
  if (req.method !== 'GET' && req.get('origin') !== 'https://app.example.com') return res.sendStatus(403);
  return next();
});
app.post('/transfer', (_req: Request, res: Response) => { res.end(); });
export default app;
