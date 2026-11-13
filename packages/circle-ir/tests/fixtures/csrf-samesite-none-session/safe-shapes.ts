// CWE-352 near misses: must produce no `csrf-samesite-none-session` finding.
import express, { type Request, type Response } from 'express';
import session from 'express-session';
import cookieSession from 'cookie-session';

const crossSite = process.env.CROSS_SITE === '1';

// sameSite not set: the browser default (Lax) applies; not decidable here.
export const a = express();
a.use(session({ secret: 's', cookie: { secure: true } }));
a.post('/a', (_req: Request, res: Response) => { res.end(); });

// sameSite from a variable.
export const b = express();
b.use(cookieSession({ name: 's', keys: ['k'], sameSite: crossSite ? 'none' : 'lax' }));
b.post('/b', (_req: Request, res: Response) => { res.end(); });

// Strict.
export const c = express();
c.use(session({ secret: 's', cookie: { sameSite: 'strict' } }));
c.put('/c/:id', (_req: Request, res: Response) => { res.end(); });
