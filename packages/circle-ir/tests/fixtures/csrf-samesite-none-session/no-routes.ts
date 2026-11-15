// CWE-352 near miss: the session is configured here, routes live elsewhere: no finding.
import express from 'express';
import session from 'express-session';

export function mountSession(app: express.Express) {
  app.use(session({ secret: 's', cookie: { sameSite: 'none', secure: true } }));
}
