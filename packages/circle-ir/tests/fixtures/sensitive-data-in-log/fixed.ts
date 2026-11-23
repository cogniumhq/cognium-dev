// CWE-532 fixture: the same handlers as vulnerable.ts with the secrets kept
// out of the logs. Must produce no `sensitive-data-in-log` finding.
import { Hono } from 'hono';

interface Env { CLIENT_SECRET: string; SIGNING_KEY: string }
interface Session { accessToken: string; refreshToken: string; userId: string }

declare const logger: { info(...a: unknown[]): void; warn(...a: unknown[]): void; error(...a: unknown[]): void };
declare function logLine(line: string): void;
declare function exchangeCode(code: string, clientSecret: string): Promise<Session>;
declare function fingerprint(value: string): string;

const app = new Hono<{ Bindings: Env }>();

app.post('/sign-in', async (c) => {
  const { email, password } = await c.req.json<{ email: string; password: string }>();
  console.log('sign-in attempt', email, password.length > 0);
  logger.info({ email, passwordProvided: Boolean(password) });
  return c.json({ ok: true });
});

app.get('/callback', async (c) => {
  const session = await exchangeCode(c.req.query('code') ?? '', c.env.CLIENT_SECRET);
  logLine(`token exchange ok: access=${fingerprint(session.accessToken)}`);
  logger.warn('refresh issued for ' + session.userId);
  console.debug(JSON.stringify({ user: session.userId, refreshToken: '[redacted]' }));
  return c.redirect('/');
});

app.use('*', async (c, next) => {
  const authorization = c.req.header('authorization') ?? '';
  console.info('auth header present', authorization !== '');
  await next();
});

export class KeyService {
  constructor(private readonly logger: { error(...a: unknown[]): void }, private readonly privateKey: string) {}
  fail(env: Env): void {
    this.logger.error('signing failed', { keyId: fingerprint(this.privateKey) });
    console.error(`config: signing key ${env.SIGNING_KEY ? 'set' : 'missing'}`);
  }
}

export default app;
