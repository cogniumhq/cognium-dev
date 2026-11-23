// CWE-532 fixture: common shapes that look close to a secret in a log but are
// not one. Must produce no `sensitive-data-in-log` finding.
declare const logger: { info(...a: unknown[]): void; debug(...a: unknown[]): void };
declare const catalog: { log(entry: unknown): void };
declare const res: { json(body: unknown): void };
declare function mask(v: string): string;
declare function login(user: string, password: string): Promise<void>;

interface User { id: string; passwordHash: string; passwordResetUrl: string; apiKeyId: string }

export async function shapes(user: User, password: string, apiKey: string, token: string, secretName: string,
  isSecret: boolean, hasPassword: boolean, nextPageToken: string, tokenCount: number, credential: { id: string }) {
  console.log('password reset email sent'); // literal only
  console.log('user', user.id, user.passwordHash, user.passwordResetUrl, user.apiKeyId); // derived names
  console.log(typeof password, !password, password.length, apiKey.slice(0, 4)); // derived values
  logger.info(`key ${mask(apiKey)}`, { last4: apiKey.slice(-4) }); // masked
  logger.debug('lexer', token, nextPageToken, tokenCount); // bare token / pagination
  logger.info({ secretName, isSecret, hasPassword, credential }); // names that are not secrets
  logger.info(password ? 'has password' : 'no password'); // ternary
  catalog.log(password); // not a logger
  res.json({ apiKey }); // not a log (response, out of scope here)
  console.log(Math.log(10));
  await login(user.id, password);
}
