/**
 * `sensitive-data-in-log` (CWE-532) — secret-named values written to a log
 * call on JavaScript / TypeScript.
 *
 * Fixtures in `tests/fixtures/sensitive-data-in-log/`:
 *   - vulnerable.ts  — every `// FLAG` line gives exactly one finding
 *   - fixed.ts       — the same handlers with the secrets kept out: zero
 *   - safe-shapes.ts — near misses (derived values, non-secret names,
 *                      non-logger receivers): zero
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { analyze, initAnalyzer } from '../../../src/analyzer.js';
import { isSecretName, logApi, secretsLogged } from '../../../src/analysis/passes/sensitive-data-in-log-pass.js';

const FIXTURES = resolve(dirname(fileURLToPath(import.meta.url)), '../../fixtures/sensitive-data-in-log');
const fixture = (name: string) => readFileSync(resolve(FIXTURES, name), 'utf8');

type R = Awaited<ReturnType<typeof analyze>>;
const logFindings = (r: R) => (r.findings ?? []).filter(f => f.rule_id === 'sensitive-data-in-log');

describe('sensitive-data-in-log: name matching', () => {
  it.each([
    'password', 'passwd', 'newPassword', 'DB_PASSWORD', 'clientSecret', 'CLIENT_SECRET', 'webhookSecret',
    'JWT_SECRET', 'apiKey', 'api_key', 'stripeApiKey', 'accessToken', 'refresh_token', 'idToken',
    'sessionToken', 'bearerToken', 'privateKey', 'signingKey', 'authorization', 'secret', 'passphrase',
  ])('%s is a secret name', (n) => {
    expect(isSecretName(n)).toBe(true);
  });

  it.each([
    'token', 'pageToken', 'nextPageToken', 'tokenCount', 'csrfToken', 'passwordHash', 'passwordResetUrl',
    'secretName', 'apiKeyId', 'isSecret', 'hasPassword', 'showPassword', 'requirePassword', 'HAS_API_KEY',
    'credential', 'credentials', 'cookie', 'pwd', 'key', 'accessTokenExpiresAt', 'length',
  ])('%s is not a secret name', (n) => {
    expect(isSecretName(n)).toBe(false);
  });
});

describe('sensitive-data-in-log: expression shapes', () => {
  it.each([
    ['password', ['password']],
    ['user.password', ['password']],
    ['this.apiKey!', ['apiKey']],
    ['session?.accessToken', ['accessToken']],
    ["req.headers['authorization']", ['authorization']],
    ['process.env.DB_PASSWORD as string', ['DB_PASSWORD']],
    ['(clientSecret)', ['clientSecret']],
    ['`key=${apiKey} user=${user.id}`', ['apiKey']],
    ["'token: ' + session.refreshToken", ['refreshToken']],
    ['{ email, password }', ['password']],
    ['{ k: env.SIGNING_KEY, "x-y": 1 }', ['SIGNING_KEY']],
    ['[user.id, privateKey]', ['privateKey']],
    ['JSON.stringify({ refreshToken })', ['refreshToken']],
    ['String(secret)', ['secret']],
  ])('%s logs %j', (expr, names) => {
    expect(secretsLogged(expr)).toEqual(names);
  });

  it.each([
    "'password'",
    '"apiKey"',
    'password.length',
    'typeof password',
    '!password',
    'password ? "set" : "unset"',
    'mask(apiKey)',
    'apiKey.slice(0, 4)',
    'hash(password)',
    '`${mask(apiKey)}`',
    '{ ...secrets }',
    '{ password: "[redacted]" }',
    '{ hasPassword: Boolean(password) }',
    'password === other',
    'count + 1',
    'i++',
    'user',
  ])('%s logs nothing', (expr) => {
    expect(secretsLogged(expr)).toEqual([]);
  });
});

describe('sensitive-data-in-log: log calls', () => {
  const call = (receiver: string | null, method: string) =>
    ({ method_name: method, receiver, arguments: [], location: { line: 1, column: 0 } }) as never;

  it.each([
    [null, 'log'], [null, 'logLine'], [null, 'logError'],
    ['console', 'log'], ['console', 'error'], ['console', 'debug'],
    ['logger', 'info'], ['this.logger', 'warn'], ['ctx.log', 'error'], ['appLogger', 'fatal'], ['_logger', 'debug'],
  ])('%s.%s is a log call', (r, m) => {
    expect(logApi(call(r, m))).not.toBeNull();
  });

  it.each([
    [null, 'login'], [null, 'logout'], [null, 'catalog'], ['Math', 'log'], ['catalog', 'log'],
    ['res', 'json'], ['console', 'table'], ['logger', 'child'], ['dialog', 'error'], ['blog', 'info'],
  ])('%s.%s is not a log call', (r, m) => {
    expect(logApi(call(r, m))).toBeNull();
  });
});

describe('sensitive-data-in-log: fixtures', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('vulnerable.ts: one finding per FLAG line, CWE-532, medium', async () => {
    const code = fixture('vulnerable.ts');
    const expected = code.split('\n').flatMap((l, i) => (l.includes('// FLAG') ? [i + 1] : []));
    const r = await analyze(code, 'vulnerable.ts', 'typescript');
    const f = logFindings(r);
    expect(f.map(x => x.line).sort((a, b) => a - b)).toEqual(expected);
    expect(expected.length).toBe(8);
    for (const x of f) {
      expect(x.cwe).toBe('CWE-532');
      expect(x.severity).toBe('medium');
      expect(x.category).toBe('security');
    }
  });

  it('fixed.ts: no finding', async () => {
    const r = await analyze(fixture('fixed.ts'), 'fixed.ts', 'typescript');
    expect(logFindings(r)).toEqual([]);
  });

  it('safe-shapes.ts: no finding', async () => {
    const r = await analyze(fixture('safe-shapes.ts'), 'safe-shapes.ts', 'typescript');
    expect(logFindings(r)).toEqual([]);
  });

  it('JavaScript is covered too', async () => {
    const code = "const password = process.argv[2];\nconsole.log('pw', password);\n";
    const f = logFindings(await analyze(code, 'a.js', 'javascript'));
    expect(f.map(x => x.line)).toEqual([2]);
  });

  it('other languages are out of scope', async () => {
    const code = "import logging\npassword = input()\nlogging.info(password)\n";
    expect(logFindings(await analyze(code, 'a.py', 'python'))).toEqual([]);
  });

  it('can be disabled', async () => {
    const r = await analyze(fixture('vulnerable.ts'), 'vulnerable.ts', 'typescript', {
      disabledPasses: ['sensitive-data-in-log'],
    } as never);
    expect(logFindings(r)).toEqual([]);
  });
});
