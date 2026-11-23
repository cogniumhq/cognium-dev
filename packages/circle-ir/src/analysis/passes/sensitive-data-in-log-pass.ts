/**
 * Pass: sensitive-data-in-log (CWE-532, category: security)
 *
 * Pattern pass for JavaScript / TypeScript: a secret-named value (password,
 * client secret, API key, access / refresh / ID / session token, private
 * key, `Authorization` header) is written to a log call as is.
 *
 * Log calls recognised:
 *   - `console.{log,info,warn,error,debug,trace}(...)`
 *   - `<logger>.{log,info,warn,warning,error,debug,trace,fatal,verbose,critical}(...)`
 *     where the receiver's last segment is `log`, `logger`, `_log`, `_logger`
 *     or ends in `Logger` (`this.logger`, `appLogger`, `ctx.log`)
 *   - bare `log(...)`, `logLine(...)`, `logInfo / logWarn / logWarning /
 *     logError / logDebug / logTrace(...)`
 *
 * A value counts only when the secret reaches the log text unchanged:
 *   - the argument itself is a reference (`password`, `user.password`,
 *     `process.env.DB_PASSWORD`, `req.headers['authorization']`, `this.apiKey!`,
 *     `token as string`);
 *   - a template-literal substitution (`` `key=${apiKey}` ``);
 *   - an operand of a string `+` concatenation;
 *   - an object-literal value or shorthand (`{ password }`, `{ pw: user.password }`);
 *   - an array element;
 *   - the first argument of `JSON.stringify(...)` or `String(...)`.
 *
 * Precision (abstain rather than guess):
 *   - Any other call around the value (`mask(apiKey)`, `hash(password)`,
 *     `apiKey.slice(0, 4)`), a member read past the secret (`password.length`,
 *     `token.expiresAt`), `typeof`, `!`, comparisons and ternaries are not
 *     followed: they log a derived value, not the secret.
 *   - Names are matched whole, after dropping `_` / `-` / `$` and case:
 *     `passwordHash`, `tokenCount`, `secretName`, `apiKeyId`, `pageToken`,
 *     `passwordResetUrl` do not match. A bare `token` does not match either
 *     (lexer and pagination tokens), nor does `credential` (WebAuthn
 *     credentials are public), nor `cookie`.
 *   - Flag-like names (`isSecret`, `hasPassword`, `showPassword`,
 *     `requirePassword`) do not match.
 *   - String literals never match (`console.log('password reset sent')`).
 *   - Receivers that are not loggers (`Math.log`, `catalog.log`, `res.json`)
 *     are not sinks.
 *
 * Out of scope: a whole object logged by reference (`logger.info(user)`),
 * secrets reaching a log through an intermediate variable, logger-side
 * redaction configured elsewhere (pino `redact`), and other languages.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { CallInfo } from '../../types/index.js';

const CONSOLE_METHODS: ReadonlySet<string> = new Set(['log', 'info', 'warn', 'error', 'debug', 'trace']);

const LOGGER_METHODS: ReadonlySet<string> = new Set([
  'log', 'info', 'warn', 'warning', 'error', 'debug', 'trace', 'fatal', 'verbose', 'critical',
]);

const LOGGER_RECEIVERS: ReadonlySet<string> = new Set(['log', 'logger', '_log', '_logger']);

const BARE_LOG_FUNCTIONS: ReadonlySet<string> = new Set([
  'log', 'logLine', 'logInfo', 'logWarn', 'logWarning', 'logError', 'logDebug', 'logTrace',
]);

/** Whole secret names, normalised (lower case, no `_` / `-` / `$`). */
const SECRET_NAMES: ReadonlySet<string> = new Set([
  'password', 'passwd', 'passphrase',
  'secret', 'clientsecret', 'apisecret', 'secretkey', 'secretaccesskey',
  'apikey', 'apitoken',
  'accesstoken', 'refreshtoken', 'idtoken', 'sessiontoken', 'authtoken', 'bearertoken',
  'privatekey', 'signingkey',
  'authorization',
]);

/** Suffixes that keep their meaning behind a qualifier (`dbPassword`, `webhookSecret`, `githubAccessToken`). */
const SECRET_SUFFIXES: readonly string[] = [
  'password', 'passphrase', 'secret', 'apikey', 'privatekey', 'accesstoken', 'refreshtoken',
];

/** Flag-like prefixes: `isSecret`, `hasPassword`, `showPassword`, `HAS_API_KEY`. */
const FLAG_PREFIXES: readonly string[] = [
  'is', 'has', 'show', 'should', 'need', 'needs', 'require', 'requires', 'allow', 'use',
  'min', 'max', 'num', 'no', 'with', 'without', 'enable', 'enabled', 'disable', 'valid', 'invalid', 'missing',
];

const MAX_EXPR_LENGTH = 2000;
const MAX_DEPTH = 6;

/** Split an identifier into words: camelCase, snake_case, kebab-case, SCREAMING_CASE. */
function words(name: string): string[] {
  const out: string[] = [];
  let cur = '';
  for (let i = 0; i < name.length; i++) {
    const ch = name[i];
    if (ch === '_' || ch === '-' || ch === '$') {
      if (cur) out.push(cur);
      cur = '';
      continue;
    }
    const prev = i > 0 ? name[i - 1] : '';
    const isUpper = ch >= 'A' && ch <= 'Z';
    const prevLower = (prev >= 'a' && prev <= 'z') || (prev >= '0' && prev <= '9');
    if (isUpper && prevLower && cur) {
      out.push(cur);
      cur = '';
    }
    cur += ch;
  }
  if (cur) out.push(cur);
  return out.map((w) => w.toLowerCase());
}

/** True when an identifier names a secret value (whole-name match, see header). */
export function isSecretName(name: string): boolean {
  if (!name || name.length < 3) return false;
  const ws = words(name);
  if (ws.length === 0) return false;
  if (ws.length > 1 && FLAG_PREFIXES.includes(ws[0])) return false;
  const norm = ws.join('');
  if (SECRET_NAMES.has(norm)) return true;
  return SECRET_SUFFIXES.some((s) => norm.length > s.length && norm.endsWith(s));
}

function isIdentStart(ch: string): boolean {
  return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch === '_' || ch === '$';
}

function isIdentChar(ch: string): boolean {
  return isIdentStart(ch) || (ch >= '0' && ch <= '9');
}

/** Index just past the string literal starting at `i` (quote at `s[i]`), or -1 if unterminated. */
function skipString(s: string, i: number): number {
  const q = s[i];
  for (let j = i + 1; j < s.length; j++) {
    if (s[j] === '\\') { j++; continue; }
    if (q === '`' && s[j] === '$' && s[j + 1] === '{') {
      const end = skipBalanced(s, j + 1);
      if (end < 0) return -1;
      j = end - 1;
      continue;
    }
    if (s[j] === q) return j + 1;
  }
  return -1;
}

/** Index just past the bracket group opening at `s[i]`, or -1 if unbalanced. */
function skipBalanced(s: string, i: number): number {
  const open = s[i];
  const close = open === '(' ? ')' : open === '[' ? ']' : '}';
  let depth = 0;
  for (let j = i; j < s.length; j++) {
    const ch = s[j];
    if (ch === '"' || ch === "'" || ch === '`') {
      const end = skipString(s, j);
      if (end < 0) return -1;
      j = end - 1;
      continue;
    }
    if (ch === open) depth++;
    else if (ch === close) {
      depth--;
      if (depth === 0) return j + 1;
    }
  }
  return -1;
}

/**
 * Split `s` at top-level occurrences of `sep` (`,` or `+`). Returns null when
 * the text cannot be scanned (unbalanced brackets / strings). For `+`, a `++`
 * or `+=` makes the whole expression unscannable (abstain).
 */
function splitTopLevel(s: string, sep: ',' | '+'): string[] | null {
  const parts: string[] = [];
  let start = 0;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch === '"' || ch === "'" || ch === '`') {
      const end = skipString(s, i);
      if (end < 0) return null;
      i = end - 1;
      continue;
    }
    if (ch === '(' || ch === '[' || ch === '{') {
      const end = skipBalanced(s, i);
      if (end < 0) return null;
      i = end - 1;
      continue;
    }
    if (ch === sep) {
      if (sep === '+' && (s[i + 1] === '+' || s[i + 1] === '=' || s[i - 1] === '+')) return null;
      parts.push(s.slice(start, i));
      start = i + 1;
    }
  }
  parts.push(s.slice(start));
  return parts.map((p) => p.trim());
}

/** The `${...}` substitutions of a template literal (text between the backticks). */
function templateSubstitutions(s: string): string[] | null {
  const subs: string[] = [];
  for (let i = 1; i < s.length - 1; i++) {
    if (s[i] === '\\') { i++; continue; }
    if (s[i] === '$' && s[i + 1] === '{') {
      const end = skipBalanced(s, i + 1);
      if (end < 0) return null;
      subs.push(s.slice(i + 2, end - 1).trim());
      i = end - 1;
    }
  }
  return subs;
}

/** Strip TypeScript-only wrappers that leave the value unchanged: `x!`, `x as T`, `x satisfies T`, `(x)`. */
function stripTransparent(expr: string): string {
  let e = expr.trim();
  for (let guard = 0; guard < 8; guard++) {
    const before = e;
    const asIdx = Math.max(e.lastIndexOf(' as '), e.lastIndexOf(' satisfies '));
    if (asIdx > 0 && splitTopLevel(e.slice(0, asIdx), ',')?.length === 1) {
      const head = e.slice(0, asIdx).trim();
      // Only when the head is itself a plain reference (avoid cutting inside a larger expression).
      if (referenceTerminal(head) !== null) e = head;
    }
    if (e.endsWith('!') && !e.endsWith('!=')) e = e.slice(0, -1).trim();
    if (e.startsWith('(') && skipBalanced(e, 0) === e.length) e = e.slice(1, -1).trim();
    if (e === before) break;
  }
  return e;
}

/**
 * When `expr` is a plain reference — an identifier, optionally `this.`-rooted,
 * followed by `.name`, `?.name`, `!` or `['literal']` segments — return its
 * last segment's name. Otherwise null.
 */
function referenceTerminal(expr: string): string | null {
  const s = expr.trim();
  if (!s || !isIdentStart(s[0])) return null;
  let i = 0;
  const readIdent = (): string | null => {
    if (i >= s.length || !isIdentStart(s[i])) return null;
    const st = i;
    while (i < s.length && isIdentChar(s[i])) i++;
    return s.slice(st, i);
  };
  const first = readIdent();
  if (first === null) return null;
  let last = first;
  while (i < s.length) {
    if (s[i] === '!') { i++; continue; }
    if (s[i] === '.' || (s[i] === '?' && s[i + 1] === '.' && s[i + 2] !== '[')) {
      i += s[i] === '.' ? 1 : 2;
      const id = readIdent();
      if (id === null) return null;
      last = id;
      continue;
    }
    if (s[i] === '[' || (s[i] === '?' && s[i + 1] === '.' && s[i + 2] === '[')) {
      if (s[i] === '?') i += 2;
      const end = skipBalanced(s, i);
      if (end < 0) return null;
      const inner = s.slice(i + 1, end - 1).trim();
      const q = inner[0];
      if ((q !== '"' && q !== "'") || inner.length < 2 || inner[inner.length - 1] !== q) return null;
      const key = inner.slice(1, -1);
      for (const ch of key) if (!isIdentChar(ch) && ch !== '-') return null;
      last = key;
      i = end;
      continue;
    }
    return null;
  }
  return last;
}

/** The secret names that reach the log text unchanged through `expr`. */
export function secretsLogged(expr: string, depth = 0): string[] {
  if (depth > MAX_DEPTH || expr.length > MAX_EXPR_LENGTH) return [];
  const e = stripTransparent(expr);
  if (!e) return [];

  const term = referenceTerminal(e);
  if (term !== null) return isSecretName(term) ? [term] : [];

  const first = e[0];
  if (first === '`') {
    if (skipString(e, 0) !== e.length) return [];
    const subs = templateSubstitutions(e);
    return subs ? subs.flatMap((x) => secretsLogged(x, depth + 1)) : [];
  }
  if (first === '"' || first === "'") {
    if (skipString(e, 0) === e.length) return [];
  }
  if (first === '{' && skipBalanced(e, 0) === e.length) {
    const entries = splitTopLevel(e.slice(1, -1), ',');
    if (!entries) return [];
    const out: string[] = [];
    for (const entry of entries) {
      if (!entry || entry.startsWith('...')) continue;
      const shorthand = referenceTerminal(entry);
      if (shorthand !== null && shorthand === entry) {
        if (isSecretName(entry)) out.push(entry);
        continue;
      }
      const colon = topLevelColon(entry);
      if (colon < 0) continue; // method shorthand, getter, etc.
      out.push(...secretsLogged(entry.slice(colon + 1), depth + 1));
    }
    return out;
  }
  if (first === '[' && skipBalanced(e, 0) === e.length) {
    const items = splitTopLevel(e.slice(1, -1), ',');
    return items ? items.flatMap((x) => (x.startsWith('...') ? [] : secretsLogged(x, depth + 1))) : [];
  }
  const wrapped = transparentCallArg(e);
  if (wrapped !== null) return secretsLogged(wrapped, depth + 1);

  const plus = splitTopLevel(e, '+');
  if (plus && plus.length > 1 && plus.every((p) => p.length > 0)) {
    return plus.flatMap((p) => secretsLogged(p, depth + 1));
  }
  return [];
}

/** Index of the key/value `:` at the top level of an object-literal entry, or -1. */
function topLevelColon(entry: string): number {
  for (let i = 0; i < entry.length; i++) {
    const ch = entry[i];
    if (ch === '"' || ch === "'" || ch === '`') {
      const end = skipString(entry, i);
      if (end < 0) return -1;
      i = end - 1;
      continue;
    }
    if (ch === '(' || ch === '[' || ch === '{') {
      // A computed key `[k]: v` is fine; a `(` before any `:` is a method.
      if (ch === '(') return -1;
      const end = skipBalanced(entry, i);
      if (end < 0) return -1;
      i = end - 1;
      continue;
    }
    if (ch === ':') return i;
  }
  return -1;
}

/** For `JSON.stringify(x, ...)` / `String(x)`, the text of `x`; otherwise null. */
function transparentCallArg(e: string): string | null {
  let callee: string;
  if (e.startsWith('JSON.stringify(')) callee = 'JSON.stringify';
  else if (e.startsWith('String(')) callee = 'String';
  else return null;
  const open = callee.length;
  if (skipBalanced(e, open) !== e.length) return null;
  const args = splitTopLevel(e.slice(open + 1, -1), ',');
  if (!args || !args[0]) return null;
  return args[0];
}

/** The log API a call writes to, or null when the call is not a log call. */
export function logApi(call: CallInfo): string | null {
  const method = call.method_name;
  const receiver = (call.receiver ?? '').trim();
  if (!receiver) return BARE_LOG_FUNCTIONS.has(method) ? method : null;
  if (receiver === 'console') return CONSOLE_METHODS.has(method) ? `console.${method}` : null;
  if (!LOGGER_METHODS.has(method)) return null;
  const lastDot = receiver.lastIndexOf('.');
  const seg = receiver.slice(lastDot + 1);
  for (const ch of seg) if (!isIdentChar(ch)) return null;
  if (LOGGER_RECEIVERS.has(seg.toLowerCase()) || (seg.length > 'Logger'.length && seg.endsWith('Logger'))) {
    return `${receiver}.${method}`;
  }
  return null;
}

export interface SensitiveDataInLogResult {
  findings: Array<{ line: number; api: string; names: string[] }>;
}

export class SensitiveDataInLogPass implements AnalysisPass<SensitiveDataInLogResult> {
  readonly name = 'sensitive-data-in-log';
  readonly category = 'security' as const;

  run(ctx: PassContext): SensitiveDataInLogResult {
    const { graph, language } = ctx;
    const findings: SensitiveDataInLogResult['findings'] = [];
    if (language !== 'javascript' && language !== 'typescript') return { findings };
    const file = graph.ir.meta.file;
    const seen = new Set<number>();

    for (const call of graph.ir.calls) {
      const api = logApi(call);
      if (!api) continue;
      const names: string[] = [];
      for (const arg of call.arguments) {
        const expr = arg.expression ?? '';
        if (!expr) continue;
        for (const n of secretsLogged(expr)) if (!names.includes(n)) names.push(n);
      }
      if (names.length === 0) continue;
      const line = call.location.line;
      if (seen.has(line)) continue;
      seen.add(line);
      findings.push({ line, api, names });
      ctx.addFinding({
        id: `${this.name}-${file}-${line}`,
        pass: this.name,
        category: this.category,
        rule_id: this.name,
        cwe: 'CWE-532',
        severity: 'medium',
        level: 'warning',
        message:
          `Secret value${names.length > 1 ? 's' : ''} ${names.map((n) => `\`${n}\``).join(', ')} ` +
          `written to the log by \`${api}\`. Anyone who can read the logs (log storage, ` +
          'aggregation, support tooling) can reuse the credential.',
        file,
        line,
        fix:
          'Do not log the secret. Log a non-secret handle instead (a key id, the last ' +
          'four characters, a fingerprint such as a truncated hash), or drop the field.',
        evidence: { api, names, language },
      });
    }
    return { findings };
  }
}
