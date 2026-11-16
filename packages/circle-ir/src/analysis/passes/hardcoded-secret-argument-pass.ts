/**
 * Pass: hardcoded-secret-argument (CWE-798, category: security)
 *
 * Pattern pass for JavaScript / TypeScript: a string literal written straight
 * into the credential position of a known API. The position, not the shape of
 * the value, says it is a secret, so there is no length or entropy gate (the
 * line-based `scan-secrets` layers need one and so miss `password: 'Winter2024!'`
 * or `session({ secret: 'keyboard cat' })`).
 *
 * Positions recognised (the callee must be bound to the package in the file,
 * by `import` or `require`, except where noted):
 *   - `jsonwebtoken`: `jwt.sign(payload, LIT)`, `jwt.verify(token, LIT)`
 *   - `crypto` / `node:crypto`: `createHmac(alg, LIT)`, `createCipheriv(alg, LIT, iv)`,
 *     `createDecipheriv(alg, LIT, iv)` (namespace or named import)
 *   - `express-session`: `session({ secret: LIT | [LIT, ...] })`
 *   - `cookie-session`: `cookieSession({ secret: LIT, keys: [LIT, ...] })`
 *   - `cookie-parser`: `cookieParser(LIT | [LIT, ...])`
 *   - `express-jwt`: `expressjwt({ secret: LIT })` / `jwt({ secret: LIT })`
 *   - `passport-jwt`: `new JwtStrategy({ secretOrKey: LIT })` (also by the
 *     conventional name `JwtStrategy` when the binding is not visible)
 *   - `mysql` / `mysql2`: `createConnection | createPool({ password: LIT })`
 *   - `pg`: `new Pool | Client({ password: LIT })`
 *   - `sequelize`: `new Sequelize(db, user, LIT, ...)`
 *   - `nodemailer`: `createTransport({ auth: { pass: LIT } })`
 *
 * A value counts only when it is a non-empty string literal (or a template
 * literal with no substitution), or an array made only of such literals.
 * Abstain on identifiers, member reads (`process.env.X`, `config.secret`),
 * calls, concatenations, placeholders (`changeme`, `your-secret-here`, ...),
 * values that only name their slot (`'password'`, `'secret'`), a Sequelize
 * SQLite connection (no password is used),
 * test / fixture / generated files, and other languages. Connection-string
 * credentials (`mongodb://user:pw@host`) stay with `scan-secrets` layer 1c.
 *
 * Emits `rule_id: 'hardcoded-credential'` (the CWE-798 rule id the other
 * layers use) and skips a line that already carries one.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { CallInfo, ImportInfo } from '../../types/index.js';
import { PLACEHOLDER_RE, isGeneratedFile, isTestFile } from './scan-secrets-pass.js';

type Position =
  | { kind: 'arg'; index: number; arrays?: boolean }
  | { kind: 'prop'; index: number; path: readonly string[]; arrays?: boolean };

interface ApiRule {
  /** Packages the callee must come from. */
  packages: readonly string[];
  /** Method name (receiver bound to the package) or bare / constructor name. */
  name: string;
  /** `member`: `<pkgBinding>.<name>(...)`; `bare`: `<binding>(...)` where the binding is the import. */
  form: 'member' | 'bare';
  positions: readonly Position[];
  /** Also accept the bare name with no visible binding (conventional names only). */
  nameFallback?: boolean;
  label: string;
}

const CRYPTO = ['crypto', 'node:crypto'] as const;
const MYSQL = ['mysql', 'mysql2', 'mysql2/promise'] as const;

const RULES: readonly ApiRule[] = [
  { packages: ['jsonwebtoken'], name: 'sign', form: 'member', positions: [{ kind: 'arg', index: 1 }], label: 'jwt.sign signing key' },
  { packages: ['jsonwebtoken'], name: 'verify', form: 'member', positions: [{ kind: 'arg', index: 1 }], label: 'jwt.verify key' },
  { packages: CRYPTO, name: 'createHmac', form: 'member', positions: [{ kind: 'arg', index: 1 }], label: 'HMAC key' },
  { packages: CRYPTO, name: 'createHmac', form: 'bare', positions: [{ kind: 'arg', index: 1 }], label: 'HMAC key' },
  { packages: CRYPTO, name: 'createCipheriv', form: 'member', positions: [{ kind: 'arg', index: 1 }], label: 'cipher key' },
  { packages: CRYPTO, name: 'createCipheriv', form: 'bare', positions: [{ kind: 'arg', index: 1 }], label: 'cipher key' },
  { packages: CRYPTO, name: 'createDecipheriv', form: 'member', positions: [{ kind: 'arg', index: 1 }], label: 'cipher key' },
  { packages: CRYPTO, name: 'createDecipheriv', form: 'bare', positions: [{ kind: 'arg', index: 1 }], label: 'cipher key' },
  { packages: ['express-session'], name: '*', form: 'bare', positions: [{ kind: 'prop', index: 0, path: ['secret'], arrays: true }], label: 'session secret' },
  {
    packages: ['cookie-session'], name: '*', form: 'bare',
    positions: [{ kind: 'prop', index: 0, path: ['secret'] }, { kind: 'prop', index: 0, path: ['keys'], arrays: true }],
    label: 'cookie-session key',
  },
  { packages: ['cookie-parser'], name: '*', form: 'bare', positions: [{ kind: 'arg', index: 0, arrays: true }], label: 'cookie-parser secret' },
  { packages: ['express-jwt'], name: '*', form: 'bare', positions: [{ kind: 'prop', index: 0, path: ['secret'] }], label: 'express-jwt secret' },
  { packages: ['passport-jwt'], name: 'JwtStrategy', form: 'bare', nameFallback: true, positions: [{ kind: 'prop', index: 0, path: ['secretOrKey'] }], label: 'passport-jwt secretOrKey' },
  { packages: ['passport-jwt'], name: 'Strategy', form: 'bare', positions: [{ kind: 'prop', index: 0, path: ['secretOrKey'] }], label: 'passport-jwt secretOrKey' },
  { packages: MYSQL, name: 'createConnection', form: 'member', positions: [{ kind: 'prop', index: 0, path: ['password'] }], label: 'database password' },
  { packages: MYSQL, name: 'createPool', form: 'member', positions: [{ kind: 'prop', index: 0, path: ['password'] }], label: 'database password' },
  { packages: ['pg'], name: 'Pool', form: 'bare', positions: [{ kind: 'prop', index: 0, path: ['password'] }], label: 'database password' },
  { packages: ['pg'], name: 'Client', form: 'bare', positions: [{ kind: 'prop', index: 0, path: ['password'] }], label: 'database password' },
  { packages: ['pg'], name: 'Pool', form: 'member', positions: [{ kind: 'prop', index: 0, path: ['password'] }], label: 'database password' },
  { packages: ['pg'], name: 'Client', form: 'member', positions: [{ kind: 'prop', index: 0, path: ['password'] }], label: 'database password' },
  { packages: ['sequelize'], name: 'Sequelize', form: 'bare', positions: [{ kind: 'arg', index: 2 }], label: 'database password' },
  { packages: ['nodemailer'], name: 'createTransport', form: 'member', positions: [{ kind: 'prop', index: 0, path: ['auth', 'pass'] }], label: 'SMTP password' },
];

/** Local name → package, from the file's imports and requires. `bare` maps a name to the package it is (part of). */
function bindings(imports: readonly ImportInfo[]): Map<string, string> {
  const m = new Map<string, string>();
  for (const imp of imports) {
    if (!imp.from_package) continue;
    const local = imp.alias ?? (imp.imported_name !== 'default' && imp.imported_name !== '*' ? imp.imported_name : null);
    if (local) m.set(local, imp.from_package);
  }
  return m;
}

/** Name an import binds to when it imports `name` from a package (named import), or the package's default/namespace. */
function importsName(imports: readonly ImportInfo[], local: string): ImportInfo | undefined {
  return imports.find((i) => (i.alias ?? i.imported_name) === local && i.from_package != null);
}

/** Index just past the string literal starting at `s[i]` (quote at `s[i]`), or -1 if unterminated. */
function skipString(s: string, i: number): number {
  const q = s[i];
  for (let j = i + 1; j < s.length; j++) {
    if (s[j] === '\\') { j++; continue; }
    if (s[j] === q) return j + 1;
  }
  return -1;
}

/** Split `s` at top-level `sep`, skipping strings and brackets; null on unbalanced input. */
export function splitTopLevel(s: string, sep: string): string[] | null {
  const out: string[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch === '"' || ch === "'" || ch === '`') {
      const end = skipString(s, i);
      if (end < 0) return null;
      i = end - 1;
      continue;
    }
    if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '}') { depth--; if (depth < 0) return null; }
    else if (ch === sep && depth === 0) { out.push(s.slice(start, i)); start = i + 1; }
  }
  if (depth !== 0) return null;
  out.push(s.slice(start));
  return out;
}

/** The value of a plain string literal (no template substitution), else null. */
export function stringLiteralValue(expr: string): string | null {
  const e = expr.trim();
  if (e.length < 2) return null;
  const q = e[0];
  if ((q !== '"' && q !== "'" && q !== '`') || e[e.length - 1] !== q) return null;
  if (skipString(e, 0) !== e.length) return null;
  const body = e.slice(1, -1);
  if (q === '`' && body.includes('${')) return null;
  return body;
}

/** Literal values of `expr`: one string literal, or (with `arrays`) an array made only of string literals. */
export function literalValues(expr: string, arrays: boolean): string[] | null {
  const one = stringLiteralValue(expr);
  if (one !== null) return [one];
  if (!arrays) return null;
  const e = expr.trim();
  if (!e.startsWith('[') || !e.endsWith(']')) return null;
  const parts = splitTopLevel(e.slice(1, -1), ',');
  if (!parts) return null;
  const vals: string[] = [];
  for (const p of parts) {
    if (p.trim() === '') continue;
    const v = stringLiteralValue(p);
    if (v === null) return null;
    vals.push(v);
  }
  return vals.length > 0 ? vals : null;
}

/** The value text of property `path` in an object literal `expr`, or null. Nested via `path`. */
export function propertyValue(expr: string, path: readonly string[]): string | null {
  let cur = expr.trim();
  for (const key of path) {
    if (!cur.startsWith('{') || !cur.endsWith('}')) return null;
    const entries = splitTopLevel(cur.slice(1, -1), ',');
    if (!entries) return null;
    let found: string | null = null;
    for (const entry of entries) {
      const colon = topLevelColon(entry);
      if (colon < 0) continue;
      // The key is the last line before the colon (a `// comment` line may precede it).
      let k = (entry.slice(0, colon).split('\n').pop() ?? '').trim();
      const kq = stringLiteralValue(k);
      if (kq !== null) k = kq;
      if (k === key) found = entry.slice(colon + 1).trim();
    }
    if (found === null) return null;
    cur = found;
  }
  return cur;
}

function topLevelColon(entry: string): number {
  let depth = 0;
  for (let i = 0; i < entry.length; i++) {
    const ch = entry[i];
    if (ch === '"' || ch === "'" || ch === '`') {
      const end = skipString(entry, i);
      if (end < 0) return -1;
      i = end - 1;
      continue;
    }
    if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '}') depth--;
    else if (ch === ':' && depth === 0) return i;
  }
  return -1;
}

/** Values that only name the slot they fill (`'password'`, `'secret'`): sample code, not a credential. */
const SLOT_NAMES: ReadonlySet<string> = new Set(['password', 'passwd', 'pass', 'secret', 'key', 'username', 'user', 'token']);

function isRealSecret(v: string): boolean {
  if (v.trim() === '') return false;
  if (PLACEHOLDER_RE.test(v)) return false;
  if (SLOT_NAMES.has(v.trim().toLowerCase())) return false;
  return true;
}

/** `new Sequelize(db, user, pw, { dialect: 'sqlite' })`: SQLite has no password, the argument is unused. */
function isSqliteSequelize(call: CallInfo): boolean {
  const opts = call.arguments.find((a) => a.position === 3)?.expression;
  if (!opts) return false;
  const dialect = propertyValue(opts, ['dialect']);
  return dialect !== null && stringLiteralValue(dialect) === 'sqlite';
}

/** The rule a call matches, or null. */
export function matchRule(call: CallInfo, imports: readonly ImportInfo[]): ApiRule | null {
  const binds = bindings(imports);
  const receiver = (call.receiver ?? '').trim();
  for (const rule of RULES) {
    if (rule.form === 'member') {
      if (!receiver || call.method_name !== rule.name) continue;
      const root = receiver.split('.')[0];
      const pkg = binds.get(root);
      if (pkg && rule.packages.includes(pkg)) return rule;
      continue;
    }
    // bare
    if (receiver) continue;
    const imp = importsName(imports, call.method_name);
    if (imp && imp.from_package && rule.packages.includes(imp.from_package)) {
      if (rule.name === '*') return rule;
      // `import { createHmac } from 'crypto'`, `const { Pool } = require('pg')`, a default or
      // namespace import under the API's own name, or a named import aliased to another name.
      if (call.method_name === rule.name || imp.imported_name === rule.name) return rule;
      continue;
    }
    if (!imp && rule.nameFallback && call.method_name === rule.name) return rule;
  }
  return null;
}

export interface HardcodedSecretArgumentResult {
  findings: Array<{ line: number; api: string; label: string }>;
}

export class HardcodedSecretArgumentPass implements AnalysisPass<HardcodedSecretArgumentResult> {
  readonly name = 'hardcoded-secret-argument';
  readonly category = 'security' as const;

  run(ctx: PassContext): HardcodedSecretArgumentResult {
    const { graph, language } = ctx;
    const findings: HardcodedSecretArgumentResult['findings'] = [];
    if (language !== 'javascript' && language !== 'typescript') return { findings };
    const file = graph.ir.meta.file;
    if (isTestFile(file) || isGeneratedFile(file)) return { findings };
    const imports = graph.ir.imports ?? [];
    if (imports.length === 0 && !ctx.code.includes('JwtStrategy')) return { findings };

    const seen = new Set<number>();
    for (const f of ctx.getFindings?.() ?? []) {
      if (f.file === file && (f.rule_id === 'hardcoded-credential' || f.rule_id === 'hardcoded-credential-entropy')) seen.add(f.line);
    }
    const lineStarts = [0];
    for (let i = 0; i < ctx.code.length; i++) if (ctx.code[i] === '\n') lineStarts.push(i + 1);
    const lineAt = (offset: number): number => {
      let lo = 0, hi = lineStarts.length - 1;
      while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (lineStarts[mid] <= offset) lo = mid; else hi = mid - 1; }
      return lo + 1;
    };

    for (const call of graph.ir.calls) {
      const rule = matchRule(call, imports);
      if (!rule) continue;
      if (rule.name === 'Sequelize' && isSqliteSequelize(call)) continue;
      for (const pos of rule.positions) {
        const arg = call.arguments.find((a) => a.position === pos.index);
        if (!arg || !arg.expression) continue;
        const valueText = pos.kind === 'arg' ? arg.expression : propertyValue(arg.expression, pos.path);
        if (valueText === null) continue;
        const vals = literalValues(valueText, pos.arrays === true);
        if (!vals || !vals.some(isRealSecret)) continue;

        // Report on the line of the literal itself (multi-line option objects).
        let line = call.location.line;
        const from = lineStarts[Math.max(0, call.location.line - 1)] ?? 0;
        const argAt = ctx.code.indexOf(arg.expression, from);
        if (argAt >= 0) {
          const inArg = pos.kind === 'arg' ? 0 : arg.expression.lastIndexOf(valueText);
          if (inArg >= 0) line = lineAt(argAt + inArg);
        }
        if (seen.has(line)) continue;
        seen.add(line);

        const api = call.receiver ? `${call.receiver}.${call.method_name}` : call.method_name;
        findings.push({ line, api, label: rule.label });
        ctx.addFinding({
          id: `hardcoded-credential-${file}-${line}`,
          pass: this.name,
          category: this.category,
          rule_id: 'hardcoded-credential',
          cwe: 'CWE-798',
          severity: 'high',
          level: 'error',
          message:
            `Hardcoded credential: a string literal is passed as the ${rule.label} of \`${api}\`. ` +
            'Anyone who can read the source can sign, decrypt or log in with it.',
          file,
          line,
          fix: 'Load the secret from the environment or a secrets manager (for example `process.env.JWT_SECRET`), and rotate the exposed value.',
          evidence: { kind: 'secret-argument', api, position: rule.label, language },
        });
      }
    }
    return { findings };
  }
}
