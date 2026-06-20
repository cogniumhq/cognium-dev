/**
 * Pass: weak-password-hash (CWE-916, category: security)
 *
 * Detects use of a fast / unsalted hash, or a KDF with insufficient
 * computational cost, applied to a credential-named identifier.
 *
 * Distinct from `weak-hash` (CWE-328):
 *   - `weak-hash` flags broken algorithms (MD2/MD4/MD5/SHA-1) at any call site.
 *   - `weak-password-hash` flags algorithm/cost choices that are SAFE for
 *     general digests but UNSAFE for password storage (e.g. plain SHA-256
 *     of a password, bcrypt cost < 10, PBKDF2 iterations < 100k).
 *
 * Detection per language:
 *   Python:
 *     - `hashlib.sha256(password)` / `.sha512(...)` / etc. where the
 *       argument is a credential-named identifier.
 *     - `bcrypt.hashpw(pw, bcrypt.gensalt(rounds=N))` where N < 10.
 *     - `PBKDF2HMAC(..., iterations=N).derive(pw)` where N < 100000.
 *   JS/TS:
 *     - `crypto.createHash('sha256').update(password).digest()`.
 *     - `bcrypt.hash(pw, N)` / `bcrypt.hashSync(pw, N)` where N < 10.
 *     - `crypto.pbkdf2Sync(pw, salt, N, ...)` where N < 100000.
 *   Java:
 *     - `MessageDigest.getInstance("SHA-256")` followed by `.update(pw)` —
 *       conservative: detect `MessageDigest.getInstance` + `.update(credIdent)`
 *       on any non-broken algorithm. (Broken algos already flagged by weak-hash.)
 *     - `PBEKeySpec(pw, salt, N, ...)` where N < 100000.
 *   Go:
 *     - `sha256.Sum256([]byte(password))`, `sha512.Sum512([]byte(password))`.
 *     - `bcrypt.GenerateFromPassword(pw, cost)` where cost < 10.
 *
 * Aligned with: OWASP ASVS 2.4.1, NIST SP 800-63B §5.1.1.2, gosec G401-style.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { CallInfo } from '../../types/index.js';
import {
  argLooksLikeCredential,
  literalAt,
} from './_credential-helpers.js';

const FAST_HASH_NAMES = new Set([
  'sha224', 'sha-224',
  'sha256', 'sha-256',
  'sha384', 'sha-384',
  'sha512', 'sha-512',
  'sha3', 'sha-3', 'sha3-256', 'sha3-512',
  // MD/SHA1 are covered by weak-hash; not duplicating here.
]);

const BCRYPT_MIN_COST = 10;
const PBKDF2_MIN_ITERATIONS = 100_000;

export interface WeakPasswordHashResult {
  findings: Array<{
    line: number;
    language: string;
    kind: 'fast-unsalted-hash' | 'low-bcrypt-cost' | 'low-pbkdf2-iterations';
    api: string;
  }>;
}

/** Parse an integer literal expression; null if not a clean integer. */
function intLiteral(s: string | null | undefined): number | null {
  if (s == null) return null;
  const t = s.trim();
  if (!/^-?\d+$/.test(t)) return null;
  const n = parseInt(t, 10);
  return Number.isFinite(n) ? n : null;
}

/** Match a Python keyword arg `rounds=4` or `iterations=1000` in the expression text. */
function pyKwargInt(call: CallInfo, name: string): number | null {
  // Walk all argument expressions looking for `name=<int>`.
  for (const a of call.arguments) {
    const expr = (a.expression ?? '').trim();
    const m = expr.match(new RegExp(`^${name}\\s*=\\s*(-?\\d+)$`));
    if (m) return parseInt(m[1], 10);
  }
  return null;
}

export class WeakPasswordHashPass implements AnalysisPass<WeakPasswordHashResult> {
  readonly name = 'weak-password-hash';
  readonly category = 'security' as const;

  run(ctx: PassContext): WeakPasswordHashResult {
    const { graph, language } = ctx;
    const file = graph.ir.meta.file;
    const findings: WeakPasswordHashResult['findings'] = [];

    for (const call of graph.ir.calls) {
      const detection = this.detect(call, language);
      if (!detection) continue;

      const { kind, api } = detection;
      const line = call.location.line;
      findings.push({ line, language, kind, api });

      const message =
        kind === 'fast-unsalted-hash'
          ? `Fast/unsalted hash \`${api}\` applied to a password. ` +
            'General-purpose hashes (SHA-256/512) are unsuitable for password storage.'
          : kind === 'low-bcrypt-cost'
          ? `bcrypt called with insufficient cost factor (< ${BCRYPT_MIN_COST}).`
          : `PBKDF2 called with insufficient iteration count (< ${PBKDF2_MIN_ITERATIONS}).`;

      ctx.addFinding({
        id: `${this.name}-${file}-${line}`,
        pass: this.name,
        category: this.category,
        rule_id: this.name,
        cwe: 'CWE-916',
        severity: 'high',
        level: 'warning',
        message,
        file,
        line,
        fix:
          'Use a memory-hard password-hashing function with appropriate cost: ' +
          'Argon2id (recommended), bcrypt (cost ≥ 12), scrypt, or PBKDF2 with ≥ 600k iterations.',
        evidence: { kind, api, language },
      });
    }

    return { findings };
  }

  private detect(
    call: CallInfo,
    language: string,
  ): { kind: WeakPasswordHashResult['findings'][number]['kind']; api: string } | null {
    const method = call.method_name ?? '';
    const receiver = call.receiver ?? '';
    const recvLower = receiver.toLowerCase();

    // ----- bcrypt cost check (Python / JS / Go) -----
    if (recvLower === 'bcrypt' || recvLower.endsWith('.bcrypt')) {
      // Python: bcrypt.hashpw(pw, bcrypt.gensalt(rounds=4))
      if (method === 'gensalt') {
        const rounds = pyKwargInt(call, 'rounds');
        if (rounds !== null && rounds < BCRYPT_MIN_COST) {
          return { kind: 'low-bcrypt-cost', api: 'bcrypt.gensalt' };
        }
      }
      // JS: bcrypt.hash(pw, cost) / bcrypt.hashSync(pw, cost)
      if (method === 'hash' || method === 'hashSync') {
        const cost = intLiteral(literalAt(call, 1));
        if (cost !== null && cost < BCRYPT_MIN_COST) {
          return { kind: 'low-bcrypt-cost', api: `bcrypt.${method}` };
        }
      }
      // Go: bcrypt.GenerateFromPassword(pw, cost)
      if (method === 'GenerateFromPassword') {
        const arg1 = call.arguments.find((a) => a.position === 1);
        const expr = (arg1?.expression ?? '').trim();
        // Accept `4`, `bcrypt.MinCost`, `bcrypt.DefaultCost` (default = 10 OK).
        const n = intLiteral(expr);
        if (n !== null && n < BCRYPT_MIN_COST) {
          return { kind: 'low-bcrypt-cost', api: 'bcrypt.GenerateFromPassword' };
        }
        if (expr === 'bcrypt.MinCost') {
          return { kind: 'low-bcrypt-cost', api: 'bcrypt.GenerateFromPassword' };
        }
      }
    }

    // ----- PBKDF2 iteration check -----
    // Python: PBKDF2HMAC(algorithm=..., iterations=1000, ...)
    if (method === 'PBKDF2HMAC') {
      const iters = pyKwargInt(call, 'iterations');
      if (iters !== null && iters < PBKDF2_MIN_ITERATIONS) {
        return { kind: 'low-pbkdf2-iterations', api: 'PBKDF2HMAC' };
      }
    }
    // JS: crypto.pbkdf2Sync(pw, salt, iterations, keylen, digest)
    if (
      (method === 'pbkdf2' || method === 'pbkdf2Sync') &&
      (recvLower === 'crypto' || recvLower.endsWith('.crypto'))
    ) {
      const iters = intLiteral(literalAt(call, 2));
      if (iters !== null && iters < PBKDF2_MIN_ITERATIONS) {
        return { kind: 'low-pbkdf2-iterations', api: `crypto.${method}` };
      }
    }
    // Java: new PBEKeySpec(pw, salt, iterations, keylen)
    if (method === 'PBEKeySpec' && language === 'java') {
      const iters = intLiteral(literalAt(call, 2));
      if (iters !== null && iters < PBKDF2_MIN_ITERATIONS) {
        return { kind: 'low-pbkdf2-iterations', api: 'PBEKeySpec' };
      }
    }

    // ----- Fast unsalted hash of a credential identifier -----

    // Python: hashlib.sha256(password) / hashlib.new("sha256", password)
    if (language === 'python' && (recvLower === 'hashlib' || recvLower.endsWith('.hashlib'))) {
      if (FAST_HASH_NAMES.has(method.toLowerCase())) {
        if (argLooksLikeCredential(call.arguments.find((a) => a.position === 0))) {
          return { kind: 'fast-unsalted-hash', api: `hashlib.${method}` };
        }
      }
      if (method === 'new') {
        const algo = literalAt(call, 0)?.toLowerCase() ?? '';
        if (FAST_HASH_NAMES.has(algo) &&
            argLooksLikeCredential(call.arguments.find((a) => a.position === 1))) {
          return { kind: 'fast-unsalted-hash', api: `hashlib.new(${algo})` };
        }
      }
    }

    // JS/TS: crypto.createHash('sha256').update(password)
    // Detect `.update(credentialVar)` when the receiver chain came from
    // crypto.createHash. The IR exposes them as separate calls; we look
    // at the .update call where receiver_type / receiver shape is a hash object.
    if ((language === 'javascript' || language === 'typescript') && method === 'update') {
      // Heuristic: receiver expression contains "createHash" or hash algo name.
      // The IR's `receiver` is typically just an identifier or expression text.
      const recvExpr = (receiver ?? '').toLowerCase();
      const hashLike =
        recvExpr.includes('hash') ||
        recvExpr.includes('createhash') ||
        recvExpr.includes('sha') ||
        recvExpr.includes('md');
      if (hashLike && argLooksLikeCredential(call.arguments.find((a) => a.position === 0))) {
        return { kind: 'fast-unsalted-hash', api: 'crypto.createHash().update' };
      }
    }

    // JS/TS one-shot: crypto.createHash('sha256') — flag when algorithm is
    // a fast hash AND there is any credential-named symbol in the file.
    // Conservative: require the .update on the same line in expression
    // (caught above). Don't fire on createHash alone to avoid FP.

    // Java: MessageDigest.update(passwordBytes) — conservative, only when
    // the argument is credential-named.
    if (language === 'java' && method === 'update') {
      // Receiver should be a MessageDigest variable; we don't track type
      // here, so use weak heuristic: receiver name contains "digest" or "md".
      const recvName = (receiver ?? '').toLowerCase();
      const looksLikeDigest =
        recvName.includes('digest') || recvName.includes('md') || recvName.includes('hash');
      if (looksLikeDigest && argLooksLikeCredential(call.arguments.find((a) => a.position === 0))) {
        return { kind: 'fast-unsalted-hash', api: 'MessageDigest.update' };
      }
    }

    // Go: sha256.Sum256([]byte(password)), sha512.Sum512(...)
    if (language === 'go') {
      const isFastPkg =
        receiver === 'sha256' || receiver === 'sha512' ||
        receiver === 'sha3' || receiver === 'sha224';
      if (isFastPkg && (method === 'Sum256' || method === 'Sum512' || method === 'Sum224' || method === 'Sum384' || method === 'Sum')) {
        // arg[0] is typically `[]byte(passwordVar)`.
        const expr = (call.arguments.find((a) => a.position === 0)?.expression ?? '').trim();
        // Strip `[]byte(...)` wrapper.
        const inner = expr.replace(/^\[\]byte\s*\(\s*/, '').replace(/\s*\)\s*$/, '');
        if (argLooksLikeCredential({ position: 0, expression: inner, variable: inner })) {
          return { kind: 'fast-unsalted-hash', api: `${receiver}.${method}` };
        }
      }
    }

    return null;
  }
}
