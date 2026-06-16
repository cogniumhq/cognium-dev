/**
 * Pass: weak-hash (CWE-328, category: security)
 *
 * Pattern pass — flags use of cryptographically broken hash algorithms
 * (MD2, MD4, MD5, SHA-1) for security purposes. The vulnerability is
 * the *constant algorithm string*, not data flow: `MessageDigest.getInstance("MD5")`
 * is always vulnerable regardless of input. Therefore this is implemented
 * as call-site literal inspection, not as a taint sink.
 *
 * Detection per language:
 *   Java:
 *     - `MessageDigest.getInstance("MD5"|"SHA-1"|"SHA1"|"MD2"|"MD4")`
 *     - `DigestUtils.md5(...)` / `md5Hex(...)` / `sha1(...)` / `sha1Hex(...)`
 *       (Apache Commons Codec — method name encodes the algorithm)
 *   Python:
 *     - `hashlib.md5(...)` / `hashlib.sha1(...)` / `hashlib.md4(...)` / `hashlib.new("md5", ...)`
 *   JavaScript / TypeScript:
 *     - `crypto.createHash('md5'|'sha1'|'md4'|'md2')`
 *     - `crypto.createHmac('md5'|'sha1', key)`
 *   Go:
 *     - `md5.New()` / `md5.Sum(...)` / `sha1.New()` / `sha1.Sum(...)`
 *       (from `crypto/md5` and `crypto/sha1` packages)
 *
 * Aligned with: gosec G401, Bandit B303/B304, OWASP Benchmark `hash` category.
 *
 * Replaces (and supersedes) the broken taint-sink registration
 * `{method:'getInstance', class:'MessageDigest', type:'weak_hash'}` that
 * could never fire on a literal algorithm name.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { CallInfo } from '../../types/index.js';

const WEAK_HASH_NAMES = new Set([
  'md2', 'md4', 'md5',
  'sha-1', 'sha1',
]);

// Apache Commons Codec DigestUtils — method name encodes algorithm.
const COMMONS_DIGEST_METHODS = new Set([
  'md2', 'md2Hex',
  'md5', 'md5Hex',
  'sha1', 'sha1Hex',
  // Apache Commons also has the misnamed `sha(...)` which is SHA-1
  'sha', 'shaHex',
]);

// Python hashlib direct constructors
const PY_HASHLIB_WEAK = new Set(['md5', 'sha1', 'md4', 'md2', 'new']);

export interface WeakHashResult {
  findings: Array<{
    line: number;
    language: string;
    algorithm: string;
    api: string;
  }>;
}

function stripQuotes(s: string): string {
  const trimmed = s.trim();
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'")) ||
    (trimmed.startsWith('`') && trimmed.endsWith('`'))
  ) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function literalAlgo(call: CallInfo, position: number): string | null {
  const arg = call.arguments.find((a) => a.position === position);
  if (!arg) return null;
  const raw = arg.literal ?? arg.expression ?? '';
  const cleaned = stripQuotes(raw).toLowerCase();
  return cleaned || null;
}

export class WeakHashPass implements AnalysisPass<WeakHashResult> {
  readonly name = 'weak-hash';
  readonly category = 'security' as const;

  run(ctx: PassContext): WeakHashResult {
    const { graph, language } = ctx;
    const file = graph.ir.meta.file;
    const findings: WeakHashResult['findings'] = [];

    for (const call of graph.ir.calls) {
      const detection = this.detect(call, language);
      if (!detection) continue;

      const { algorithm, api } = detection;
      const line = call.location.line;
      findings.push({ line, language, algorithm, api });

      ctx.addFinding({
        id: `${this.name}-${file}-${line}`,
        pass: this.name,
        category: this.category,
        rule_id: this.name,
        cwe: 'CWE-328',
        severity: 'medium',
        level: 'warning',
        message:
          `Weak hash algorithm \`${algorithm.toUpperCase()}\` used via \`${api}\`. ` +
          'MD2/MD4/MD5/SHA-1 are cryptographically broken and must not be used ' +
          'for passwords, signatures, integrity checks, or anywhere collision ' +
          'resistance is required.',
        file,
        line,
        fix:
          'Use SHA-256 or stronger (SHA-384, SHA-512, SHA-3). For passwords, ' +
          'use a password-hashing function: bcrypt, scrypt, Argon2, or PBKDF2.',
        evidence: { algorithm, api, language },
      });
    }

    return { findings };
  }

  private detect(call: CallInfo, language: string):
    | { algorithm: string; api: string }
    | null
  {
    const method = call.method_name;
    const receiver = call.receiver ?? '';

    if (language === 'java') {
      // MessageDigest.getInstance("MD5")
      if (method === 'getInstance' && (receiver === 'MessageDigest' || receiver.endsWith('.MessageDigest'))) {
        const algo = literalAlgo(call, 0);
        if (algo && WEAK_HASH_NAMES.has(algo)) {
          return { algorithm: algo, api: 'MessageDigest.getInstance' };
        }
      }
      // Apache Commons Codec — DigestUtils.md5Hex(...), .sha1(...), etc.
      if (COMMONS_DIGEST_METHODS.has(method) && (receiver === 'DigestUtils' || receiver.endsWith('.DigestUtils'))) {
        const algoFromMethod = method.toLowerCase().replace(/hex$/, '');
        const normalized = algoFromMethod === 'sha' ? 'sha1' : algoFromMethod;
        return { algorithm: normalized, api: `DigestUtils.${method}` };
      }
      return null;
    }

    if (language === 'python') {
      // hashlib.md5(...), .sha1(...), .md4(...), .md2(...)
      if ((receiver === 'hashlib' || receiver.endsWith('.hashlib')) && PY_HASHLIB_WEAK.has(method)) {
        if (method === 'new') {
          const algo = literalAlgo(call, 0);
          if (algo && WEAK_HASH_NAMES.has(algo)) {
            return { algorithm: algo, api: 'hashlib.new' };
          }
          return null;
        }
        return { algorithm: method, api: `hashlib.${method}` };
      }
      return null;
    }

    if (language === 'javascript' || language === 'typescript') {
      // crypto.createHash('md5') / crypto.createHmac('sha1', key)
      if ((method === 'createHash' || method === 'createHmac') && receiver === 'crypto') {
        const algo = literalAlgo(call, 0);
        if (algo && WEAK_HASH_NAMES.has(algo)) {
          return { algorithm: algo, api: `crypto.${method}` };
        }
      }
      return null;
    }

    if (language === 'go') {
      // md5.New() / md5.Sum(...) / sha1.New() / sha1.Sum(...)
      const isWeakPkg = receiver === 'md5' || receiver === 'sha1';
      if (isWeakPkg && (method === 'New' || method === 'Sum')) {
        return { algorithm: receiver, api: `${receiver}.${method}` };
      }
      return null;
    }

    return null;
  }
}
