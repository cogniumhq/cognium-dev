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
import type { ConstantPropagatorResult } from './constant-propagation-pass.js';

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

// Apache Commons Codec DigestUtils — getter form returning MessageDigest.
// Used in OWASP Java benchmark; method name encodes algorithm.
// Example: `DigestUtils.getMd5Digest().digest(input)` (cognium-dev #119).
const COMMONS_DIGEST_GETTERS: Record<string, string> = {
  getMd2Digest: 'md2',
  getMd5Digest: 'md5',
  getSha1Digest: 'sha1',
  getShaDigest: 'sha1',
};

// Apache Commons Codec — `MessageDigestAlgorithms.MD5` / `.SHA_1` constants.
// When `MessageDigest.getInstance(arg)` receives one of these field references
// as its argument, resolve to the corresponding algorithm name.
const COMMONS_ALGO_CONSTANTS: Record<string, string> = {
  'MessageDigestAlgorithms.MD2': 'md2',
  'MessageDigestAlgorithms.MD5': 'md5',
  'MessageDigestAlgorithms.SHA_1': 'sha1',
};

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

/**
 * Resolve the algorithm-name argument of a Java `getInstance(...)` call,
 * preferring an inline literal but falling back to:
 *   - `MessageDigestAlgorithms.MD5` / `.SHA_1` etc. (Apache Commons constants)
 *   - constant-propagation result (`arg.variable` → bound string value)
 *   - regex-scanned source bindings (`final String NAME = "MD5"` /
 *     `static final String NAME = "MD5"` / `private String NAME = "MD5"`)
 *
 * Returns the lowercased algorithm name or null when unresolved.
 * cognium-dev #119: OWASP Java benchmark FNs come from these shapes.
 */
function resolveJavaAlgo(
  call: CallInfo,
  position: number,
  constProp: ConstantPropagatorResult | null,
  javaBindings: Map<string, string>,
): string | null {
  const arg = call.arguments.find((a) => a.position === position);
  if (!arg) return null;

  // 1. Inline literal (existing behaviour)
  if (arg.literal) {
    const cleaned = stripQuotes(arg.literal).toLowerCase();
    if (cleaned) return cleaned;
  }
  const expr = (arg.expression ?? '').trim();
  if (expr.startsWith('"') || expr.startsWith('`') || expr.startsWith("'")) {
    const cleaned = stripQuotes(expr).toLowerCase();
    if (cleaned) return cleaned;
  }

  // 2. Apache Commons Codec algorithm constants
  if (COMMONS_ALGO_CONSTANTS[expr]) return COMMONS_ALGO_CONSTANTS[expr];
  // Also handle fully-qualified form: org.apache.commons.codec.digest.MessageDigestAlgorithms.MD5
  const tail = expr.split('.').slice(-2).join('.');
  if (COMMONS_ALGO_CONSTANTS[tail]) return COMMONS_ALGO_CONSTANTS[tail];

  // 3. Variable resolved via constant propagation
  if (arg.variable && constProp) {
    const sym = constProp.symbols?.get(arg.variable);
    if (sym && sym.type === 'string' && typeof sym.value === 'string') {
      const cleaned = stripQuotes(sym.value).toLowerCase();
      if (cleaned) return cleaned;
    }
  }

  // 4. Regex-scanned source bindings (handles fields and locals the
  //    Java constant-propagation pass does not yet track for hash-algo
  //    strings).
  if (arg.variable) {
    const bound = javaBindings.get(arg.variable);
    if (bound) {
      const cleaned = stripQuotes(bound).toLowerCase();
      if (cleaned) return cleaned;
    }
  }

  return null;
}

/**
 * One-pass regex scan for Java string-literal bindings:
 *   `[modifiers] String NAME = "literal";`
 *
 * Conservative — only inline string literals on the RHS are recognised.
 * Modifiers (`public`, `private`, `static`, `final`, etc.) are skipped.
 * Used as a fallback for the weak-hash pass when the algorithm argument
 * is an identifier reference. (cognium-dev #119)
 */
function scanJavaStringBindings(code: string): Map<string, string> {
  const out = new Map<string, string>();
  if (!code) return out;
  // `[modifiers] String NAME = "MD5";` — modifiers are any combination
  // of public/private/protected/static/final/volatile.
  const re = /^[ \t]*(?:(?:public|private|protected|static|final|volatile)\s+){0,5}String\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*("[^"]*")\s*;/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(code)) !== null) {
    if (m[1] && m[2]) out.set(m[1], m[2]);
  }
  return out;
}

export class WeakHashPass implements AnalysisPass<WeakHashResult> {
  readonly name = 'weak-hash';
  readonly category = 'security' as const;

  run(ctx: PassContext): WeakHashResult {
    const { graph, language, code } = ctx;
    const file = graph.ir.meta.file;
    const findings: WeakHashResult['findings'] = [];

    // Optional constant-propagation result for resolving variable
    // algorithm names (e.g. `final String algo = "MD5";
    // MessageDigest.getInstance(algo)`). cognium-dev #119.
    const constProp = ctx.hasResult('constant-propagation')
      ? ctx.getResult<ConstantPropagatorResult>('constant-propagation')
      : null;

    // Java-only: one-pass regex scan for `String NAME = "literal";` bindings
    // as fallback when const-prop does not track the symbol.
    const javaBindings = language === 'java'
      ? scanJavaStringBindings(code)
      : new Map<string, string>();

    for (const call of graph.ir.calls) {
      const detection = this.detect(call, language, constProp, javaBindings);
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

  private detect(
    call: CallInfo,
    language: string,
    constProp: ConstantPropagatorResult | null,
    javaBindings: Map<string, string>,
  ):
    | { algorithm: string; api: string }
    | null
  {
    const method = call.method_name;
    const receiver = call.receiver ?? '';

    if (language === 'java') {
      // MessageDigest.getInstance("MD5") — literal or resolved variable.
      if (method === 'getInstance' && (receiver === 'MessageDigest' || receiver.endsWith('.MessageDigest'))) {
        const algo = resolveJavaAlgo(call, 0, constProp, javaBindings);
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
      // Apache Commons Codec getter form — DigestUtils.getMd5Digest() /
      // .getSha1Digest() / .getShaDigest(). cognium-dev #119.
      if (COMMONS_DIGEST_GETTERS[method] && (receiver === 'DigestUtils' || receiver.endsWith('.DigestUtils'))) {
        return { algorithm: COMMONS_DIGEST_GETTERS[method], api: `DigestUtils.${method}` };
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
