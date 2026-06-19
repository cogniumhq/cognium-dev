/**
 * Pass: weak-random (CWE-330, category: security)
 *
 * Pattern pass — flags use of non-cryptographic pseudo-random generators.
 * The vulnerability is the *choice of RNG*, not data flow: `new Random()`
 * is always a weak generator regardless of how its output is used.
 *
 * We flag PRNG construction / direct PRNG calls. Mirrors gosec G404 and
 * Bandit B311 behaviour: any use is reported and the developer is expected
 * to triage non-security uses (game RNG, jitter, simulation) as accepted.
 *
 * Detection per language:
 *   Java:
 *     - `new Random()` / `new Random(seed)`
 *     - `Math.random()`
 *     - `ThreadLocalRandom.current().nextX()` (also non-CSPRNG)
 *     - `new SplittableRandom(...)`
 *   Python:
 *     - `random.random()` / `random.randint(...)` / `random.choice(...)` /
 *       `random.uniform(...)` / `random.shuffle(...)` / `random.getrandbits(...)` /
 *       `random.sample(...)` / `random.choices(...)` / `random.randrange(...)` /
 *       `random.seed(...)`
 *   JavaScript / TypeScript:
 *     - `Math.random()`
 *   Go:
 *     - `math/rand` package calls — `rand.Int()`, `Intn()`, `Float64()`, etc.
 *       (Note: we check the bare receiver `rand`; the `crypto/rand` package
 *       is typically aliased on import to disambiguate.)
 *
 * Aligned with: gosec G404, Bandit B311, OWASP Benchmark `weakrand` category.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { CallInfo } from '../../types/index.js';

// Java
const JAVA_RANDOM_METHODS = new Set([
  'nextInt', 'nextLong', 'nextFloat', 'nextDouble', 'nextBoolean',
  'nextBytes', 'nextGaussian', 'ints', 'longs', 'doubles',
]);

// Python random module functions
const PY_RANDOM_FUNCS = new Set([
  'random', 'randint', 'choice', 'uniform', 'shuffle', 'getrandbits',
  'sample', 'choices', 'randrange', 'seed', 'gauss', 'normalvariate',
  'expovariate', 'paretovariate', 'weibullvariate', 'triangular',
  'lognormvariate', 'vonmisesvariate', 'betavariate', 'gammavariate',
]);

// Go math/rand functions
const GO_RAND_FUNCS = new Set([
  'Int', 'Intn', 'Int31', 'Int31n', 'Int63', 'Int63n',
  'Float32', 'Float64', 'NormFloat64', 'ExpFloat64',
  'Perm', 'Shuffle', 'Read', 'Uint32', 'Uint64',
  'Seed', 'New', 'NewSource',
]);

export interface WeakRandomResult {
  findings: Array<{
    line: number;
    language: string;
    api: string;
  }>;
}

export class WeakRandomPass implements AnalysisPass<WeakRandomResult> {
  readonly name = 'weak-random';
  readonly category = 'security' as const;

  run(ctx: PassContext): WeakRandomResult {
    const { graph, language } = ctx;
    const file = graph.ir.meta.file;
    const findings: WeakRandomResult['findings'] = [];

    for (const call of graph.ir.calls) {
      const api = this.detect(call, language, ctx);
      if (!api) continue;

      const line = call.location.line;
      findings.push({ line, language, api });

      ctx.addFinding({
        id: `${this.name}-${file}-${line}`,
        pass: this.name,
        category: this.category,
        rule_id: this.name,
        cwe: 'CWE-330',
        severity: 'medium',
        level: 'warning',
        message:
          `Non-cryptographic random generator \`${api}\` used. The output of ` +
          'this PRNG is predictable and must not be used for security-sensitive ' +
          'values (tokens, session IDs, keys, salts, password reset codes, OTPs).',
        file,
        line,
        fix:
          this.fixFor(language),
        evidence: { api, language },
      });
    }

    return { findings };
  }

  private fixFor(language: string): string {
    switch (language) {
      case 'java':
        return 'Use `java.security.SecureRandom`. Example: ' +
          '`SecureRandom sr = new SecureRandom(); byte[] b = new byte[32]; sr.nextBytes(b);`';
      case 'python':
        return 'Use the `secrets` module (`secrets.token_bytes`, ' +
          '`secrets.token_hex`, `secrets.choice`, `secrets.randbelow`).';
      case 'javascript':
      case 'typescript':
      case 'tsx':
        return 'Use `crypto.randomBytes(n)` (Node.js) or ' +
          '`crypto.getRandomValues(typedArray)` (browser).';
      case 'go':
        return 'Use `crypto/rand` instead of `math/rand`. Example: ' +
          '`b := make([]byte, 32); _, _ = rand.Read(b)` (where `rand` is `crypto/rand`).';
      default:
        return 'Use a cryptographically secure random generator from your standard library.';
    }
  }

  private detect(call: CallInfo, language: string, ctx: PassContext): string | null {
    const method = call.method_name;
    const receiver = call.receiver ?? '';

    if (language === 'java') {
      // `new Random()`, `new SplittableRandom()`
      if (call.is_constructor) {
        const ctor = method;
        if (ctor === 'Random') return 'new Random';
        if (ctor === 'SplittableRandom') return 'new SplittableRandom';
      }
      // `Math.random()`
      if (method === 'random' && (receiver === 'Math' || receiver.endsWith('.Math'))) {
        return 'Math.random';
      }
      // `someRandomInstance.nextInt()` — receiver_type is Random / SplittableRandom / ThreadLocalRandom
      if (JAVA_RANDOM_METHODS.has(method)) {
        const rt = call.receiver_type ?? '';
        if (rt === 'Random' || rt === 'SplittableRandom' || rt === 'ThreadLocalRandom') {
          return `${rt}.${method}`;
        }
      }
      // Chained constructor: `new Random().nextX()` / `new SplittableRandom().nextX()`.
      // For chained `new C().m()`, the IR emits `m` with receiver_type=null
      // (receiver is an expression, not a typed variable), so the receiver_type
      // check above misses. Match the constructor prefix on the receiver
      // expression instead. (cognium-dev #112)
      if (JAVA_RANDOM_METHODS.has(method)) {
        if (/^new\s+Random\s*\(/.test(receiver)) return `new Random.${method}`;
        if (/^new\s+SplittableRandom\s*\(/.test(receiver)) return `new SplittableRandom.${method}`;
      }
      // ThreadLocalRandom.current().nextX() — chained, receiver expression literal
      if (JAVA_RANDOM_METHODS.has(method) && /ThreadLocalRandom\.current\(\)/.test(receiver)) {
        return `ThreadLocalRandom.current.${method}`;
      }
      return null;
    }

    if (language === 'python') {
      // `random.random()`, `random.randint(...)`, etc.
      if ((receiver === 'random' || receiver.endsWith('.random')) && PY_RANDOM_FUNCS.has(method)) {
        return `random.${method}`;
      }
      return null;
    }

    if (language === 'javascript' || language === 'typescript' || language === 'tsx') {
      if (method === 'random' && (receiver === 'Math' || receiver.endsWith('.Math'))) {
        return 'Math.random';
      }
      return null;
    }

    if (language === 'go') {
      // math/rand — receiver is bare `rand` after `import "math/rand"`.
      // `crypto/rand` is also imported as `rand` by default, so we must
      // disambiguate via import inspection to avoid a false positive when
      // only `crypto/rand` is in scope.
      if (receiver === 'rand' && GO_RAND_FUNCS.has(method)) {
        if (this.goMathRandIsActive(ctx)) {
          return `rand.${method}`;
        }
      }
      return null;
    }

    return null;
  }

  /**
   * Returns true when `math/rand` is the active `rand` identifier in this
   * file (i.e. `math/rand` imported unaliased; `crypto/rand` is either not
   * imported or imported under an alias).
   */
  private goMathRandIsActive(ctx: PassContext): boolean {
    const imports = ctx.graph.ir.imports ?? [];
    let mathRandUnaliased = false;
    let cryptoRandUnaliased = false;
    for (const imp of imports) {
      const pkg = imp.from_package ?? imp.imported_name;
      const alias = imp.alias;
      if (pkg === 'math/rand' && (!alias || alias === 'rand')) {
        mathRandUnaliased = true;
      }
      if (pkg === 'crypto/rand' && (!alias || alias === 'rand')) {
        cryptoRandUnaliased = true;
      }
    }
    // Only flag when math/rand owns the bare `rand` symbol.
    return mathRandUnaliased && !cryptoRandUnaliased;
  }
}
