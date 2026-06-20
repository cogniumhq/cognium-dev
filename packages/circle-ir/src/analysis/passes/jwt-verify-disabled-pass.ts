/**
 * Pass: jwt-verify-disabled (CWE-347, category: security)
 *
 * Pattern pass — flags places where JWT signature verification is explicitly
 * disabled or set to the `none` algorithm. This is a configuration
 * vulnerability (the bad value is a hard-coded constant), not a taint flow.
 *
 * Detection per language:
 *   Python (PyJWT):
 *     - `jwt.decode(token, ..., options={"verify_signature": False})`
 *     - `jwt.decode(token, ..., verify=False)`         — pre-2.0 PyJWT
 *     - `jwt.decode(token, ..., algorithms=["none"])`  — accepts unsigned tokens
 *   JavaScript / TypeScript (jsonwebtoken):
 *     - `jwt.verify(token, secret, { algorithms: ['none'] })`
 *     - `jwt.verify(token, null, ...)` / `jwt.verify(token, '', ...)` — empty key
 *     - `jwt.verify(token, secret, { verify: false })` (rare)
 *   Java (auth0 java-jwt):
 *     - `JWT.require(Algorithm.none())`               — accepts `alg:none` tokens
 *   Java (jjwt 0.x):
 *     - `Jwts.parser().setSigningKey(...).parse(...)` — `parse` returns Jwt<?,?>
 *       without enforcing the signature; `parseClaimsJws()` is the safe form
 *
 * Aligned with: CWE-347, OWASP API Security Top 10 (API2:2023 broken auth),
 * Bandit B701 (jinja2_autoescape is unrelated — JWT has no direct Bandit rule
 * but PyJWT documents this as misuse).
 *
 * Issue: #86, Sprint 5.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { CallInfo } from '../../types/index.js';

// `verify_signature: False` inside an `options=` dict literal.
const PY_VERIFY_SIGNATURE_FALSE_RE =
  /["']verify_signature["']\s*:\s*False\b/;
// `verify=False` kwarg (pre-2.0 PyJWT).
const PY_VERIFY_KW_FALSE_RE = /\bverify\s*=\s*False\b/;
// `algorithms=['none', ...]` or `algorithms=("none",)` — case-insensitive.
const PY_ALG_NONE_RE = /\balgorithms\s*=\s*[\[\(]\s*["']none["']/i;

// JS `algorithms: ['none']` inside an options literal.
const JS_ALG_NONE_RE = /\balgorithms\s*:\s*\[\s*["']none["']/i;

interface Detection {
  pattern: string;
  api: string;
}

export interface JwtVerifyDisabledResult {
  findings: Array<{
    line: number;
    language: string;
    pattern: string;
    api: string;
  }>;
}

export class JwtVerifyDisabledPass
  implements AnalysisPass<JwtVerifyDisabledResult>
{
  readonly name = 'jwt-verify-disabled';
  readonly category = 'security' as const;

  run(ctx: PassContext): JwtVerifyDisabledResult {
    const { graph, language } = ctx;
    const file = graph.ir.meta.file;
    const findings: JwtVerifyDisabledResult['findings'] = [];

    for (const call of graph.ir.calls) {
      const detections = this.detect(call, language);
      for (const det of detections) {
        const line = call.location.line;
        findings.push({ line, language, ...det });
        ctx.addFinding({
          id: `${this.name}-${file}-${line}-${det.pattern}`,
          pass: this.name,
          category: this.category,
          rule_id: this.name,
          cwe: 'CWE-347',
          severity: 'critical',
          level: 'error',
          message:
            `JWT signature verification disabled via \`${det.pattern}\` in ` +
            `\`${det.api}\`. Any attacker can forge a token with arbitrary ` +
            'claims (user id, roles, expiry) since the signature is not ' +
            'checked.',
          file,
          line,
          fix: this.fixFor(language),
          evidence: { ...det, language },
        });
      }
    }

    return { findings };
  }

  private detect(call: CallInfo, language: string): Detection[] {
    const method = call.method_name;
    const receiver = call.receiver ?? '';
    const out: Detection[] = [];

    if (language === 'python') {
      // PyJWT: jwt.decode(token, key, options={...}, algorithms=[...], verify=...)
      if (receiver === 'jwt' && method === 'decode') {
        for (const arg of call.arguments) {
          const expr = (arg.expression ?? '').trim();
          if (!expr) continue;
          if (PY_VERIFY_SIGNATURE_FALSE_RE.test(expr)) {
            out.push({ pattern: 'verify_signature: False', api: 'jwt.decode' });
          }
          if (PY_VERIFY_KW_FALSE_RE.test(expr)) {
            out.push({ pattern: 'verify=False', api: 'jwt.decode' });
          }
          if (PY_ALG_NONE_RE.test(expr)) {
            out.push({ pattern: "algorithms=['none']", api: 'jwt.decode' });
          }
        }
      }
      return out;
    }

    if (language === 'javascript' || language === 'typescript') {
      // jsonwebtoken: jwt.verify(token, secret, options)
      if (receiver === 'jwt' && method === 'verify') {
        // Inspect option literal for algorithms:['none'] or verify:false.
        for (const arg of call.arguments) {
          const expr = (arg.expression ?? '').trim();
          if (!expr) continue;
          if (JS_ALG_NONE_RE.test(expr)) {
            out.push({ pattern: "algorithms: ['none']", api: 'jwt.verify' });
          }
          if (/\bverify\s*:\s*false\b/i.test(expr)) {
            out.push({ pattern: 'verify: false', api: 'jwt.verify' });
          }
        }
        // Empty / null key as 2nd arg.
        const keyArg = call.arguments.find((a) => a.position === 1);
        const keyExpr = (keyArg?.expression ?? keyArg?.literal ?? '').trim();
        if (keyExpr === 'null' || keyExpr === 'undefined' ||
            keyExpr === '""' || keyExpr === "''" || keyExpr === '``') {
          out.push({ pattern: `empty key (${keyExpr || 'missing'})`, api: 'jwt.verify' });
        }
      }
      return out;
    }

    if (language === 'java') {
      // auth0 java-jwt: JWT.require(Algorithm.none())
      // The argument expression text contains `Algorithm.none()`.
      if (method === 'require' &&
          (receiver === 'JWT' || receiver.endsWith('.JWT'))) {
        const arg = call.arguments.find((a) => a.position === 0);
        const expr = (arg?.expression ?? '').trim();
        if (/\bAlgorithm\s*\.\s*none\s*\(/.test(expr)) {
          out.push({ pattern: 'Algorithm.none()', api: 'JWT.require' });
        }
      }
      // jjwt 0.x: Jwts.parser()...parse(token) — unsafe (no signature check)
      // vs parseClaimsJws / parseSignedClaims which do verify.
      //
      // cognium-dev #121: the original check `receiver.includes('parser')`
      // was too loose — it matched any receiver containing the substring
      // `parser`, including local variables literally named `parser`
      // (parser-combinator code), classes whose name ends in `Parser`
      // (ANTLR, FastDateParser, etc.), and any field/getter with the
      // substring `parser`. Across a 12-repo sample of popular Java OSS
      // this produced 20 critical-severity FPs with zero true positives.
      //
      // Anchor the match to the explicit JJWT chain `Jwts.parser(` so the
      // rule only fires on receivers that syntactically reference the
      // JJWT entry point. Handles:
      //   - Jwts.parser().parse(t)
      //   - Jwts.parser().setSigningKey(k).parse(t)
      //   - io.jsonwebtoken.Jwts.parser().parse(t)  (fully-qualified)
      //   - whitespace variants `Jwts . parser ( )`
      // and rejects bare `parser.parse(...)`, `FooParser.parse(...)`, etc.
      if (method === 'parse' && /\bJwts\s*\.\s*parser\s*\(/.test(receiver)) {
        out.push({ pattern: 'parse() instead of parseClaimsJws()', api: 'Jwts.parser().parse' });
      }
      return out;
    }

    return out;
  }

  private fixFor(language: string): string {
    if (language === 'python') {
      return (
        'Always pass `options={"verify_signature": True}` (the default in ' +
        'PyJWT 2.0+) and a concrete `algorithms=["HS256"|"RS256"]` list. ' +
        'Never accept `none`.'
      );
    }
    if (language === 'javascript' || language === 'typescript') {
      return (
        'Call `jwt.verify(token, secret, { algorithms: ["HS256" | "RS256"] })` ' +
        'with a non-empty key. Never use `algorithms: ["none"]` or pass ' +
        'null/empty as the secret.'
      );
    }
    if (language === 'java') {
      return (
        'For auth0/java-jwt: use `JWT.require(Algorithm.HMAC256(secret))` or ' +
        'an RSA algorithm. For jjwt: call `parseClaimsJws(token)` (signature ' +
        'enforced) rather than `parse(token)` (signature ignored).'
      );
    }
    return (
      'Enforce JWT signature verification with a concrete algorithm ' +
      '(HS256/RS256/ES256). Never accept `alg: none`.'
    );
  }
}
