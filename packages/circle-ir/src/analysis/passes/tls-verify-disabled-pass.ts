/**
 * Pass: tls-verify-disabled (CWE-295, category: security)
 *
 * Pattern pass — flags places where TLS certificate / hostname verification
 * is explicitly disabled. This is a *configuration* vulnerability (the bad
 * value is hard-coded, no taint flow is involved).
 *
 * Detection per language:
 *   Go:
 *     - `&tls.Config{InsecureSkipVerify: true}` (composite literal)
 *     - Detected via call argument scan: when the receiver is `tls` and
 *       call/composite contains literal `InsecureSkipVerify: true`, OR via
 *       a syntactic text scan (composite literals are not always emitted
 *       as calls in IR).
 *     - `(*x509.Certificate).Verify` with `x509.VerifyOptions` and no
 *       intermediate-CA denylist / blocklist guard in the same file — PKIX
 *       chain acceptance without checking blocked intermediates (CWE-295).
 *   Python:
 *     - `requests.get|post|put|delete|patch|head|options|request(..., verify=False)`
 *     - `ssl._create_unverified_context()` / `ssl._create_default_https_context = ssl._create_unverified_context`
 *     - `urllib3.disable_warnings(InsecureRequestWarning)` — best-effort hint
 *     - `httpx.Client(verify=False)` / `httpx.get(..., verify=False)`
 *   JavaScript / TypeScript:
 *     - `{ rejectUnauthorized: false }` in https.request / fetch options /
 *       node-fetch / axios — text scan on arg expressions
 *     - `https.Agent({ rejectUnauthorized: false })`
 *     - Custom `checkServerIdentity` that always succeeds (`=> undefined` /
 *       `=> null` / empty body) — disables hostname verification without
 *       setting `rejectUnauthorized: false`
 *     - Custom `checkServerIdentity` that accepts after loose host parsing
 *       (digit-only IP folding, helper such as `looseIp`) — CWE-295 weak identity
 *     - Custom `checkServerIdentity` that compares hosts after Unicode NFKC
 *       normalization (fullwidth / homograph confusion)
 *     - Custom `checkServerIdentity` that accepts when the requested host
 *       appears in subjectAltName / DNS SAN text (DNS↔IP confusion)
 *     - Custom `checkServerIdentity` that walks `issuerCertificate` without
 *       an intermediate denylist / blocklist guard
 *     - `process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'` (assignment;
 *       detected via call to property assignment — best-effort)
 *   Java:
 *     - Custom `HostnameVerifier` that returns true unconditionally
 *       (lambdas `(h, s) -> true` / anonymous classes) — detected via
 *       textual scan on setHostnameVerifier arg expression.
 *     - `setHostnameVerifier(NoopHostnameVerifier.INSTANCE)` /
 *       `setHostnameVerifier(new AllowAllHostnameVerifier())`
 *
 * Aligned with: gosec G402 (Go), Bandit B501/B502/B504/B505 (Python).
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { CallInfo } from '../../types/index.js';

// Python HTTP libraries whose calls accept a verify=False kwarg.
const PY_HTTP_METHODS = new Set([
  'get', 'post', 'put', 'delete', 'patch', 'head', 'options', 'request',
  'send',
]);
const PY_HTTP_RECEIVERS = new Set([
  'requests', 'httpx',
]);

const VERIFY_FALSE_RE = /\bverify\s*=\s*False\b/;
const REJECT_UNAUTHORIZED_FALSE_RE = /\brejectUnauthorized\s*:\s*false\b/;
const INSECURE_SKIP_VERIFY_TRUE_RE = /\bInsecureSkipVerify\s*:\s*true\b/;
const GO_X509_VERIFY_CALL_RE = /\.Verify\s*\(/;
const GO_INTERMEDIATE_DENYLIST_GUARD_RE =
  /\b(denylist|denyList|deny_list|blocklist|blockList|blockedIntermediate|blocked_intermediate|deniedIntermediate|denied_intermediate|isDeniedIntermediate|intermediateDenylist|intermediate_denylist)\b/i;
const HOSTNAME_LAMBDA_TRUE_RE = /\(\s*\w+\s*,\s*\w+\s*\)\s*->\s*true\b/;
// C#: a cert-validation callback given an always-true lambda — assigned
// (`= `/`+= `) or wrapped in a delegate constructor (`new …Callback( … )`).
// Accepts a parenthesised or single-identifier parameter list and either
// `=> true` or `=> { return true; }`.
const CS_CERT_CALLBACK_TRUE_RE =
  /\b(ServerCertificateValidationCallback|ServerCertificateCustomValidationCallback|RemoteCertificateValidationCallback)\s*(?:\+?=|\()\s*(?:\([^)]*\)|\w+)\s*=>\s*(?:true\b|\{\s*return\s+true\b)/;
const CS_DANGEROUS_ACCEPT_RE = /\bDangerousAcceptAnyServerCertificateValidator\b/;
const ALLOW_ALL_HOSTNAME_VERIFIERS = new Set([
  'NoopHostnameVerifier.INSTANCE',
  'new AllowAllHostnameVerifier()',
  'new NoopHostnameVerifier()',
]);
// Node TLS: returning undefined/null from checkServerIdentity means success.
const JS_CHECK_SERVER_IDENTITY_NOP_RE =
  /\bcheckServerIdentity\s*:\s*(?:async\s*)?\([^)]*\)\s*=>\s*(?:undefined|null)\b/;
const JS_CHECK_SERVER_IDENTITY_NOP_FN_RE =
  /\bcheckServerIdentity\s*:\s*function\s*\([^)]*\)\s*\{\s*return\s+(?:undefined|null)\s*;?\s*\}/;
const JS_CHECK_SERVER_IDENTITY_DECL_RE =
  /\bfunction\s+checkServerIdentity\s*\([^)]*\)\s*\{/g;
const JS_LOOSE_IP_HOST_STRIP_RE = /\.replace\s*\(\s*\/\[\^\\d\.\]\\]\//;
const JS_CHECK_SERVER_IDENTITY_LOOSE_BODY_RE =
  /(?:looseIp\s*\(|\.replace\s*\(\s*\/\[\^\\d\.\]\\]\/)[\s\S]*?return\s+undefined\b/;
const JS_NFKC_NORMALIZE_RE = /\.normalize\s*\(\s*['"]NFKC['"]\s*\)/i;
const JS_SUBJECT_ALT_NAME_RE =
  /\bsubjectaltname\b|\bsubjectAltName\b|\baltNames\b|\bDNS:\b|\bIP Address:/i;
const JS_ISSUER_CHAIN_WALK_RE = /\bissuerCertificate\b/;

export interface TlsVerifyDisabledResult {
  findings: Array<{
    line: number;
    language: string;
    pattern: string;
    api: string;
  }>;
}

export class TlsVerifyDisabledPass implements AnalysisPass<TlsVerifyDisabledResult> {
  readonly name = 'tls-verify-disabled';
  readonly category = 'security' as const;

  run(ctx: PassContext): TlsVerifyDisabledResult {
    const { graph, language, code } = ctx;
    const file = graph.ir.meta.file;
    const findings: TlsVerifyDisabledResult['findings'] = [];

    // Call-based detection (most precise — uses arg.expression text).
    for (const call of graph.ir.calls) {
      const det = this.detectCall(call, language);
      if (!det) continue;

      const line = call.location.line;
      findings.push({ line, language, ...det });

      ctx.addFinding({
        id: `${this.name}-${file}-${line}-${det.pattern}`,
        pass: this.name,
        category: this.category,
        rule_id: this.name,
        cwe: 'CWE-295',
        severity: 'high',
        level: 'error',
        message:
          `TLS certificate verification disabled via \`${det.pattern}\` in ` +
          `\`${det.api}\`. The connection becomes vulnerable to active ` +
          'man-in-the-middle attacks — any attacker on the network path can ' +
          'present a forged certificate.',
        file,
        line,
        fix: this.fixFor(language, det.pattern),
        evidence: { ...det, language },
      });
    }

    // Source-text scan for composite-literal / module-level patterns that
    // do not surface as IR calls (Go `tls.Config{}`, Python ssl globals,
    // Node `NODE_TLS_REJECT_UNAUTHORIZED`).
    for (const extra of this.detectSourceText(code, language)) {
      const dupKey = `${extra.line}-${extra.pattern}`;
      if (findings.some((f) => `${f.line}-${f.pattern}` === dupKey)) continue;
      findings.push({ ...extra, language });
      ctx.addFinding({
        id: `${this.name}-${file}-${extra.line}-${extra.pattern}`,
        pass: this.name,
        category: this.category,
        rule_id: this.name,
        cwe: 'CWE-295',
        severity: 'high',
        level: 'error',
        message:
          `TLS certificate verification disabled via \`${extra.pattern}\` ` +
          `(${extra.api}). Vulnerable to active man-in-the-middle.`,
        file,
        line: extra.line,
        fix: this.fixFor(language, extra.pattern),
        evidence: { ...extra, language },
      });
    }

    return { findings };
  }

  private detectCall(call: CallInfo, language: string):
    | { pattern: string; api: string }
    | null
  {
    const method = call.method_name;
    const receiver = call.receiver ?? '';

    if (language === 'python') {
      // requests.get(..., verify=False) etc.
      if (PY_HTTP_RECEIVERS.has(receiver) && PY_HTTP_METHODS.has(method)) {
        for (const arg of call.arguments) {
          const expr = (arg.expression ?? '').trim();
          if (VERIFY_FALSE_RE.test(expr)) {
            return { pattern: 'verify=False', api: `${receiver}.${method}` };
          }
        }
      }
      // ssl._create_unverified_context()
      if (method === '_create_unverified_context' && receiver === 'ssl') {
        return { pattern: 'ssl._create_unverified_context', api: 'ssl._create_unverified_context()' };
      }
      // httpx.Client(verify=False) — same shape via constructor; receiver is module.
      if (receiver === 'httpx' && method === 'Client') {
        for (const arg of call.arguments) {
          if (VERIFY_FALSE_RE.test(arg.expression ?? '')) {
            return { pattern: 'verify=False', api: 'httpx.Client' };
          }
        }
      }
      return null;
    }

    if (language === 'javascript' || language === 'typescript') {
      // axios.create({httpsAgent: new https.Agent({rejectUnauthorized: false})}),
      // https.request({rejectUnauthorized: false}, ...), fetch(url, {agent: ...})
      // We do an arg-expression text scan because the option commonly appears
      // inside an inline object literal.
      //
      // The JS plugin sometimes surfaces `new https.Agent(...)` with
      // method_name='https.Agent' and receiver=null (rather than receiver='https',
      // method='Agent'). Accept the trailing segment of the dotted name too.
      const lastSeg = method.includes('.') ? method.split('.').pop() ?? '' : method;
      const arglooks =
        method === 'request' || method === 'get' || method === 'post' ||
        method === 'create' || method === 'Agent' || method === 'fetch' ||
        lastSeg === 'Agent' || lastSeg === 'request' || lastSeg === 'create';
      if (arglooks) {
        for (const arg of call.arguments) {
          if (REJECT_UNAUTHORIZED_FALSE_RE.test(arg.expression ?? '')) {
            return { pattern: 'rejectUnauthorized: false', api: `${receiver || '(global)'}.${method}` };
          }
        }
      }
      return null;
    }

    if (language === 'java') {
      // someConn.setHostnameVerifier((h, s) -> true)
      if (method === 'setHostnameVerifier') {
        const arg = call.arguments.find((a) => a.position === 0);
        const expr = (arg?.expression ?? '').trim();
        if (HOSTNAME_LAMBDA_TRUE_RE.test(expr)) {
          return { pattern: '(h,s) -> true', api: 'setHostnameVerifier' };
        }
        for (const v of ALLOW_ALL_HOSTNAME_VERIFIERS) {
          if (expr === v || expr.replace(/\s+/g, '') === v.replace(/\s+/g, '')) {
            return { pattern: v, api: 'setHostnameVerifier' };
          }
        }
      }
      return null;
    }

    return null;
  }

  private detectSourceText(code: string, language: string): Array<{
    line: number; pattern: string; api: string;
  }> {
    const out: Array<{ line: number; pattern: string; api: string }> = [];
    const lines = code.split('\n');

    if (language === 'go') {
      // Look for `InsecureSkipVerify: true` literal anywhere — overwhelmingly
      // appears in tls.Config{} composite literals.
      for (let i = 0; i < lines.length; i++) {
        if (INSECURE_SKIP_VERIFY_TRUE_RE.test(lines[i])) {
          out.push({
            line: i + 1,
            pattern: 'InsecureSkipVerify: true',
            api: 'tls.Config',
          });
        }
      }
      if (
        /\bx509\./.test(code) &&
        /\bVerifyOptions\b/.test(code) &&
        GO_X509_VERIFY_CALL_RE.test(code) &&
        !GO_INTERMEDIATE_DENYLIST_GUARD_RE.test(code)
      ) {
        for (let i = 0; i < lines.length; i++) {
          if (GO_X509_VERIFY_CALL_RE.test(lines[i])) {
            out.push({
              line: i + 1,
              pattern: 'x509.Verify without intermediate denylist',
              api: 'x509.Certificate.Verify',
            });
            break;
          }
        }
      }
    }

    if (language === 'python') {
      for (let i = 0; i < lines.length; i++) {
        const l = lines[i];
        if (/ssl\._create_default_https_context\s*=\s*ssl\._create_unverified_context/.test(l)) {
          out.push({
            line: i + 1,
            pattern: 'ssl._create_default_https_context = _create_unverified_context',
            api: 'ssl module override',
          });
        }
      }
    }

    if (language === 'javascript' || language === 'typescript') {
      for (let i = 0; i < lines.length; i++) {
        const l = lines[i];
        if (/process\.env\.NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]0['"]/.test(l)) {
          out.push({
            line: i + 1,
            pattern: 'NODE_TLS_REJECT_UNAUTHORIZED=0',
            api: 'process.env',
          });
        }
        if (
          JS_CHECK_SERVER_IDENTITY_NOP_RE.test(l) ||
          JS_CHECK_SERVER_IDENTITY_NOP_FN_RE.test(l)
        ) {
          out.push({
            line: i + 1,
            pattern: 'checkServerIdentity => undefined',
            api: 'tls.connect / https.request options',
          });
        }
      }
      // Multi-line arrow bodies (options object spans lines).
      const m = JS_CHECK_SERVER_IDENTITY_NOP_RE.exec(code) ?? JS_CHECK_SERVER_IDENTITY_NOP_FN_RE.exec(code);
      if (m && m.index !== undefined) {
        const line = code.slice(0, m.index).split('\n').length;
        const dupKey = `${line}-checkServerIdentity => undefined`;
        if (!out.some((o) => `${o.line}-${o.pattern}` === dupKey)) {
          out.push({
            line,
            pattern: 'checkServerIdentity => undefined',
            api: 'tls.connect / https.request options',
          });
        }
      }
      for (const weak of this.detectWeakCheckServerIdentityCallbacks(code)) {
        const dupKey = `${weak.line}-${weak.pattern}`;
        if (!out.some((o) => `${o.line}-${o.pattern}` === dupKey)) {
          out.push({
            line: weak.line,
            pattern: weak.pattern,
            api: 'checkServerIdentity (custom)',
          });
        }
      }
    }

    if (language === 'csharp') {
      // A certificate-validation callback whose body is `true` accepts every
      // cert (active MITM). Covers ServicePointManager.ServerCertificateValidationCallback,
      // HttpClientHandler.ServerCertificateCustomValidationCallback and the
      // RemoteCertificateValidationCallback delegate — assigned an always-true
      // lambda (`(s,c,ch,e) => true` / `=> { return true; }`) or the built-in
      // `HttpClientHandler.DangerousAcceptAnyServerCertificateValidator`.
      for (let i = 0; i < lines.length; i++) {
        const l = lines[i];
        const m = CS_CERT_CALLBACK_TRUE_RE.exec(l);
        if (m) {
          out.push({ line: i + 1, pattern: `${m[1]} => true`, api: m[1] });
        } else if (CS_DANGEROUS_ACCEPT_RE.test(l)) {
          out.push({
            line: i + 1,
            pattern: 'DangerousAcceptAnyServerCertificateValidator',
            api: 'HttpClientHandler',
          });
        }
      }
    }

    return out;
  }

  /** Standalone and inline `checkServerIdentity` with weak identity checks. */
  private detectWeakCheckServerIdentityCallbacks(code: string): Array<{
    line: number;
    pattern: string;
  }> {
    const hits: Array<{ line: number; pattern: string }> = [];
    const fileHasDenylist = GO_INTERMEDIATE_DENYLIST_GUARD_RE.test(code);

    const declRe = new RegExp(JS_CHECK_SERVER_IDENTITY_DECL_RE.source, 'g');
    let match: RegExpExecArray | null;
    while ((match = declRe.exec(code)) !== null) {
      const openBrace = code.indexOf('{', match.index);
      if (openBrace < 0) continue;
      const body = this.sliceBalancedBraces(code, openBrace);
      if (!body) continue;
      const prelude = code.slice(Math.max(0, match.index - 800), match.index);
      const line = code.slice(0, match.index).split('\n').length;
      const weak = this.classifyWeakCheckServerIdentityBody(
        body, prelude, fileHasDenylist,
      );
      if (weak) hits.push({ line, pattern: weak });
    }

    const inlineRe =
      /\bcheckServerIdentity\s*:\s*(?:async\s*)?function\s*\([^)]*\)\s*\{/g;
    while ((match = inlineRe.exec(code)) !== null) {
      const openBrace = code.indexOf('{', match.index);
      if (openBrace < 0) continue;
      const body = this.sliceBalancedBraces(code, openBrace);
      if (!body) continue;
      const prelude = code.slice(Math.max(0, match.index - 800), match.index);
      const line = code.slice(0, match.index).split('\n').length;
      const weak = this.classifyWeakCheckServerIdentityBody(
        body, prelude, fileHasDenylist,
      );
      if (weak) hits.push({ line, pattern: weak });
    }

    return hits;
  }

  private classifyWeakCheckServerIdentityBody(
    body: string,
    prelude: string,
    fileHasDenylist: boolean,
  ): string | null {
    if (!/\breturn\s+undefined\b/.test(body)) return null;

    const loose =
      JS_LOOSE_IP_HOST_STRIP_RE.test(body) ||
      JS_LOOSE_IP_HOST_STRIP_RE.test(prelude) ||
      /\blooseIp\s*\(/.test(body);
    if (loose && JS_CHECK_SERVER_IDENTITY_LOOSE_BODY_RE.test(body)) {
      return 'checkServerIdentity loose host parse => undefined';
    }

    const nfkc =
      JS_NFKC_NORMALIZE_RE.test(body) || JS_NFKC_NORMALIZE_RE.test(prelude);
    if (nfkc && /\breturn\s+undefined\b/.test(body)) {
      return 'checkServerIdentity NFKC host normalize => undefined';
    }

    if (JS_SUBJECT_ALT_NAME_RE.test(body) && /\breturn\s+undefined\b/.test(body)) {
      return 'checkServerIdentity DNS SAN / IP match => undefined';
    }

    if (
      JS_ISSUER_CHAIN_WALK_RE.test(body) &&
      !fileHasDenylist &&
      /\breturn\s+undefined\b/.test(body)
    ) {
      return 'checkServerIdentity issuer chain without denylist => undefined';
    }

    return null;
  }

  private sliceBalancedBraces(code: string, openIndex: number): string | null {
    if (code[openIndex] !== '{') return null;
    let depth = 0;
    for (let i = openIndex; i < code.length; i++) {
      const ch = code[i];
      if (ch === '{') depth++;
      else if (ch === '}') {
        depth--;
        if (depth === 0) return code.slice(openIndex, i + 1);
      }
    }
    return null;
  }

  private fixFor(language: string, pattern: string): string {
    if (pattern.includes('InsecureSkipVerify')) {
      return 'Remove `InsecureSkipVerify: true` — let Go verify the cert. If ' +
        'you need to trust a private CA, set `RootCAs` to a `*x509.CertPool` ' +
        'containing that CA.';
    }
    if (pattern.includes('x509.Verify without intermediate denylist')) {
      return 'Before calling `x509.Certificate.Verify`, check the chain (including ' +
        'intermediates) against your blocked-CA / denylist policy. Relying on PKIX ' +
        'verification alone accepts chains that include revoked or blocked intermediates.';
    }
    if (pattern.includes('verify=False')) {
      return 'Remove `verify=False`. To trust a private CA, pass `verify=\'/path/to/ca.pem\'`.';
    }
    if (pattern.includes('rejectUnauthorized')) {
      return 'Remove `rejectUnauthorized: false`. To trust a private CA, set the ' +
        '`ca` option to the CA cert(s). Never disable TLS verification globally.';
    }
    if (pattern.includes('checkServerIdentity')) {
      return 'Implement `checkServerIdentity` to compare the certificate to the ' +
        'intended hostname (or remove the override). Returning `undefined` accepts ' +
        'the connection; loose host/IP folding before that check enables MITM.';
    }
    if (pattern.includes('NODE_TLS_REJECT_UNAUTHORIZED')) {
      return 'Remove the `NODE_TLS_REJECT_UNAUTHORIZED=0` assignment — it globally ' +
        'disables TLS verification for every outbound HTTPS request.';
    }
    if (language === 'java') {
      return 'Do not use an always-true HostnameVerifier or AllowAllHostnameVerifier. ' +
        'Use the JVM\'s default verifier; for self-signed certs add the cert to a ' +
        'custom TrustManager that validates the chain.';
    }
    if (pattern.includes('ssl._create_unverified_context')) {
      return 'Do not use `_create_unverified_context()`. Use `ssl.create_default_context()`.';
    }
    if (language === 'csharp') {
      return 'Do not accept every certificate. Remove the always-true validation ' +
        'callback (and `DangerousAcceptAnyServerCertificateValidator`); rely on the ' +
        'platform default. To trust a private CA, validate the chain against it in ' +
        'the callback instead of returning true.';
    }
    return 'Restore TLS certificate and hostname verification.';
  }
}
