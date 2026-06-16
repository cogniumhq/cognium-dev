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
 *   Python:
 *     - `requests.get|post|put|delete|patch|head|options|request(..., verify=False)`
 *     - `ssl._create_unverified_context()` / `ssl._create_default_https_context = ssl._create_unverified_context`
 *     - `urllib3.disable_warnings(InsecureRequestWarning)` — best-effort hint
 *     - `httpx.Client(verify=False)` / `httpx.get(..., verify=False)`
 *   JavaScript / TypeScript:
 *     - `{ rejectUnauthorized: false }` in https.request / fetch options /
 *       node-fetch / axios — text scan on arg expressions
 *     - `https.Agent({ rejectUnauthorized: false })`
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
const HOSTNAME_LAMBDA_TRUE_RE = /\(\s*\w+\s*,\s*\w+\s*\)\s*->\s*true\b/;
const ALLOW_ALL_HOSTNAME_VERIFIERS = new Set([
  'NoopHostnameVerifier.INSTANCE',
  'new AllowAllHostnameVerifier()',
  'new NoopHostnameVerifier()',
]);

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
      }
    }

    return out;
  }

  private fixFor(language: string, pattern: string): string {
    if (pattern.includes('InsecureSkipVerify')) {
      return 'Remove `InsecureSkipVerify: true` — let Go verify the cert. If ' +
        'you need to trust a private CA, set `RootCAs` to a `*x509.CertPool` ' +
        'containing that CA.';
    }
    if (pattern.includes('verify=False')) {
      return 'Remove `verify=False`. To trust a private CA, pass `verify=\'/path/to/ca.pem\'`.';
    }
    if (pattern.includes('rejectUnauthorized')) {
      return 'Remove `rejectUnauthorized: false`. To trust a private CA, set the ' +
        '`ca` option to the CA cert(s). Never disable TLS verification globally.';
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
    return 'Restore TLS certificate and hostname verification.';
  }
}
