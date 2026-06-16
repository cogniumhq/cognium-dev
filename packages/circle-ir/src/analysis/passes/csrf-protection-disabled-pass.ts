/**
 * Pass: csrf-protection-disabled (CWE-352, category: security)
 *
 * Pattern pass — flags places where cross-site request forgery (CSRF)
 * protection is *explicitly disabled*. We do not attempt to detect the
 * absence of CSRF protection (false-positive prone across framework
 * idioms); instead we look for the documented "turn it off" calls.
 *
 * Detection per language:
 *   Java (Spring Security):
 *     - `http.csrf().disable()`
 *     - `http.csrf(csrf -> csrf.disable())`        — DSL form
 *     - `http.csrf(AbstractHttpConfigurer::disable)` — method-ref form
 *     - `.csrfTokenRepository(null)`               — neuters the repo
 *   Python (Django):
 *     - `@csrf_exempt` decorator on a view
 *     - `MIDDLEWARE = [...]` with `django.middleware.csrf.CsrfViewMiddleware`
 *       removed — we do NOT detect this (config-file analysis).
 *   JavaScript (Express):
 *     - We do NOT detect "csurf missing" — that's an absence check that
 *       fires on every non-Express handler.
 *
 * Severity: critical (CWE-352 is direct privilege escalation).
 * Issue: #86, Sprint 6.
 */

import type { AnalysisPass, PassContext } from '../../graph/analysis-pass.js';
import type { CallInfo } from '../../types/index.js';

// Match `.csrf().disable()` or `.csrf(<lambda>).disable(...)`.
const JAVA_CSRF_DISABLE_RE = /\.csrf\s*\([^)]*\)\s*\.\s*disable\b/;
// `csrf(csrf -> csrf.disable())` or `csrf(c -> c.disable())`.
const JAVA_CSRF_LAMBDA_DISABLE_RE =
  /\bcsrf\s*\(\s*\w+\s*->\s*\w+\s*\.\s*disable\s*\(/;
// Method-reference form: `csrf(AbstractHttpConfigurer::disable)`.
const JAVA_CSRF_METHODREF_RE = /\bcsrf\s*\(\s*[\w.]+::disable\s*\)/;
// `.csrfTokenRepository(null)`.
const JAVA_CSRF_NULL_REPO_RE = /\.csrfTokenRepository\s*\(\s*null\s*\)/;

interface Detection {
  pattern: string;
  api: string;
}

export interface CsrfProtectionDisabledResult {
  findings: Array<{
    line: number;
    language: string;
    pattern: string;
    api: string;
  }>;
}

export class CsrfProtectionDisabledPass
  implements AnalysisPass<CsrfProtectionDisabledResult>
{
  readonly name = 'csrf-protection-disabled';
  readonly category = 'security' as const;

  run(ctx: PassContext): CsrfProtectionDisabledResult {
    const { graph, language } = ctx;
    const file = graph.ir.meta.file;
    const findings: CsrfProtectionDisabledResult['findings'] = [];

    // 1. Call-based detection.
    for (const call of graph.ir.calls) {
      const detections = this.detectCall(call, language);
      for (const det of detections) {
        const line = call.location.line;
        findings.push({ line, language, ...det });
        ctx.addFinding({
          id: `${this.name}-${file}-${line}-${det.pattern}`,
          pass: this.name,
          category: this.category,
          rule_id: this.name,
          cwe: 'CWE-352',
          severity: 'critical',
          level: 'error',
          message:
            `CSRF protection explicitly disabled via \`${det.pattern}\` ` +
            `(${det.api}). Any browser session can be silently used to ` +
            'perform state-changing requests from a malicious origin.',
          file,
          line,
          fix: this.fixFor(language),
          evidence: { ...det, language },
        });
      }
    }

    // 2. Source-text detection for Java DSL chains that are emitted as a
    // single call expression (the `disable()` arrives as a method on a
    // chained receiver and not always as a discoverable separate CallInfo).
    if (language === 'java') {
      const src = ctx.code ?? '';
      if (src) {
        const lines = src.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = i + 1;
          const text = lines[i] ?? '';
          let det: Detection | null = null;
          if (JAVA_CSRF_LAMBDA_DISABLE_RE.test(text)) {
            det = { pattern: 'csrf(c -> c.disable())', api: 'HttpSecurity.csrf' };
          } else if (JAVA_CSRF_METHODREF_RE.test(text)) {
            det = { pattern: 'csrf(::disable)', api: 'HttpSecurity.csrf' };
          } else if (JAVA_CSRF_NULL_REPO_RE.test(text)) {
            det = { pattern: 'csrfTokenRepository(null)', api: 'HttpSecurity.csrfTokenRepository' };
          } else if (JAVA_CSRF_DISABLE_RE.test(text)) {
            det = { pattern: 'csrf().disable()', api: 'HttpSecurity.csrf' };
          }
          if (det && !findings.some((f) => f.line === line && f.pattern === det!.pattern)) {
            findings.push({ line, language, ...det });
            ctx.addFinding({
              id: `${this.name}-${file}-${line}-${det.pattern}`,
              pass: this.name,
              category: this.category,
              rule_id: this.name,
              cwe: 'CWE-352',
              severity: 'critical',
              level: 'error',
              message:
                `CSRF protection explicitly disabled via \`${det.pattern}\` ` +
                `(${det.api}). Any browser session can be silently used to ` +
                'perform state-changing requests from a malicious origin.',
              file,
              line,
              fix: this.fixFor(language),
              evidence: { ...det, language },
            });
          }
        }
      }
    }

    // 3. Python `@csrf_exempt` decorator — present on annotations / types.
    if (language === 'python') {
      const src = ctx.code ?? '';
      if (src) {
        const lines = src.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const text = lines[i] ?? '';
          if (/^\s*@csrf_exempt\b/.test(text)) {
            const line = i + 1;
            const det: Detection = { pattern: '@csrf_exempt', api: 'django.views.decorators.csrf' };
            findings.push({ line, language, ...det });
            ctx.addFinding({
              id: `${this.name}-${file}-${line}-${det.pattern}`,
              pass: this.name,
              category: this.category,
              rule_id: this.name,
              cwe: 'CWE-352',
              severity: 'critical',
              level: 'error',
              message:
                'Django view is decorated with `@csrf_exempt`, bypassing the ' +
                'framework CSRF middleware for this endpoint. Any browser ' +
                'session can be silently used to invoke this handler from ' +
                'a malicious origin.',
              file,
              line,
              fix: this.fixFor(language),
              evidence: { ...det, language },
            });
          }
        }
      }
    }

    return { findings };
  }

  private detectCall(call: CallInfo, language: string): Detection[] {
    const out: Detection[] = [];
    if (language !== 'java') return out;

    // Plain `csrf().disable()` chain — the IR may split this into two calls
    // (the outer .disable() with receiver "csrf()" or chained receiver).
    if (call.method_name === 'disable') {
      const recv = call.receiver ?? '';
      if (/\bcsrf\s*\(\s*\)\s*$/.test(recv) || recv.endsWith('.csrf()')) {
        out.push({ pattern: 'csrf().disable()', api: 'HttpSecurity.csrf' });
      }
    }

    if (call.method_name === 'csrfTokenRepository') {
      const arg = call.arguments.find((a) => a.position === 0);
      const expr = (arg?.expression ?? arg?.literal ?? '').trim();
      if (expr === 'null') {
        out.push({
          pattern: 'csrfTokenRepository(null)',
          api: 'HttpSecurity.csrfTokenRepository',
        });
      }
    }

    return out;
  }

  private fixFor(language: string): string {
    if (language === 'java') {
      return (
        'Leave Spring Security CSRF protection enabled. If you need to ' +
        'exempt a specific endpoint (e.g. webhook), use ' +
        '`.csrf(c -> c.ignoringRequestMatchers("/webhook"))` rather than ' +
        '`.disable()`. For stateless APIs, prefer a per-request token over ' +
        'disabling CSRF entirely.'
      );
    }
    if (language === 'python') {
      return (
        'Remove `@csrf_exempt`. For stateless API endpoints, use Django REST ' +
        'Framework with a token / session auth backend that does not rely on ' +
        'cookies. For webhook receivers, verify a shared-secret signature ' +
        'instead of disabling CSRF.'
      );
    }
    return 'Re-enable framework CSRF protection or replace with origin / token validation.';
  }
}
