/**
 * Tests for csrf-protection-disabled (CWE-352, category: security).
 *
 * The pass deliberately detects only EXPLICIT disabling, never the absence
 * of CSRF protection — an absence check fires on every handler that is not
 * a form POST. The negative cases here are what keep that boundary honest.
 */
import { describe, it, expect } from 'vitest';
import { CsrfProtectionDisabledPass } from '../../../src/analysis/passes/csrf-protection-disabled-pass.js';
import { makeIR, makeCtx } from './_pass-fixtures.js';

const run = (code: string, language: string) => {
  const file = language === 'java' ? 'Security.java' : 'views.py';
  const ir = makeIR({
    meta: { circle_ir: '3.0', file, language, loc: code.split('\n').length, hash: '' },
  });
  const ctx = makeCtx(ir, code, language);
  new CsrfProtectionDisabledPass().run(ctx);
  return ctx;
};

describe('CsrfProtectionDisabledPass', () => {
  describe('Java / Spring Security', () => {
    it('flags the chained http.csrf().disable() form', () => {
      const ctx = run('protected void configure(HttpSecurity http) {\n  http.csrf().disable();\n}', 'java');
      expect(ctx.findings).toHaveLength(1);
      expect(ctx.findings[0].cwe).toBe('CWE-352');
      expect(ctx.findings[0].severity).toBe('critical');
      expect(ctx.findings[0].line).toBe(2);
    });

    it('flags the lambda DSL form', () => {
      const ctx = run('http.csrf(csrf -> csrf.disable());', 'java');
      expect(ctx.findings).toHaveLength(1);
    });

    it('flags the method-reference form', () => {
      const ctx = run('http.csrf(AbstractHttpConfigurer::disable);', 'java');
      expect(ctx.findings).toHaveLength(1);
    });

    it('flags a null csrfTokenRepository, which neuters the repo', () => {
      const ctx = run('http.csrf().csrfTokenRepository(null);', 'java');
      expect(ctx.findings.length).toBeGreaterThanOrEqual(1);
    });

    it('does not flag CSRF configured but left enabled', () => {
      const ctx = run('http.csrf(csrf -> csrf.csrfTokenRepository(repo));', 'java');
      expect(ctx.findings).toHaveLength(0);
    });

    it('does not flag an unrelated disable() call', () => {
      // `.cors().disable()` is a different control entirely.
      const ctx = run('http.cors().disable();', 'java');
      expect(ctx.findings).toHaveLength(0);
    });
  });

  describe('Python / Django', () => {
    it('flags the @csrf_exempt decorator', () => {
      const ctx = run('@csrf_exempt\ndef transfer(request):\n    pass', 'python');
      expect(ctx.findings).toHaveLength(1);
      expect(ctx.findings[0].line).toBe(1);
    });

    it('does not flag a view with no exemption', () => {
      const ctx = run('@login_required\ndef transfer(request):\n    pass', 'python');
      expect(ctx.findings).toHaveLength(0);
    });
  });

  it('does not attempt absence-detection on Express handlers', () => {
    const ctx = run("app.post('/transfer', (req, res) => { transfer(req.body); });", 'javascript');
    expect(ctx.findings).toHaveLength(0);
  });
});
