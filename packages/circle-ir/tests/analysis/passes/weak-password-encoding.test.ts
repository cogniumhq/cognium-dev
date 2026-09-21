/**
 * Tests for weak-password-encoding (CWE-261, category: security).
 *
 * Encoding is not encryption: base64 of a password buys nothing. The one
 * legitimate use is HTTP Basic auth, where base64 IS the wire format — so
 * the "Basic " guard is the case worth pinning, since without it this rule
 * would fire on every conforming Basic auth client.
 */
import { describe, it, expect } from 'vitest';
import { WeakPasswordEncodingPass } from '../../../src/analysis/passes/weak-password-encoding-pass.js';
import { makeIR, makeCtx, call } from './_pass-fixtures.js';

const run = (calls: ReturnType<typeof call>[], language = 'python', code = '') => {
  const ir = makeIR({
    meta: { circle_ir: '3.0', file: 'enc.py', language, loc: 20, hash: '' },
    calls,
  });
  const ctx = makeCtx(ir, code, language);
  new WeakPasswordEncodingPass().run(ctx);
  return ctx;
};

describe('WeakPasswordEncodingPass', () => {
  it('flags base64.b64encode(password) in Python', () => {
    const ctx = run([call('base64', 'b64encode', [['password', 'password']])]);
    expect(ctx.findings).toHaveLength(1);
    expect(ctx.findings[0].cwe).toBe('CWE-261');
    expect(ctx.findings[0].severity).toBe('medium');
  });

  it('flags binascii.hexlify(password)', () => {
    const ctx = run([call('binascii', 'hexlify', [['password', 'password']])]);
    expect(ctx.findings).toHaveLength(1);
  });

  it('does not flag encoding a non-credential value', () => {
    const ctx = run([call('base64', 'b64encode', [['image_bytes', 'image_bytes']])]);
    expect(ctx.findings).toHaveLength(0);
  });

  it('flags btoa(password) in JS', () => {
    const ctx = run([call('', 'btoa', [['password', 'password']])], 'javascript');
    expect(ctx.findings).toHaveLength(1);
  });

  it('flags Go base64.StdEncoding.EncodeToString on a credential', () => {
    const ctx = run([call('base64.StdEncoding', 'EncodeToString', [['passwordBytes', 'passwordBytes']])], 'go');
    expect(ctx.findings).toHaveLength(1);
  });

  describe('HTTP Basic auth guard', () => {
    it('does not flag base64 used to build a Basic auth header', () => {
      // Line 3 is the call; the guard scans a small window around it.
      const code = [
        'def client():',
        '    creds = user + ":" + password',
        '    token = base64.b64encode(password)',
        '    headers = {"Authorization": "Basic " + token}',
      ].join('\n');
      const ctx = run([call('base64', 'b64encode', [['password', 'password']], 3)], 'python', code);
      expect(ctx.findings).toHaveLength(0);
    });

    it('still flags base64 when no Basic header is nearby', () => {
      const code = [
        'def store():',
        '    blob = "x"',
        '    token = base64.b64encode(password)',
        '    save(token)',
      ].join('\n');
      const ctx = run([call('base64', 'b64encode', [['password', 'password']], 3)], 'python', code);
      expect(ctx.findings).toHaveLength(1);
    });
  });
});
