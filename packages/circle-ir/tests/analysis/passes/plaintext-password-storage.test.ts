/**
 * Tests for plaintext-password-storage (CWE-256, category: security).
 *
 * The pass suppresses when the credential was hashed earlier in the SAME
 * method scope. That scoping is the interesting part: a hash in a different
 * method must not silence a plaintext write, or the rule can be defeated by
 * having hashed a password anywhere in the file.
 */
import { describe, it, expect } from 'vitest';
import { PlaintextPasswordStoragePass } from '../../../src/analysis/passes/plaintext-password-storage-pass.js';
import { makeIR, makeCtx, call } from './_pass-fixtures.js';

const run = (calls: ReturnType<typeof call>[], language = 'javascript') => {
  const ir = makeIR({
    meta: { circle_ir: '3.0', file: 'store.js', language, loc: 30, hash: '' },
    calls,
  });
  const ctx = makeCtx(ir, '', language);
  new PlaintextPasswordStoragePass().run(ctx);
  return ctx;
};

describe('PlaintextPasswordStoragePass', () => {
  it('flags fs.writeFileSync(path, password)', () => {
    const ctx = run([call('fs', 'writeFileSync', [['"/tmp/u"'], ['password', 'password']])]);
    expect(ctx.findings).toHaveLength(1);
    expect(ctx.findings[0].cwe).toBe('CWE-256');
    expect(ctx.findings[0].evidence?.identifier).toBe('password');
  });

  it('flags localStorage.setItem(key, password)', () => {
    const ctx = run([call('localStorage', 'setItem', [['"pw"'], ['password', 'password']])]);
    expect(ctx.findings).toHaveLength(1);
  });

  it('does not flag writing a non-credential value', () => {
    const ctx = run([call('fs', 'writeFileSync', [['"/tmp/u"'], ['username', 'username']])]);
    expect(ctx.findings).toHaveLength(0);
  });

  it('flags a Python file write of a password', () => {
    const ctx = run([call('f', 'write', [['password', 'password']])], 'python');
    expect(ctx.findings).toHaveLength(1);
  });

  describe('hash suppression', () => {
    it('suppresses when the credential was hashed earlier in the same method', () => {
      const ctx = run([
        call('bcrypt', 'hashSync', [['password', 'password'], ['12']], 3, 'saveUser'),
        call('fs', 'writeFileSync', [['"/tmp/u"'], ['password', 'password']], 5, 'saveUser'),
      ]);
      expect(ctx.findings).toHaveLength(0);
    });

    it('does NOT suppress when the hash is in a different method', () => {
      // Hashing a password in one function must not license writing it in
      // plaintext from another.
      const ctx = run([
        call('bcrypt', 'hashSync', [['password', 'password'], ['12']], 3, 'hashIt'),
        call('fs', 'writeFileSync', [['"/tmp/u"'], ['password', 'password']], 9, 'saveUser'),
      ]);
      expect(ctx.findings).toHaveLength(1);
      expect(ctx.findings[0].line).toBe(9);
    });

    it('does NOT suppress when the hash happens after the write', () => {
      const ctx = run([
        call('fs', 'writeFileSync', [['"/tmp/u"'], ['password', 'password']], 3, 'saveUser'),
        call('bcrypt', 'hashSync', [['password', 'password'], ['12']], 5, 'saveUser'),
      ]);
      expect(ctx.findings).toHaveLength(1);
    });

    it('suppresses an inline hash in the written expression', () => {
      const ctx = run([call('fs', 'writeFileSync', [['"/tmp/u"'], ['bcrypt.hashSync(password, 12)']])]);
      expect(ctx.findings).toHaveLength(0);
    });
  });
});
