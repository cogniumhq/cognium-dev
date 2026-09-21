/**
 * Tests for weak-password-hash (CWE-916, category: security).
 *
 * The distinction this pass exists to draw: SHA-256 is a fine digest and a
 * bad password hash, and bcrypt is a fine password hash at the wrong cost.
 * So the boundary cases (cost exactly at the threshold, non-credential
 * argument) are the point — flagging every sha256 call would be the failure.
 */
import { describe, it, expect } from 'vitest';
import { WeakPasswordHashPass } from '../../../src/analysis/passes/weak-password-hash-pass.js';
import { makeIR, makeCtx, call } from './_pass-fixtures.js';

const run = (calls: ReturnType<typeof call>[], language = 'python') => {
  const ir = makeIR({
    meta: { circle_ir: '3.0', file: 'auth.py', language, loc: 20, hash: '' },
    calls,
  });
  const ctx = makeCtx(ir, '', language);
  new WeakPasswordHashPass().run(ctx);
  return ctx;
};

describe('WeakPasswordHashPass', () => {
  describe('fast unsalted hash of a credential', () => {
    it('flags hashlib.sha256(password)', () => {
      const ctx = run([call('hashlib', 'sha256', [['password', 'password']])]);
      expect(ctx.findings).toHaveLength(1);
      expect(ctx.findings[0].cwe).toBe('CWE-916');
      expect(ctx.findings[0].severity).toBe('high');
    });

    it('does not flag hashlib.sha256 of a non-credential value', () => {
      // The same algorithm over file bytes is a correct digest, not a finding.
      const ctx = run([call('hashlib', 'sha256', [['file_bytes', 'file_bytes']])]);
      expect(ctx.findings).toHaveLength(0);
    });
  });

  describe('bcrypt cost threshold (min 10)', () => {
    it('flags bcrypt.gensalt(rounds=4)', () => {
      const ctx = run([call('bcrypt', 'gensalt', [['rounds=4']])]);
      expect(ctx.findings).toHaveLength(1);
      expect(ctx.findings[0].evidence?.kind).toBe('low-bcrypt-cost');
    });

    it('does not flag rounds exactly at the threshold', () => {
      const ctx = run([call('bcrypt', 'gensalt', [['rounds=10']])]);
      expect(ctx.findings).toHaveLength(0);
    });

    it('does not flag rounds above the threshold', () => {
      const ctx = run([call('bcrypt', 'gensalt', [['rounds=12']])]);
      expect(ctx.findings).toHaveLength(0);
    });

    it('flags bcrypt.hashSync(pw, 4) in JS', () => {
      const ctx = run([call('bcrypt', 'hashSync', [['pw', 'pw'], ['4']])], 'javascript');
      expect(ctx.findings).toHaveLength(1);
    });

    it('flags Go bcrypt.MinCost by name, not only by number', () => {
      const ctx = run([call('bcrypt', 'GenerateFromPassword', [['pw', 'pw'], ['bcrypt.MinCost']])], 'go');
      expect(ctx.findings).toHaveLength(1);
    });

    it('does not flag Go bcrypt.DefaultCost', () => {
      const ctx = run([call('bcrypt', 'GenerateFromPassword', [['pw', 'pw'], ['bcrypt.DefaultCost']])], 'go');
      expect(ctx.findings).toHaveLength(0);
    });
  });

  describe('PBKDF2 iteration threshold (min 100k)', () => {
    it('flags PBKDF2HMAC(iterations=1000)', () => {
      const ctx = run([call(null, 'PBKDF2HMAC', [['iterations=1000']])]);
      expect(ctx.findings).toHaveLength(1);
      expect(ctx.findings[0].evidence?.kind).toBe('low-pbkdf2-iterations');
    });

    it('does not flag iterations exactly at the threshold', () => {
      const ctx = run([call(null, 'PBKDF2HMAC', [['iterations=100000']])]);
      expect(ctx.findings).toHaveLength(0);
    });

    it('flags crypto.pbkdf2Sync with too few iterations in JS', () => {
      const ctx = run([call('crypto', 'pbkdf2Sync', [['pw', 'pw'], ['salt', 'salt'], ['1000']])], 'javascript');
      expect(ctx.findings).toHaveLength(1);
    });

    it('does not flag crypto.pbkdf2Sync at 600000 iterations', () => {
      const ctx = run([call('crypto', 'pbkdf2Sync', [['pw', 'pw'], ['salt', 'salt'], ['600000']])], 'javascript');
      expect(ctx.findings).toHaveLength(0);
    });
  });
});
