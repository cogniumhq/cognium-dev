/**
 * Tests for cleartext-credential-transport (CWE-523, category: security).
 *
 * The pass fires when a credential-named value is sent to an `http://` URL.
 * Both halves matter: an http:// URL alone is not a finding, and a credential
 * over https:// is not either — so the negative cases here are what stop it
 * degrading into "flags every plaintext URL".
 */
import { describe, it, expect } from 'vitest';
import { CleartextCredentialTransportPass } from '../../../src/analysis/passes/cleartext-credential-transport-pass.js';
import { makeIR, makeCtx, call } from './_pass-fixtures.js';

const run = (calls: ReturnType<typeof call>[], language = 'python') => {
  const ir = makeIR({
    meta: { circle_ir: '3.0', file: 'app.py', language, loc: 20, hash: '' },
    calls,
  });
  const ctx = makeCtx(ir, '', language);
  new CleartextCredentialTransportPass().run(ctx);
  return ctx;
};

describe('CleartextCredentialTransportPass', () => {
  describe('Python', () => {
    it('flags requests.post to http:// carrying a password', () => {
      const ctx = run([call('requests', 'post', [['"http://api.example.com/login"'], ['password', 'password']])]);
      expect(ctx.findings).toHaveLength(1);
      expect(ctx.findings[0].rule_id).toBe('cleartext-credential-transport');
      expect(ctx.findings[0].cwe).toBe('CWE-523');
      expect(ctx.findings[0].severity).toBe('high');
      expect(ctx.findings[0].line).toBe(10);
    });

    it('does not flag the same call over https', () => {
      const ctx = run([call('requests', 'post', [['"https://api.example.com/login"'], ['password', 'password']])]);
      expect(ctx.findings).toHaveLength(0);
    });

    it('does not flag http when no argument carries a credential', () => {
      const ctx = run([call('requests', 'post', [['"http://api.example.com/items"'], ['payload', 'payload']])]);
      expect(ctx.findings).toHaveLength(0);
    });

    it('flags httpx as well as requests', () => {
      const ctx = run([call('httpx', 'put', [['"http://api.example.com/u"'], ['api_key', 'api_key']])]);
      expect(ctx.findings).toHaveLength(1);
    });

    it('flags an inline dict carrying a credential key', () => {
      const ctx = run([call('requests', 'post', [['"http://api.example.com/login"'], ['{"password": pw}']])]);
      expect(ctx.findings).toHaveLength(1);
    });
  });

  describe('localhost allowlist', () => {
    // Dev loopback traffic never leaves the host, so it is deliberately exempt.
    it.each(['http://localhost:8080/login', 'http://127.0.0.1/login', 'http://0.0.0.0:3000/login'])(
      'does not flag %s',
      (url) => {
        const ctx = run([call('requests', 'post', [[`"${url}"`], ['password', 'password']])]);
        expect(ctx.findings).toHaveLength(0);
      },
    );

    it('still flags a host that merely starts with the word localhost', () => {
      // `localhost.evil.com` is a real remote host; the allowlist is anchored.
      const ctx = run([call('requests', 'post', [['"http://localhost.evil.com/login"'], ['password', 'password']])]);
      expect(ctx.findings).toHaveLength(1);
    });
  });

  it('reports one finding per offending call', () => {
    const ctx = run([
      call('requests', 'post', [['"http://a.example.com/l"'], ['password', 'password']], 3),
      call('requests', 'post', [['"http://b.example.com/l"'], ['secret', 'secret']], 7),
    ]);
    expect(ctx.findings).toHaveLength(2);
    expect(ctx.findings.map(f => f.line)).toEqual([3, 7]);
  });
});
