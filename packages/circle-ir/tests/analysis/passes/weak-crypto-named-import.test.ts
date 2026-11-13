/**
 * weak-hash (CWE-328) / weak-crypto (CWE-327) on Node `crypto` APIs reached
 * through a named import, an aliased import, a destructured require, a module
 * alias or an inline require — not only the receiver text `crypto`.
 *
 * Fixtures in `tests/fixtures/weak-crypto-named-import/`:
 *   - vulnerable.ts — every `// FLAG` line gives exactly one finding
 *   - fixed.ts      — the same functions with strong algorithms: zero
 *   - near-miss.ts  — the same names bound to other modules or local
 *                     functions: zero
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { analyze, initAnalyzer } from '../../../src/analyzer.js';
import { jsCryptoBindings, cryptoCallAsMember } from '../../../src/analysis/passes/_js-crypto-binding.js';
import type { CallInfo, ImportInfo } from '../../../src/types/index.js';

const FIXTURES = resolve(dirname(fileURLToPath(import.meta.url)), '../../fixtures/weak-crypto-named-import');
const fixture = (name: string) => readFileSync(resolve(FIXTURES, name), 'utf8');

type R = Awaited<ReturnType<typeof analyze>>;
const RULES = new Set(['weak-hash', 'weak-crypto']);
const cryptoFindings = (r: R) => (r.findings ?? []).filter(f => RULES.has(f.rule_id));

const imp = (imported_name: string, from_package: string, alias: string | null = null, is_wildcard = false): ImportInfo =>
  ({ imported_name, from_package, alias, is_wildcard, line_number: 1 });
const call = (method_name: string, receiver: string | null): CallInfo =>
  ({ method_name, receiver, arguments: [], location: { line: 1, column: 0 } } as unknown as CallInfo);

describe('weak-crypto-named-import: bindings', () => {
  const b = jsCryptoBindings([
    imp('createHash', 'crypto'),
    imp('createCipheriv', 'node:crypto', 'cipherWith'),
    imp('*', 'crypto', 'nodeCrypto', true),
    imp('default', 'node:crypto', 'cryptoLib'),
    imp('createHmac', './hmac-shim'),
    imp('*', 'hash-wasm', 'hashing', true),
  ]);

  it.each([
    [call('createHash', null), 'createHash'],
    [call('cipherWith', null), 'createCipheriv'],
    [call('createHash', 'nodeCrypto'), 'createHash'],
    [call('createCipher', 'cryptoLib'), 'createCipher'],
    [call('createHash', "require('crypto')"), 'createHash'],
    [call('createHash', 'require("node:crypto")'), 'createHash'],
  ])('%o resolves to crypto.%s', (c, api) => {
    const out = cryptoCallAsMember(c, b);
    expect(out.receiver).toBe('crypto');
    expect(out.method_name).toBe(api);
  });

  it.each([
    call('createHmac', null),
    call('createHash', 'hashing'),
    call('createCipheriv', null),
    call('createHash', "require('./crypto')"),
    call('createHash', 'this.crypto'),
  ])('%o is left alone', (c) => {
    expect(cryptoCallAsMember(c, b)).toBe(c);
  });
});

describe('weak-crypto-named-import: fixtures', () => {
  let vulnerable: R;
  let fixed: R;
  let nearMiss: R;

  beforeAll(async () => {
    await initAnalyzer();
    vulnerable = await analyze(fixture('vulnerable.ts'), 'src/crypto-util.ts', 'typescript');
    fixed = await analyze(fixture('fixed.ts'), 'src/crypto-util.ts', 'typescript');
    nearMiss = await analyze(fixture('near-miss.ts'), 'src/crypto-util.ts', 'typescript');
  });

  it('vulnerable: one finding on every FLAG line, none elsewhere', () => {
    const lines = fixture('vulnerable.ts').split('\n');
    const expected = lines.flatMap((l, i) => (l.includes('// FLAG') ? [i + 1] : []));
    const got = cryptoFindings(vulnerable).map(f => f.line).sort((a, b) => a - b);
    expect(got).toEqual(expected);
  });

  it('vulnerable: rule and CWE per line', () => {
    const lines = fixture('vulnerable.ts').split('\n');
    for (const f of cryptoFindings(vulnerable)) {
      const rule = /\/\/ FLAG (\S+)/.exec(lines[f.line - 1])![1];
      expect(f.rule_id).toBe(rule);
      expect(f.cwe).toBe(rule === 'weak-hash' ? 'CWE-328' : 'CWE-327');
    }
  });

  it('fixed: zero', () => {
    expect(cryptoFindings(fixed)).toEqual([]);
  });

  it('near-miss: zero', () => {
    expect(cryptoFindings(nearMiss)).toEqual([]);
  });

  it('JavaScript: the same shapes are reported', async () => {
    const js = await analyze(
      "const { createHash } = require('crypto');\nfunction h(x) { return createHash('md5').update(x).digest('hex'); }\nmodule.exports = { h };\n",
      'src/h.js', 'javascript');
    expect(cryptoFindings(js).map(f => [f.line, f.rule_id])).toEqual([[2, 'weak-hash']]);
  });

  it('weak-password-hash: low PBKDF2 iterations through a named import', async () => {
    const src = "import { pbkdf2Sync } from 'node:crypto';\nexport function derive(pw: string, salt: Buffer) { return pbkdf2Sync(pw, salt, 1000, 32, 'sha256'); }\n";
    const r = await analyze(src, 'src/kdf.ts', 'typescript');
    expect((r.findings ?? []).filter(f => f.rule_id === 'weak-password-hash').map(f => f.line)).toEqual([2]);
    const local = await analyze(src.replace("from 'node:crypto'", "from './kdf-shim'"), 'src/kdf.ts', 'typescript');
    expect((local.findings ?? []).filter(f => f.rule_id === 'weak-password-hash')).toEqual([]);
  });
});
