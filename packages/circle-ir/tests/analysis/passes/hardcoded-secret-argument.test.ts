/**
 * `hardcoded-secret-argument` (CWE-798) — a string literal passed into the
 * credential position of a known JavaScript / TypeScript API.
 *
 * Fixtures in `tests/fixtures/hardcoded-secret-argument/`:
 *   - vulnerable.ts — every `// FLAG` line gives exactly one finding
 *   - fixed.ts      — the same code with secrets from the environment: zero
 *   - near-miss.ts  — non-secret literals, non-literal secrets, look-alike
 *                     helpers, placeholders: zero
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { analyze, initAnalyzer } from '../../../src/analyzer.js';
import { literalValues, propertyValue, stringLiteralValue } from '../../../src/analysis/passes/hardcoded-secret-argument-pass.js';

const FIXTURES = resolve(dirname(fileURLToPath(import.meta.url)), '../../fixtures/hardcoded-secret-argument');
const fixture = (name: string) => readFileSync(resolve(FIXTURES, name), 'utf8');

type R = Awaited<ReturnType<typeof analyze>>;
const credFindings = (r: R) => (r.findings ?? []).filter(f => f.rule_id === 'hardcoded-credential');

describe('hardcoded-secret-argument: literal shapes', () => {
  it.each([
    ["'abc'", 'abc'], ['"abc"', 'abc'], ['`abc`', 'abc'], ["'it\\'s'", "it\\'s"],
  ])('%s is the literal %s', (e, v) => {
    expect(stringLiteralValue(e)).toBe(v);
  });

  it.each(['`a${b}`', 'secret', 'process.env.X', "'a' + b", "'a'.trim()", "f('a')", "'a' as string"])('%s is not a literal', (e) => {
    expect(stringLiteralValue(e)).toBeNull();
  });

  it('arrays of literals count only where allowed and only when every element is a literal', () => {
    expect(literalValues("['a', 'b']", true)).toEqual(['a', 'b']);
    expect(literalValues("['a', k]", true)).toBeNull();
    expect(literalValues("['a']", false)).toBeNull();
  });

  it('reads nested object properties at top level only', () => {
    expect(propertyValue("{ host: 'h', password: 'pw' }", ['password'])).toBe("'pw'");
    expect(propertyValue("{ auth: { user: 'u', pass: 'p' } }", ['auth', 'pass'])).toBe("'p'");
    expect(propertyValue("{ 'password': 'pw' }", ['password'])).toBe("'pw'");
    expect(propertyValue("{ opts: f({ password: 'pw' }) }", ['password'])).toBeNull();
    expect(propertyValue('{ password }', ['password'])).toBeNull();
    expect(propertyValue("{\n  // rotate yearly\n  secret: 'k1',\n}", ['secret'])).toBe("'k1'");
  });
});

describe('hardcoded-secret-argument: fixtures', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('vulnerable.ts: one CWE-798 finding per FLAG line, high', async () => {
    const code = fixture('vulnerable.ts');
    const expected = code.split('\n').flatMap((l, i) => (l.includes('// FLAG') ? [i + 1] : []));
    const f = credFindings(await analyze(code, 'vulnerable.ts', 'typescript'));
    expect(f.map(x => x.line).sort((a, b) => a - b)).toEqual(expected);
    expect(expected.length).toBe(11);
    for (const x of f) {
      expect(x.cwe).toBe('CWE-798');
      expect(x.severity).toBe('high');
      expect(x.category).toBe('security');
    }
  });

  it('fixed.ts: no finding', async () => {
    expect(credFindings(await analyze(fixture('fixed.ts'), 'fixed.ts', 'typescript'))).toEqual([]);
  });

  it('near-miss.ts: no finding', async () => {
    expect(credFindings(await analyze(fixture('near-miss.ts'), 'near-miss.ts', 'typescript'))).toEqual([]);
  });

  it('JavaScript with require() is covered too', async () => {
    const code = [
      "const jwt = require('jsonwebtoken');",
      "const { Pool } = require('pg');",
      "function sign(u) { return jwt.sign({ u }, 'Zk3-signing'); }",
      "const pool = new Pool({ password: 'pg-pass-1' });",
      'module.exports = { sign, pool };',
    ].join('\n');
    const f = credFindings(await analyze(code, 'src/a.js', 'javascript'));
    expect(f.map(x => x.line)).toEqual([3, 4]);
  });

  it('an unbound name is not the library', async () => {
    const code = "function session(o) { return o; }\nsession({ secret: 'Zk3-signing-key' });\n";
    expect(credFindings(await analyze(code, 'src/a.js', 'javascript'))).toEqual([]);
  });

  it('test files are skipped', async () => {
    const code = "const jwt = require('jsonwebtoken');\njwt.sign({}, 'Zk3-signing');\n";
    expect(credFindings(await analyze(code, 'src/__tests__/a.test.js', 'javascript'))).toEqual([]);
  });

  it('other languages are out of scope', async () => {
    const code = "import jwt\njwt.encode({}, 'Zk3', algorithm='HS256')\n";
    expect((await analyze(code, 'a.py', 'python')).findings?.filter(f => f.pass === 'hardcoded-secret-argument') ?? []).toEqual([]);
  });

  it('can be disabled', async () => {
    const r = await analyze(fixture('vulnerable.ts'), 'vulnerable.ts', 'typescript', {
      disabledPasses: ['hardcoded-secret-argument'],
    } as never);
    expect(credFindings(r).filter(f => f.pass === 'hardcoded-secret-argument')).toEqual([]);
  });
});
