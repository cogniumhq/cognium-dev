/**
 * `redos-regex-literal` (CWE-1333) — a request value matched against a regex
 * literal that can backtrack exponentially, on JavaScript / TypeScript.
 *
 * Fixtures in `tests/fixtures/redos-regex-literal/`:
 *   - vulnerable.ts  — every `// FLAG` line gives exactly one finding
 *   - fixed.ts       — the same handlers with linear regexes: zero
 *   - safe-shapes.ts — near misses (values not from the request, linear or
 *                      bounded patterns, nothing mandatory after the group): zero
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { analyze, initAnalyzer } from '../../../src/analyzer.js';
import {
  MAX_GROUP_DEPTH,
  MAX_SOURCE_LENGTH,
  isExponentialRegex,
  parseRegex,
  requestMemberBase,
  splitRegexLiteral,
  stripWrappers,
} from '../../../src/analysis/passes/redos-regex-literal-pass.js';

const FIXTURES = resolve(dirname(fileURLToPath(import.meta.url)), '../../fixtures/redos-regex-literal');
const fixture = (name: string) => readFileSync(resolve(FIXTURES, name), 'utf8');

type R = Awaited<ReturnType<typeof analyze>>;
const redos = (r: R) => (r.findings ?? []).filter(f => f.rule_id === 'redos-regex-literal');

describe('redos-regex-literal: the regex', () => {
  it.each([
    '^(a+)+$',
    '^(a*)*$',
    '^([a-zA-Z0-9]+)*@example\\.com$',
    '^([a-zA-Z0-9]+[-._]?)+@example\\.com$',
    '^(\\w+\\s?)*$',
    '^(([a-z])+,?)+;$',
    '^(\\d+)+-x$',
    '^((a+))+$',
    '^(?:[a-z]+|b)+$',
    '^(?<w>\\w+)+!',
    '(x+x?)+y',
    '^([^/]+/?)*\\.js$',
    '^(a+){2,}$',
  ])('%s is exponential', (src) => {
    expect(isExponentialRegex(src)).toBe(true);
  });

  it.each([
    '^[a-zA-Z0-9]+@example\\.com$',
    '^[a-zA-Z0-9]+(?:[-._][a-zA-Z0-9]+)*@example\\.com$',
    '^\\w+(?:\\s\\w+)*$',
    '^(\\d+,)*\\d+$',
    '^(ab+)+$',
    '(a+)+',
    '^(a{1,3}){1,4}$',
    '^((a+)\\2)+$',
    '^(?=(a+)+)b$',
    '^[(a+)+]$',
    '^\\(a+\\)+$',
    '^(\\w+\\b)+!$',
    '^(a|b)+$',
  ])('%s is not reported', (src) => {
    expect(isExponentialRegex(src)).toBe(false);
  });

  it('skips the v flag and unparsable sources', () => {
    expect(isExponentialRegex('^(a+)+$', 'v')).toBe(false);
    expect(parseRegex('(a')).toBeNull();
    expect(parseRegex('a)')).toBeNull();
    expect(parseRegex('[a')).toBeNull();
  });

  // `d` groups nested inside each other, each repeated: `((…(a+)+…)+)+$`.
  const nested = (d: number) => '('.repeat(d) + 'a+' + ')+'.repeat(d) + '$';

  it('abstains on 2000 nested groups instead of overflowing the stack', () => {
    expect(() => parseRegex(nested(2000))).not.toThrow();
    expect(parseRegex(nested(2000))).toBeNull();
    expect(() => isExponentialRegex(nested(2000))).not.toThrow();
    expect(isExponentialRegex(nested(2000))).toBe(false);
    expect(isExponentialRegex(nested(20000))).toBe(false);
  });

  it('nesting limit: MAX_GROUP_DEPTH groups parse, one more does not', () => {
    expect(MAX_GROUP_DEPTH).toBe(100);
    expect(parseRegex(nested(MAX_GROUP_DEPTH))).not.toBeNull();
    expect(isExponentialRegex(nested(MAX_GROUP_DEPTH))).toBe(true);
    expect(parseRegex(nested(MAX_GROUP_DEPTH + 1))).toBeNull();
    expect(isExponentialRegex(nested(MAX_GROUP_DEPTH + 1))).toBe(false);
    // Lookarounds count toward the depth.
    const inLookahead = '(?=' + nested(MAX_GROUP_DEPTH).slice(0, -1) + ')x';
    expect(parseRegex(inLookahead)).toBeNull();
  });

  it('length limit: MAX_SOURCE_LENGTH characters parse, one more does not', () => {
    expect(MAX_SOURCE_LENGTH).toBe(10_000);
    const at = 'b'.repeat(MAX_SOURCE_LENGTH - '(a+)+$'.length) + '(a+)+$';
    expect(at.length).toBe(MAX_SOURCE_LENGTH);
    expect(isExponentialRegex(at)).toBe(true);
    expect(parseRegex('b' + at)).toBeNull();
    expect(isExponentialRegex('b' + at)).toBe(false);
  });

  it('splits a regex literal', () => {
    expect(splitRegexLiteral('/^(a+)+$/iu')).toEqual({ source: '^(a+)+$', flags: 'iu' });
    expect(splitRegexLiteral('/[/]x/')).toEqual({ source: '[/]x', flags: '' });
    expect(splitRegexLiteral('a / b / c')).toBeNull();
    expect(splitRegexLiteral('/a/ + b / c')).toBeNull();
    expect(splitRegexLiteral('// comment')).toBeNull();
  });
});

describe('redos-regex-literal: the value', () => {
  it.each([
    ['req.query.q', 'req'],
    ["req.body['email']", 'req'],
    ['request.headers.host', 'request'],
    ['req.params.id as string', 'req'],
    ['String(req.query.q).trim()', 'req'],
    ["(req.query.q as string) || ''", 'req'],
    ['req.body', 'req'],
  ])('%s is a request value', (expr, base) => {
    expect(requestMemberBase(expr)).toBe(base);
  });

  it.each([
    'req.query', 'req.query.q.length', 'req.user.email', 'res.locals.q', 'reqs.query.q',
    'req.query.q.split(",")', 'foo(req.query.q)', 'req.query[q]',
  ])('%s is not', (expr) => {
    expect(requestMemberBase(expr)).toBeNull();
  });

  it('strips value-preserving wrappers', () => {
    expect(stripWrappers('String(req.query.q).toLowerCase()')).toBe('req.query.q');
    expect(stripWrappers('req.body.x!')).toBe('req.body.x');
  });
});

describe('redos-regex-literal: fixtures', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('vulnerable.ts: one finding per FLAG line, CWE-1333, medium', async () => {
    const code = fixture('vulnerable.ts');
    const expected = code.split('\n').flatMap((l, i) => (l.includes('// FLAG') ? [i + 1] : []));
    const found = redos(await analyze(code, 'vulnerable.ts', 'typescript'));
    expect(found.map(f => f.line).sort((a, b) => a - b)).toEqual(expected);
    for (const f of found) {
      expect(f.cwe).toBe('CWE-1333');
      expect(f.severity).toBe('medium');
      expect(f.category).toBe('security');
    }
  });

  it('fixed.ts: no finding', async () => {
    expect(redos(await analyze(fixture('fixed.ts'), 'fixed.ts', 'typescript'))).toEqual([]);
  });

  it('safe-shapes.ts: no finding', async () => {
    expect(redos(await analyze(fixture('safe-shapes.ts'), 'safe-shapes.ts', 'typescript'))).toEqual([]);
  });

  it('JavaScript: an Express handler', async () => {
    const code = [
      "const app = require('express')();",
      "app.get('/check', function checkEmail(req, res) {",
      '  const email = req.query.email;',
      '  const ok = /^([a-zA-Z0-9]+)*@example\\.com$/.test(email);',
      '  res.json({ ok });',
      '});',
    ].join('\n');
    expect(redos(await analyze(code, 'app.js', 'javascript')).map(f => f.line)).toEqual([4]);
  });

  it('a 2000-deep nested literal: no throw, no finding; a normal one beside it still fires', async () => {
    const deep = '('.repeat(2000) + 'a+' + ')+'.repeat(2000) + '$';
    const code = [
      "const app = require('express')();",
      "app.get('/x', function check(req, res) {",
      `  const deep = /${deep}/.test(req.query.q);`,
      '  const ok = /^(\\w+\\s?)*$/.test(req.query.name);',
      '  res.json({ deep, ok });',
      '});',
    ].join('\n');
    // Before the depth cap this call threw `RangeError: Maximum call stack size exceeded`.
    const r = await analyze(code, 'deep.js', 'javascript');
    expect(redos(r).map(f => f.line)).toEqual([4]);
  });

  it('other languages are not scanned', async () => {
    const code = 'import re\ndef f(request):\n    return re.match(r"^(a+)+$", request.args["q"])\n';
    expect(redos(await analyze(code, 'a.py', 'python'))).toEqual([]);
  });

  it('can be disabled', async () => {
    const r = await analyze(fixture('vulnerable.ts'), 'vulnerable.ts', 'typescript', { disabledPasses: ['redos-regex-literal'] } as never);
    expect(redos(r)).toEqual([]);
  });
});
