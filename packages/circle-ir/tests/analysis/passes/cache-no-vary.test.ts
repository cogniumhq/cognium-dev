/**
 * Tests for cache-no-vary (CWE-524, category: security).
 *
 * The rule is a three-way AND: shared-cacheable Cache-Control, an auth/session
 * read, and no covering Vary. Each of the three negatives below removes one
 * leg — without them this would fire on every `Cache-Control: public`, which
 * is ordinary and correct on static assets.
 */
import { describe, it, expect } from 'vitest';
import { CacheNoVaryPass } from '../../../src/analysis/passes/cache-no-vary-pass.js';
import { makeIR, makeCtx, call } from './_pass-fixtures.js';

const HANDLER = 'getProfile';

const run = (
  code: string,
  calls: ReturnType<typeof call>[],
  language = 'javascript',
  file = 'routes.js',
) => {
  const ir = makeIR({
    meta: { circle_ir: '3.0', file, language, loc: code.split('\n').length, hash: '' },
    calls,
  });
  const ctx = makeCtx(ir, code, language);
  new CacheNoVaryPass().run(ctx);
  return ctx;
};

// A handler that reads a cookie (auth leg) and sets a public cache header.
const leakyCode = [
  'function getProfile(req, res) {',
  '  const uid = req.cookies.uid;',
  "  res.setHeader('Cache-Control', 'public, max-age=600');",
  '  res.json(load(uid));',
  '}',
].join('\n');

const cacheCall = (line = 3) =>
  call('res', 'setHeader', [["'Cache-Control'"], ["'public, max-age=600'"]], line, HANDLER);

describe('CacheNoVaryPass', () => {
  it('flags a public-cached handler that reads a cookie and sets no Vary', () => {
    const ctx = run(leakyCode, [cacheCall()]);
    expect(ctx.findings).toHaveLength(1);
    expect(ctx.findings[0].cwe).toBe('CWE-524');
    expect(ctx.findings[0].severity).toBe('medium');
  });

  it('does not flag when a covering Vary is set', () => {
    const code = leakyCode.replace(
      "  res.json(load(uid));",
      "  res.setHeader('Vary', 'Cookie');\n  res.json(load(uid));",
    );
    const ctx = run(code, [
      cacheCall(),
      call('res', 'setHeader', [["'Vary'"], ["'Cookie'"]], 4, HANDLER),
    ]);
    expect(ctx.findings).toHaveLength(0);
  });

  it('does not flag a public cache with no auth or session read', () => {
    // Static asset handler — public caching here is correct.
    const code = [
      'function getLogo(req, res) {',
      "  res.setHeader('Cache-Control', 'public, max-age=600');",
      '  res.sendFile(LOGO);',
      '}',
    ].join('\n');
    const ctx = run(code, [
      call('res', 'setHeader', [["'Cache-Control'"], ["'public, max-age=600'"]], 2, 'getLogo'),
    ]);
    expect(ctx.findings).toHaveLength(0);
  });

  describe('non-shared-cacheable directives', () => {
    it.each(['private, max-age=600', 'no-store', 'no-cache', 'max-age=0'])(
      'does not flag Cache-Control: %s',
      (value) => {
        const code = leakyCode.replace('public, max-age=600', value);
        const ctx = run(code, [
          call('res', 'setHeader', [["'Cache-Control'"], [`'${value}'`]], 3, HANDLER),
        ]);
        expect(ctx.findings).toHaveLength(0);
      },
    );
  });

  // NOTE: documents CURRENT behaviour, which contradicts this pass's own
  // header comment ("Skips: ... `max-age=0` (effectively non-cacheable)").
  // `isSharedCacheable` returns `pub || positiveMax`, so an explicit `public`
  // wins regardless of max-age. Arguably the code is right and the comment is
  // wrong — a shared cache may still store a `public, max-age=0` response and
  // replay one user's body to another after a 304 revalidation — but the two
  // disagree, so this test pins the behaviour rather than the intent. See the
  // note on #439.
  it('flags `public, max-age=0` despite the header comment claiming otherwise', () => {
    const code = leakyCode.replace('public, max-age=600', 'public, max-age=0');
    const ctx = run(code, [
      call('res', 'setHeader', [["'Cache-Control'"], ["'public, max-age=0'"]], 3, HANDLER),
    ]);
    expect(ctx.findings).toHaveLength(1);
  });

  it('skips test files entirely', () => {
    const ctx = run(leakyCode, [cacheCall()], 'javascript', 'routes.test.js');
    expect(ctx.findings).toHaveLength(0);
  });

  it('skips unsupported languages', () => {
    const ctx = run(leakyCode, [cacheCall()], 'rust', 'main.rs');
    expect(ctx.findings).toHaveLength(0);
  });

  it('emits at most one finding per handler', () => {
    const ctx = run(leakyCode, [cacheCall(3), cacheCall(4)]);
    expect(ctx.findings).toHaveLength(1);
  });
});
