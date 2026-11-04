/**
 * cognium-dev#1129 — Nest decoratorPath with declarationDetail.
 */
import { describe, expect, it } from 'vitest';
import { analyze } from '../../src/analyzer.js';
import { decoratorPath } from '../../src/core/extractors/ts-declaration-detail.js';

function dec(name: string, args: { text: string; value?: string }[] | undefined) {
  return args === undefined ? undefined : { name, arguments: args };
}

describe('cognium-dev#1129 — decoratorPath', () => {
  it('returns empty string when the decorator has no path argument', () => {
    expect(decoratorPath(dec('Get', []))).toBe('');
  });

  it('returns the literal for @Get("z")', () => {
    expect(decoratorPath(dec('Get', [{ text: "'z'", value: 'z' }]))).toBe('z');
  });

  it('returns undefined for array route args @Get(["a","b"])', () => {
    expect(decoratorPath(dec('Get', [{ text: "['a','b']" }]))).toBeUndefined();
  });

  it('returns undefined for template literal paths', () => {
    expect(decoratorPath(dec('Get', [{ text: '`tmpl`' }]))).toBeUndefined();
  });

  it('extracts path from @Controller({ path: "dogs" })', () => {
    expect(decoratorPath(dec('Controller', [{ text: "{ path: 'dogs' }" }]))).toBe('dogs');
  });

  it('returns undefined for @Controller(CONST) and unresolved object path', async () => {
    const code = `
const CONST = 'api';
import { Controller, Get } from '@nestjs/common';
@Controller(CONST)
class C {
  @Get('z')
  m() {}
}
@Controller({ path: CONST })
class D {
  @Get('w')
  n() {}
}
`;
    const ir = await analyze(code, 'nest.ts', 'typescript', { declarationDetail: true });
    const c = ir.types.find(t => t.name === 'C');
    const d = ir.types.find(t => t.name === 'D');
    expect(decoratorPath(c?.decorators?.find(x => x.name === 'Controller'))).toBeUndefined();
    expect(decoratorPath(d?.decorators?.find(x => x.name === 'Controller'))).toBeUndefined();
    const getZ = c?.methods.find(m => m.name === 'm')?.decorators?.find(x => x.name === 'Get');
    expect(decoratorPath(getZ)).toBe('z');
  });
});
