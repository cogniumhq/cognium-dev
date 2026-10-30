/**
 * `AnalyzerOptions.declarationDetail`: TypeScript export and access
 * modifiers, return types, decorators with arguments, and `ir.exports`
 * limited to what is exported. Off by default, and the default is unchanged.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

beforeAll(async () => {
  await initAnalyzer();
});

const CATS = [
  "import { Controller, Get, Param, Injectable } from '@nestjs/common';",
  '',
  '@Injectable()',
  'export class CatsService {',
  '  private readonly cats: Cat[] = [];',
  '  protected count: number = 0;',
  '  #secret = 1;',
  '  findAll(): Cat[] { return this.cats; }',
  '  private helper(): void {}',
  '}',
  '',
  "@Controller('cats')",
  'export class CatsController {',
  '  constructor(private readonly svc: CatsService) {}',
  "  @Get(':id')",
  "  async findOne(@Param('id') id: string): Promise<Cat> { return this.svc.findAll()[0]; }",
  '}',
  '',
  'abstract class Base { abstract run(): void; }',
  'export interface Cat { name: string; }',
  'export function make(n: string): Cat { return { name: n }; }',
  'function internal() {}',
  'export const arrow = (x: number): number => x;',
  'const hidden = () => 1;',
  'export { internal as renamed };',
  'export default hidden;',
].join('\n');

describe('declarationDetail', () => {
  it('carries export and access modifiers, return types and decorators with arguments', async () => {
    const ir = await analyze(CATS, 'src/cats.ts', 'typescript', { declarationDetail: true });
    const type = (n: string) => ir.types.find(t => t.name === n);
    expect(type('CatsService')?.modifiers).toEqual(['export']);
    expect(type('CatsService')?.decorators).toEqual([{ name: 'Injectable', arguments: [] }]);
    expect(type('CatsController')?.decorators).toEqual([{ name: 'Controller', arguments: [{ text: "'cats'", value: 'cats' }] }]);
    expect(type('Cat')?.modifiers).toEqual(['export']);
    const svc = type('CatsService');
    expect(svc?.fields.find(f => f.name === 'cats')).toMatchObject({ type: 'Cat[]', modifiers: ['private', 'readonly'] });
    expect(svc?.fields.find(f => f.name === 'count')?.modifiers).toEqual(['protected']);
    expect(svc?.methods.find(m => m.name === 'findAll')?.return_type).toBe('Cat[]');
    expect(svc?.methods.find(m => m.name === 'helper')?.modifiers).toContain('private');
    const findOne = type('CatsController')?.methods.find(m => m.name === 'findOne');
    expect(findOne?.decorators).toEqual([{ name: 'Get', arguments: [{ text: "':id'", value: ':id' }] }]);
    expect(findOne?.return_type).toBe('Promise<Cat>');
    expect(findOne?.parameters[0].decorators).toEqual([{ name: 'Param', arguments: [{ text: "'id'", value: 'id' }] }]);
    const mod = type('<module>');
    expect(mod?.methods.find(m => m.name === 'make')).toMatchObject({ return_type: 'Cat' });
    expect(mod?.methods.find(m => m.name === 'make')?.modifiers).toContain('export');
    expect(mod?.methods.find(m => m.name === 'arrow')?.return_type).toBe('number');
    expect(mod?.methods.find(m => m.name === 'internal')?.modifiers).toContain('export'); // `export { internal as renamed }`
    expect(mod?.methods.find(m => m.name === 'hidden')?.modifiers).toEqual(expect.arrayContaining(['export', 'default']));
  });

  it('exports only what the file exports; private members are left out', async () => {
    const ir = await analyze(CATS, 'src/cats.ts', 'typescript', { declarationDetail: true });
    const symbols = ir.exports.map(e => `${e.symbol}:${e.visibility}`);
    expect(symbols).toEqual(expect.arrayContaining([
      'CatsService:public', 'CatsService.findAll:public', 'CatsService.count:protected',
      'CatsController:public', 'CatsController.findOne:public', 'Cat:public', 'make:public', 'arrow:public',
    ]));
    expect(symbols.some(s => s.startsWith('CatsService.helper') || s.startsWith('CatsService.cats') || s.startsWith('Base'))).toBe(false);
  });

  it('a file without ES exports keeps every declaration (CommonJS)', async () => {
    const code = 'function a() {}\nclass B { m() {} }\nmodule.exports = { a, B };';
    const detail = await analyze(code, 'lib/x.js', 'javascript', { declarationDetail: true });
    const plain = await analyze(code, 'lib/x.js', 'javascript');
    expect(detail.exports).toEqual(plain.exports);
  });

  it('is off by default: types and exports are unchanged', async () => {
    const plain = await analyze(CATS, 'src/cats.ts', 'typescript');
    expect(plain.types.some(t => t.modifiers !== undefined || t.decorators !== undefined)).toBe(false);
    expect(plain.types.flatMap(t => t.methods).some(m => m.decorators !== undefined)).toBe(false);
    expect(plain.types.find(t => t.name === 'CatsService')?.methods.find(m => m.name === 'findAll')?.return_type).toBeNull();
    // The default lists private members too.
    expect(plain.exports.some(e => e.symbol === 'CatsService.helper')).toBe(true);
  });
});
