/**
 * TypeScript interface extraction (tasks.md "Interface extraction enrichment").
 *
 * `extractJavaScriptTypes` walked only `class_declaration`, `function_declaration`
 * and named arrow functions, so an `interface` declaration produced no
 * `TypeInfo` at all: two interfaces alongside an implementing class yielded
 * exactly one type, the class. Cross-instance taint analysis (Issue #1) needs
 * the declared contract when a field's type is an interface.
 *
 * Java interfaces go through `extractInterfaceInfo` and have a different body
 * shape; these tests cover the TS path only.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';
import type { TypeInfo } from '../../src/types/index.js';

const source = [
  'export interface User { id: string; email?: string; }',
  'export interface UserRepo extends Base, Audited {',
  '  readonly name: string;',
  '  find(id: string): Promise<User>;',
  '  save(u: User): void;',
  '  onEvent: (e: string) => void;',
  '}',
  'export class SqlUserRepo implements UserRepo {',
  '  save(u: User) {}',
  '}',
].join('\n');

async function typesOf(file: string, lang: 'typescript' | 'javascript'): Promise<TypeInfo[]> {
  const ir = await analyze(source, file, lang);
  return ir.types;
}

describe('TypeScript interface extraction', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('emits a TypeInfo per interface, alongside the class', async () => {
    const types = await typesOf('r.ts', 'typescript');
    const names = types.map(t => `${t.kind}:${t.name}`);
    expect(names).toContain('interface:User');
    expect(names).toContain('interface:UserRepo');
    expect(names).toContain('class:SqlUserRepo');
  });

  it('populates methods from method_signature with parameters and return type', async () => {
    const repo = (await typesOf('r.ts', 'typescript')).find(t => t.name === 'UserRepo')!;
    const find = repo.methods.find(m => m.name === 'find')!;
    expect(find).toBeDefined();
    expect(find.parameters.map(p => p.name)).toEqual(['id']);
    expect(find.return_type).toBe('Promise<User>');
    expect(repo.methods.map(m => m.name)).toContain('save');
  });

  it('populates fields from property_signature, with readonly and optional modifiers', async () => {
    const types = await typesOf('r.ts', 'typescript');
    const repo = types.find(t => t.name === 'UserRepo')!;
    const user = types.find(t => t.name === 'User')!;

    const name = repo.fields.find(f => f.name === 'name')!;
    expect(name.type).toBe('string');
    expect(name.modifiers).toContain('readonly');

    const email = user.fields.find(f => f.name === 'email')!;
    expect(email.modifiers).toContain('optional');
  });

  it('treats a function-typed property as a field, not a method', async () => {
    // `onEvent: (e: string) => void` is a property_signature in the grammar.
    const repo = (await typesOf('r.ts', 'typescript')).find(t => t.name === 'UserRepo')!;
    expect(repo.fields.map(f => f.name)).toContain('onEvent');
    expect(repo.methods.map(m => m.name)).not.toContain('onEvent');
  });

  it('splits multiple extends across extends + implements', async () => {
    const repo = (await typesOf('r.ts', 'typescript')).find(t => t.name === 'UserRepo')!;
    expect(repo.extends).toBe('Base');
    expect(repo.implements).toEqual(['Audited']);
  });

  it('works identically for .tsx', async () => {
    const ts = await typesOf('r.ts', 'typescript');
    const tsx = await typesOf('r.tsx', 'typescript');
    expect(tsx.map(t => `${t.kind}:${t.name}`).sort()).toEqual(
      ts.map(t => `${t.kind}:${t.name}`).sort(),
    );
  });

  it('is a no-op for plain JavaScript, which has no interface_declaration', async () => {
    const ir = await analyze('class A { m() {} }', 'a.js', 'javascript');
    expect(ir.types.map(t => `${t.kind}:${t.name}`)).toEqual(['class:A']);
  });
});
