/**
 * Regression tests for Issue #5 — TypeScript parser dropped functions with
 * inline object-literal type parameters. Root cause was a silent
 * `typescript → javascript` grammar redirect in `core/parser.ts`; after
 * shipping the real `tree-sitter-typescript.wasm` grammar and adding
 * `required_parameter` / `optional_parameter` handling in `extractJSParameters`,
 * these cases must all produce well-formed types/methods/params.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initParser, parse } from '../../src/core/parser.js';
import { extractTypes } from '../../src/core/extractors/types.js';

describe('TypeScript Type Extractor (Issue #5)', () => {
  beforeAll(async () => {
    await initParser();
  });

  it('extracts a function whose only param is an inline object type', async () => {
    const code = `export function describe(p: { name: string }): string { return p.name; }`;
    const tree = await parse(code, 'typescript');
    const types = extractTypes(tree, undefined, 'typescript');

    const moduleType = types.find(t => t.name === '<module>');
    expect(moduleType).toBeDefined();
    const describeFn = moduleType!.methods.find(m => m.name === 'describe');
    expect(describeFn).toBeDefined();
    expect(describeFn!.parameters.length).toBe(1);
    expect(describeFn!.parameters[0].name).toBe('p');
    expect(describeFn!.parameters[0].type).toContain('name');
  });

  it('extracts both functions when an inline-object-type fn precedes a plain fn', async () => {
    const code = [
      `export function describe(p: { name: string }): string { return p.name; }`,
      `export function other(x: number): number { return x; }`,
    ].join('\n');
    const tree = await parse(code, 'typescript');
    const types = extractTypes(tree, undefined, 'typescript');

    const moduleType = types.find(t => t.name === '<module>');
    expect(moduleType).toBeDefined();
    const names = moduleType!.methods.map(m => m.name).sort();
    expect(names).toEqual(['describe', 'other']);
  });

  it('extracts function with inline-object-array param plus follower', async () => {
    const code = [
      `export function calculateTotal(items: { price: number }[]) { return items.length; }`,
      `export function applyDiscount(x: number) { return x; }`,
    ].join('\n');
    const tree = await parse(code, 'typescript');
    const types = extractTypes(tree, undefined, 'typescript');

    const moduleType = types.find(t => t.name === '<module>');
    expect(moduleType).toBeDefined();
    const names = moduleType!.methods.map(m => m.name).sort();
    expect(names).toEqual(['applyDiscount', 'calculateTotal']);
  });

  it('preserves param name and TS type for primitive-typed params', async () => {
    const code = `export function plain(x: number): number { return x; }`;
    const tree = await parse(code, 'typescript');
    const types = extractTypes(tree, undefined, 'typescript');

    const moduleType = types.find(t => t.name === '<module>');
    const plain = moduleType!.methods.find(m => m.name === 'plain');
    expect(plain).toBeDefined();
    expect(plain!.parameters.length).toBe(1);
    expect(plain!.parameters[0].name).toBe('x');
    expect(plain!.parameters[0].type).toBe('number');
  });

  it('extracts function referencing a named interface as its param type', async () => {
    const code = [
      `interface Item { price: number }`,
      `export function calculateTotal(items: Item[]) { return items.length; }`,
    ].join('\n');
    const tree = await parse(code, 'typescript');
    const types = extractTypes(tree, undefined, 'typescript');

    const moduleType = types.find(t => t.name === '<module>');
    expect(moduleType).toBeDefined();
    const calc = moduleType!.methods.find(m => m.name === 'calculateTotal');
    expect(calc).toBeDefined();
    expect(calc!.parameters.length).toBe(1);
    expect(calc!.parameters[0].name).toBe('items');
    expect(calc!.parameters[0].type).toBe('Item[]');
  });

  it('handles optional parameters', async () => {
    const code = `export function optFn(a: number, b?: string): void {}`;
    const tree = await parse(code, 'typescript');
    const types = extractTypes(tree, undefined, 'typescript');

    const moduleType = types.find(t => t.name === '<module>');
    const opt = moduleType!.methods.find(m => m.name === 'optFn');
    expect(opt).toBeDefined();
    expect(opt!.parameters.length).toBe(2);
    expect(opt!.parameters[0].name).toBe('a');
    expect(opt!.parameters[0].type).toBe('number');
    expect(opt!.parameters[1].name).toBe('b');
    expect(opt!.parameters[1].type).toBe('string');
  });
});
