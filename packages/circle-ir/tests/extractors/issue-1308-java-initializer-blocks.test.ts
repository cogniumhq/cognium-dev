/**
 * Java static and instance initializer blocks (cognium-dev#1308): their calls
 * carry `in_method` `<clinit>` / `<init>` instead of `null`, and their
 * assignments and locals get DFG defs with chains between them.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initParser, parse } from '../../src/core/parser.js';
import { extractCalls } from '../../src/core/extractors/calls.js';
import { buildDFG } from '../../src/core/extractors/dfg.js';

const CODE = `class A {
  static int count;
  static {
    count = load();
    String c = System.getenv("X");
    String d = c + " -v";
  }
  int x;
  {
    x = init();
    register(this);
  }
  static int load() { return 1; }
  int init() { return 2; }
  void m() { helper(); }
  A() { setup(); }
  enum E {
    ONE;
    static { warm(); }
    { touch(); }
  }
  void anon() {
    Runnable r = new Runnable() {
      { inner(); }
      public void run() {}
    };
  }
}`;

describe('Java initializer blocks (#1308)', () => {
  beforeAll(async () => {
    await initParser();
  });

  it('calls in a static block are in <clinit>, in an instance initializer in <init>', async () => {
    const tree = await parse(CODE, 'java');
    const calls = extractCalls(tree, undefined, 'java');
    const inMethod = (name: string) => calls.find(c => c.method_name === name)?.in_method;
    expect(inMethod('load')).toBe('<clinit>');
    expect(inMethod('getenv')).toBe('<clinit>');
    expect(inMethod('init')).toBe('<init>');
    expect(inMethod('register')).toBe('<init>');
    expect(inMethod('warm')).toBe('<clinit>');
    expect(inMethod('touch')).toBe('<init>');
  });

  it('calls in methods and constructors keep their enclosing name', async () => {
    const tree = await parse(CODE, 'java');
    const calls = extractCalls(tree, undefined, 'java');
    const inMethod = (name: string) => calls.find(c => c.method_name === name)?.in_method;
    expect(inMethod('helper')).toBe('m');
    expect(inMethod('setup')).toBe('A');
    // an anonymous class's initializer inside a method stays with that method
    expect(inMethod('inner')).toBe('anon');
  });

  it('assignments and locals in initializer blocks are DFG defs with chains', async () => {
    const tree = await parse(CODE, 'java');
    const dfg = buildDFG(tree, undefined, 'java');
    const local = (v: string, line: number) => dfg.defs.find(d => d.variable === v && d.line === line && d.kind === 'local');
    expect(local('count', 4)).toBeDefined();
    expect(local('x', 10)).toBeDefined();
    const c = local('c', 5);
    const d = local('d', 6);
    expect(c).toBeDefined();
    expect(d).toBeDefined();
    expect(dfg.chains).toContainEqual({ from_def: c!.id, to_def: d!.id, via: 'c' });
    expect(dfg.uses.find(u => u.variable === 'c' && u.line === 6)?.def_id).toBe(c!.id);
  });
});
