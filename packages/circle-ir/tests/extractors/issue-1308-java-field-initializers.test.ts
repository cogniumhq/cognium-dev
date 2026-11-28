/**
 * Java field initializers (cognium-dev#1308): a call in a static field's
 * initializer, an interface constant's or an enum constant's arguments
 * carries `in_method` `<clinit>`, and one in an instance field's initializer
 * `<init>`, instead of `null`.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initParser, parse } from '../../src/core/parser.js';
import { extractCalls } from '../../src/core/extractors/calls.js';

const JAVA = `class A {
  static final String KEY = System.getenv("KEY");
  private String url = build(KEY);
  Runnable r = () -> later();
  interface I { String C = make(); }
  enum E {
    ONE(compute()) {
      int v = constantField();
      void m() { constantMethod(); }
    };
    static int n = count();
    String label = name().toLowerCase();
    E(int x) {}
  }
  void m() {
    Object o = new Object() { int y = inner(); };
  }
}`;

const CSHARP = `class A {
  private static string Key = Environment.GetEnvironmentVariable("KEY");
}`;

describe('Java field initializers (#1308)', () => {
  beforeAll(async () => {
    await initParser();
  });

  const inMethodOf = async () => {
    const calls = extractCalls(await parse(JAVA, 'java'), undefined, 'java');
    return (name: string) => calls.find(c => c.method_name === name)?.in_method;
  };

  it('calls in static field, interface constant and enum constant initializers are in <clinit>', async () => {
    const inMethod = await inMethodOf();
    expect(inMethod('getenv')).toBe('<clinit>');
    expect(inMethod('make')).toBe('<clinit>');
    expect(inMethod('compute')).toBe('<clinit>');
    expect(inMethod('count')).toBe('<clinit>');
  });

  it('calls in instance field initializers are in <init>', async () => {
    const inMethod = await inMethodOf();
    expect(inMethod('build')).toBe('<init>');
    expect(inMethod('later')).toBe('<init>');
    expect(inMethod('toLowerCase')).toBe('<init>');
    // a field of an enum constant's body is an instance field of that body
    expect(inMethod('constantField')).toBe('<init>');
  });

  it('calls in methods keep their enclosing name', async () => {
    const inMethod = await inMethodOf();
    expect(inMethod('constantMethod')).toBe('m');
    // a field of an anonymous class inside a method stays with that method
    expect(inMethod('inner')).toBe('m');
  });

  it('leaves C# field initializers unchanged', async () => {
    const calls = extractCalls(await parse(CSHARP, 'csharp'), undefined, 'csharp');
    const call = calls.find(c => c.method_name === 'GetEnvironmentVariable');
    expect(call).toBeDefined();
    expect(call!.in_method).toBeNull();
  });
});
