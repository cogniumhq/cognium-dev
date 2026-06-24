/**
 * Unit tests for `resolveEnv` — path-based ProjectEnv classifier
 * (3.106.0, #169). Pillar I: pure path classification, no LLM identifiers.
 */

import { describe, test, expect } from 'bun:test';
import { resolveEnv } from '../src/project-profile-detect/env-resolve.js';

describe('resolveEnv', () => {
  test('src/main/... → production', () => {
    expect(resolveEnv('/repo/src/main/java/com/foo/Bar.java')).toBe('production');
  });

  test('src/test/... → test', () => {
    expect(resolveEnv('/repo/src/test/java/com/foo/BarTest.java')).toBe('test');
  });

  test('tests/ → test', () => {
    expect(resolveEnv('/repo/tests/integration/foo.py')).toBe('test');
  });

  test('test/ → test', () => {
    expect(resolveEnv('/repo/test/unit/foo.java')).toBe('test');
  });

  test('samples/ → sample', () => {
    expect(resolveEnv('/repo/samples/hello/Foo.java')).toBe('sample');
  });

  test('sample/ → sample', () => {
    expect(resolveEnv('/repo/sample/Foo.java')).toBe('sample');
  });

  test('examples/ → sample', () => {
    expect(resolveEnv('/repo/examples/quickstart/Foo.java')).toBe('sample');
  });

  test('example/ → sample', () => {
    expect(resolveEnv('/repo/example/Foo.java')).toBe('sample');
  });

  test('demos/ → sample', () => {
    expect(resolveEnv('/repo/demos/web/Foo.java')).toBe('sample');
  });

  test('fixtures/ → sample', () => {
    expect(resolveEnv('/repo/fixtures/data/Foo.java')).toBe('sample');
  });

  test('benchmarks/ → benchmark', () => {
    expect(resolveEnv('/repo/benchmarks/jmh/Foo.java')).toBe('benchmark');
  });

  test('benchmark/ → benchmark', () => {
    expect(resolveEnv('/repo/benchmark/Foo.java')).toBe('benchmark');
  });

  test('no matching prefix → dev', () => {
    expect(resolveEnv('/repo/lib/Foo.java')).toBe('dev');
  });

  test('test wins over src/main when both appear', () => {
    expect(resolveEnv('/repo/src/main/test/integration/FooTest.java')).toBe('test');
  });

  test('Windows-style backslashes are normalized', () => {
    expect(resolveEnv('C:\\repo\\src\\main\\java\\Foo.java')).toBe('production');
    expect(resolveEnv('C:\\repo\\tests\\Foo.java')).toBe('test');
  });

  test('case-insensitive matching', () => {
    expect(resolveEnv('/repo/Tests/Foo.java')).toBe('test');
    expect(resolveEnv('/repo/SAMPLES/Foo.java')).toBe('sample');
  });
});
