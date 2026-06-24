/**
 * Unit tests for `compileOverrides` + `applyOverrides` — glob-based
 * profile overrides (3.106.0, #169). Pillar I: no LLM identifiers.
 */

import { describe, test, expect } from 'bun:test';
import {
  compileOverrides,
  applyOverrides,
} from '../src/overrides.js';

describe('compileOverrides + applyOverrides', () => {
  test('empty / undefined input → no matches', () => {
    expect(compileOverrides(undefined)).toEqual([]);
    expect(compileOverrides({})).toEqual([]);
    expect(applyOverrides('any/file.java', [])).toBeUndefined();
  });

  test('exact literal match', () => {
    const c = compileOverrides({ 'src/main/java/Foo.java': 'library/production' });
    expect(applyOverrides('src/main/java/Foo.java', c)?.profile).toBe('library/production');
    expect(applyOverrides('src/main/java/Bar.java', c)).toBeUndefined();
  });

  test('single * matches within a path segment but not across /', () => {
    const c = compileOverrides({ 'src/main/java/*.java': 'application/dev' });
    expect(applyOverrides('src/main/java/Foo.java', c)?.profile).toBe('application/dev');
    expect(applyOverrides('src/main/java/sub/Foo.java', c)).toBeUndefined();
  });

  test('** matches across / segments', () => {
    const c = compileOverrides({ 'src/main/**/*.java': 'library/dev' });
    expect(applyOverrides('src/main/java/Foo.java', c)?.profile).toBe('library/dev');
    expect(applyOverrides('src/main/java/com/example/deep/Foo.java', c)?.profile).toBe('library/dev');
    expect(applyOverrides('other/Foo.java', c)).toBeUndefined();
  });

  test('? matches exactly one non-slash character', () => {
    const c = compileOverrides({ 'F?o.java': 'library/dev' });
    expect(applyOverrides('Foo.java', c)?.profile).toBe('library/dev');
    expect(applyOverrides('Fxo.java', c)?.profile).toBe('library/dev');
    expect(applyOverrides('Fxxo.java', c)).toBeUndefined();
  });

  test('regex metacharacters are escaped (literal . [ ] etc.)', () => {
    const c = compileOverrides({ 'lib/v1.0/Foo.java': 'library/production' });
    expect(applyOverrides('lib/v1.0/Foo.java', c)?.profile).toBe('library/production');
    // Without escape, `.` would match any char.
    expect(applyOverrides('lib/v1X0/Foo.java', c)).toBeUndefined();
  });

  test('first matching glob wins (insertion order)', () => {
    const c = compileOverrides({
      'src/main/java/Foo.java': 'application/production',
      'src/main/**/*.java':      'library/production',
    });
    expect(applyOverrides('src/main/java/Foo.java', c)?.profile).toBe('application/production');
    expect(applyOverrides('src/main/java/Bar.java', c)?.profile).toBe('library/production');
  });

  test('windows backslashes are normalized', () => {
    const c = compileOverrides({ 'src/main/**/*.java': 'library/dev' });
    expect(applyOverrides('src\\main\\java\\Foo.java', c)?.profile).toBe('library/dev');
  });

  test('explicit unknown override masks detection', () => {
    const c = compileOverrides({ 'thirdparty/**': 'unknown' });
    expect(applyOverrides('thirdparty/foo/Bar.java', c)?.profile).toBe('unknown');
  });

  test('reason output includes the matching glob', () => {
    const c = compileOverrides({ 'src/main/**/*.java': 'library/production' });
    expect(applyOverrides('src/main/Foo.java', c)?.glob).toBe('src/main/**/*.java');
  });
});
