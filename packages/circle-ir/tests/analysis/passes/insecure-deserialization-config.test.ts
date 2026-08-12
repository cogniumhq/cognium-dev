import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const has = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.findings ?? []).some((f) => f.rule_id === 'insecure-deserialization-config');

// cognium-dev#225 — deterministic CWE-502 finding for XStream configured with a
// grant-all type permission. The vulnerability is the constant argument, not a
// taint flow, so this is a call-shape match (like weak-crypto).
describe('insecure-deserialization-config (XStream AnyTypePermission)', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('fires on addPermission(AnyTypePermission.ANY)', async () => {
    const code = `public class C { void s() { xstream.addPermission(AnyTypePermission.ANY); } }`;
    expect(has(await analyze(code, 'X.java', 'java'))).toBe(true);
  });

  it('fires on addPermission(new AnyTypePermission())', async () => {
    const code = `public class C { void s() { xs.addPermission(new AnyTypePermission()); } }`;
    expect(has(await analyze(code, 'X.java', 'java'))).toBe(true);
  });

  it('fires on a fully-qualified AnyTypePermission', async () => {
    const code = `public class C { void s() { xs.addPermission(com.thoughtworks.xstream.security.AnyTypePermission.ANY); } }`;
    expect(has(await analyze(code, 'X.java', 'java'))).toBe(true);
  });

  it('reports CWE-502 at the addPermission line', async () => {
    const code = [
      'public class C {',
      '  void setupSecurity() {',
      '    xstream.addPermission(AnyTypePermission.ANY);',
      '  }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'X.java', 'java');
    const f = (r.findings ?? []).find((x) => x.rule_id === 'insecure-deserialization-config');
    expect(f?.cwe).toBe('CWE-502');
    expect(f?.line).toBe(3);
  });

  it('does NOT fire on the secure NoTypePermission.NONE shape', async () => {
    const code = `public class C { void s() { xstream.addPermission(NoTypePermission.NONE); } }`;
    expect(has(await analyze(code, 'X.java', 'java'))).toBe(false);
  });

  it('does NOT fire on an explicit type allow-list (allowTypes / WildcardTypePermission)', async () => {
    const allow = `public class C { void s() { xstream.allowTypes(new Class[]{ Foo.class }); } }`;
    const wild = `public class C { void s() { xstream.addPermission(new WildcardTypePermission(new String[]{"com.example.**"})); } }`;
    expect(has(await analyze(allow, 'X.java', 'java'))).toBe(false);
    expect(has(await analyze(wild, 'X.java', 'java'))).toBe(false);
  });

  it('does NOT fire on an unrelated addPermission call', async () => {
    const code = `public class C { void s() { acl.addPermission(READ); } }`;
    expect(has(await analyze(code, 'X.java', 'java'))).toBe(false);
  });

  it('is Java-only (does not fire on other languages)', async () => {
    const code = `public class C { void s() { xs.addPermission(AnyTypePermission.ANY); } }`;
    expect(has(await analyze(code, 'X.cs', 'csharp'))).toBe(false);
  });
});
