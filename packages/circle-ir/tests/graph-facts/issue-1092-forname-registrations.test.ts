/**
 * cognium-dev#1092 — `Class.forName(<computed>)` registrations named every declaration
 * without a strong path (iDempiere: 26 sites holding 25,707 may-be-live declarations).
 * They now carry `from` (counted only when the site's body is reached), resolve a local
 * string constant like a literal, and carry a type bound when the method casts / checks
 * the loaded class; with `boundRegistrations` on (off by default) they then name only
 * that type and its subtypes.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer } from '../../src/analyzer.js';
import { buildJavaGraph } from '../../src/navigation/index.js';
import { reach } from '../../src/graph-facts/index.js';

const f = (path: string, code: string) => ({ path, code });

const lib = [
  f('src/p/Plugin.java', 'package p;\npublic interface Plugin { void run(); }\n'),
  f('src/p/PluginImpl.java', 'package p;\npublic class PluginImpl implements Plugin { public void run() {} }\n'),
  f('src/p/SubImpl.java', 'package p;\npublic class SubImpl extends PluginImpl { public void run() {} }\n'),
  f('src/p/Unrelated.java', 'package p;\npublic class Unrelated { public void go() {} }\n'),
  f('src/p/B.java', 'package p;\npublic class B { public void b() {} }\n'),
  f('src/p/C.java', 'package p;\npublic class C { public void c() {} }\n'),
];

async function run(loader: string, opts: { reachLoader?: boolean; bound?: boolean } = {}) {
  const main = opts.reachLoader === false
    ? 'package p;\npublic class Main { public static void main(String[] a) {} }\n'
    : 'package p;\npublic class Main { public static void main(String[] a) throws Exception { new Loader().load(a[0]); } }\n';
  const g = await buildJavaGraph([...lib, f('src/p/Main.java', main), f('src/p/Loader.java', `package p;\nimport java.security.Provider;\npublic class Loader {\n${loader}\n}\n`)]);
  const facts = reach(g, { boundRegistrations: opts.bound ?? true }).facts;
  const named = (qname: string) => {
    const fact = facts.find(x => x.qualified_name === qname);
    return fact ? fact.unresolved.filter(u => u.kind === 'registration').length : -1;
  };
  return { g, named };
}

describe('#1092 Class.forName registrations', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('a site in an unreached body carries from and names nothing', async () => {
    const { g, named } = await run('  public Object load(String n) throws Exception { return Class.forName(n).newInstance(); }', { reachLoader: false });
    expect(g.unresolvedRegistrations).toHaveLength(1);
    expect(g.unresolvedRegistrations[0].from).toBeDefined();
    expect(named('p:Unrelated')).toBe(0);
  });

  it('unbound and reached: names every declaration without a strong path (unchanged)', async () => {
    const { named } = await run('  public Object load(String n) throws Exception { return Class.forName(n).newInstance(); }');
    expect(named('p:Unrelated')).toBe(1);
    expect(named('p:B')).toBe(1);
  });

  it('a local string constant is the literal case: a reflection entry, no registration', async () => {
    const { g } = await run('  public Object load(String x) throws Exception { String n = "p.B"; return Class.forName(n).newInstance(); }');
    expect(g.unresolvedRegistrations).toHaveLength(0);
    expect(g.entries.some(e => e.kind === 'reflection' && e.evidence?.includes('local constant'))).toBe(true);
  });

  it('a local constant naming a type outside the tree gives neither entry nor registration', async () => {
    const { g } = await run('  public Object load(String x) throws Exception { String n = "oracle.jdbc.OracleDriver"; return Class.forName(n); }');
    expect(g.unresolvedRegistrations).toHaveLength(0);
    expect(g.entries.filter(e => e.kind === 'reflection')).toHaveLength(0);
  });

  it('two literal assignments give both entries; a non-literal on any path keeps the registration', async () => {
    const both = await run('  public Object load(String x) throws Exception { String n = "p.B"; if (x == null) n = "p.C"; return Class.forName(n); }');
    expect(both.g.unresolvedRegistrations).toHaveLength(0);
    expect(both.g.entries.filter(e => e.kind === 'reflection')).toHaveLength(2);
    const mixed = await run('  public Object load(String x) throws Exception { String n = "p.B"; if (x != null) n = x.trim(); return Class.forName(n); }');
    expect(mixed.g.unresolvedRegistrations).toHaveLength(1);
  });

  it('a null initializer names no class: null then literal reassignments resolve (iDempiere Adempiere.java)', async () => {
    const { g } = await run('  public void load(String x) { String n = null; try { n = "p.B"; Class.forName(n); n = "p.C"; Class.forName(n); } catch (Exception e) { System.out.println(n); } }');
    expect(g.unresolvedRegistrations).toHaveLength(0);
    expect(new Set(g.entries.filter(e => e.kind === 'reflection').map(e => e.id)).size).toBe(2);
  });

  it('a same-named local in a sibling block is another variable (iDempiere Adempiere.java)', async () => {
    const { g } = await run('  public void load(String x) { if (x != null) { String n = x.trim(); System.out.println(n); }\n    String n = null; try { n = "p.B"; Class.forName(n); } catch (Exception e) { } }');
    expect(g.unresolvedRegistrations).toHaveLength(0);
    expect(g.entries.filter(e => e.kind === 'reflection')).toHaveLength(1);
  });

  it('a static final String field constant resolves too', async () => {
    const { g } = await run('  private static final String IMPL = "p.C";\n  public Object load(String x) throws Exception { return Class.forName(IMPL).newInstance(); }');
    expect(g.unresolvedRegistrations).toHaveLength(0);
  });

  const bounded: Array<[string, string]> = [
    ['a cast of getDeclaredConstructor().newInstance()', '  public Plugin load(String n) throws Exception { return (Plugin) Class.forName(n).getDeclaredConstructor().newInstance(); }'],
    ['a cast of newInstance() on a variable', '  public Plugin load(String n) throws Exception { Class<?> c = Class.forName(n); return (Plugin) c.newInstance(); }'],
    ['asSubclass', '  public Object load(String n) throws Exception { return Class.forName(n).asSubclass(Plugin.class).getDeclaredConstructor().newInstance(); }'],
    ['instanceof', '  public Object load(String n) throws Exception { Object o = Class.forName(n).newInstance(); if (o instanceof Plugin) return o; return null; }'],
    ['isAssignableFrom', '  public Object load(String n) throws Exception { Class<?> c = Class.forName(n); if (Plugin.class.isAssignableFrom(c)) return c.newInstance(); return null; }'],
  ];
  for (const [name, code] of bounded) {
    it(`bound by ${name}: names the type and its subtypes, not Unrelated`, async () => {
      const { g, named } = await run(code);
      // a same-package simple name is kept as written; the fill step tries the file's package
      expect(g.unresolvedRegistrations[0].bound).toEqual(['Plugin']);
      expect(named('p:PluginImpl')).toBe(1);
      expect(named('p:SubImpl')).toBe(1);
      expect(named('p:Unrelated')).toBe(0);
      expect(named('p:B')).toBe(0);
    });
  }

  it('a getSuperclass() == T.class walk bounds by T', async () => {
    const { named } = await run('  public Object load(String n) throws Exception { Class<?> c = Class.forName(n); while (c != null && c.getSuperclass() != PluginImpl.class) c = c.getSuperclass(); return c; }');
    // the walk compares with !=; only `==` is recognised, so this stays unbound
    expect(named('p:Unrelated')).toBe(1);
    const eq = await run('  public Object load(String n) throws Exception { Class<?> c = Class.forName(n); if (c.getSuperclass() == PluginImpl.class) return c.newInstance(); return null; }');
    expect(eq.named('p:SubImpl')).toBe(1);
    expect(eq.named('p:Unrelated')).toBe(0);
  });

  it('with boundRegistrations off (the default) the bound is kept as evidence but does not narrow', async () => {
    const code = '  public Plugin load(String n) throws Exception { return (Plugin) Class.forName(n).getDeclaredConstructor().newInstance(); }';
    const { g, named } = await run(code, { bound: false });
    expect(g.unresolvedRegistrations[0].bound).toEqual(['Plugin']);
    expect(g.unresolvedRegistrations[0].boundTypes?.length).toBeGreaterThan(0);
    expect(named('p:PluginImpl')).toBe(1);
    expect(named('p:Unrelated')).toBe(1);
    expect(named('p:B')).toBe(1);
  });

  it('a getSuperclass() walk through a variable bounds by T (iDempiere DefaultModelFactory.getPOclass)', async () => {
    const { g, named } = await run('  public Class<?> load(String n) { try { Class<?> c = Class.forName(n); Class<?> s = c.getSuperclass(); while (s != null) { if (s == PluginImpl.class) return c; s = s.getSuperclass(); } } catch (Exception e) { } return null; }');
    expect(g.unresolvedRegistrations[0].bound).toEqual(['PluginImpl']);
    expect(named('p:SubImpl')).toBe(1);
    expect(named('p:Unrelated')).toBe(0);
  });

  it('a package-qualified pattern instanceof bounds too (iDempiere DefaultKeyStore.java)', async () => {
    const { g, named } = await run('  public void load(String n) throws Exception { Class<?> c = Class.forName(n); Object o = c.getDeclaredConstructor().newInstance(); if (o != null && o instanceof java.security.Provider sp) java.security.Security.addProvider(sp); }');
    expect(g.unresolvedRegistrations[0].bound).toEqual(['java.security.Provider']);
    expect(g.unresolvedRegistrations[0].boundTypes).toEqual([]);
    expect(named('p:Unrelated')).toBe(0);
  });

  it('an external bound (java.security.Provider) names no in-tree declaration', async () => {
    const { g, named } = await run('  public Object load(String n) throws Exception { Object o = Class.forName(n).newInstance(); if (o instanceof Provider) return o; return null; }');
    expect(g.unresolvedRegistrations[0].bound).toEqual(['java.security.Provider']);
    expect(g.unresolvedRegistrations[0].boundTypes).toEqual([]);
    expect(named('p:Unrelated')).toBe(0);
    expect(named('p:PluginImpl')).toBe(0);
  });
});
