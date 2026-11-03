/**
 * cognium-dev#1093 — `X[]::new` and `Ext::new` method references were emitted as
 * `dynamic` unresolved sites with methodName `constructor`, and removal reach / dead code
 * then named every constructor in the tree with them (iDempiere: 83 rows). An array
 * creation calls no declared constructor; a constructor reference to a type outside the
 * tree is an `external` call naming its receiver, like `new Ext()`.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer } from '../../src/analyzer.js';
import { buildJavaGraph } from '../../src/navigation/index.js';

const file = (path: string, code: string) => ({ path, code });

const graph = (body: string) => buildJavaGraph([
  file('src/app/Box.java', 'package app;\npublic class Box {\n  public Box() {}\n  public Box(String s) {}\n}\n'),
  file('src/app/Use.java', `package app;\nimport java.util.*;\nimport java.util.stream.*;\npublic class Use {\n  void run(List<String> xs) {\n${body}\n  }\n}\n`),
]);

const ctorRows = (g: Awaited<ReturnType<typeof buildJavaGraph>>) => g.unresolved.filter(u => u.methodName === 'constructor');

describe('#1093 constructor method references', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('T[]::new emits no unresolved row (an array, no constructor)', async () => {
    const g = await graph('    String[] a = xs.stream().toArray(String[]::new);\n    int[][] b = Stream.of(1).map(i -> new int[0]).toArray(int[][]::new);');
    expect(ctorRows(g)).toHaveLength(0);
  });

  it('Ext::new on a type outside the tree is external, naming its receiver', async () => {
    const g = await graph('    Map<String, List<String>> m = new HashMap<>();\n    m.computeIfAbsent("k", k -> new ArrayList<>());\n    Set<String> s = xs.stream().collect(Collectors.toCollection(TreeSet::new));\n    List<String> l = xs.stream().collect(Collectors.toCollection(java.util.LinkedList::new));');
    const rows = ctorRows(g);
    // a wildcard import (`java.util.*`) names no package for the simple name; a qualified one is kept
    expect(rows.map(r => [r.reason, r.receiver])).toEqual([['external', 'TreeSet'], ['external', 'java.util.LinkedList']]);
    expect(rows.some(r => r.reason === 'dynamic')).toBe(false);
  });

  it('an explicit import gives the qualified receiver', async () => {
    const g = await buildJavaGraph([file('src/app/E.java', 'package app;\nimport java.util.ArrayDeque;\nimport java.util.function.Supplier;\npublic class E {\n  Supplier<ArrayDeque<String>> s = ArrayDeque::new;\n}\n')]);
    expect(ctorRows(g).map(r => [r.reason, r.receiver])).toEqual([['external', 'java.util.ArrayDeque']]);
  });

  it('a constructor reference to a type in the tree still links to its constructors', async () => {
    const g = await graph('    List<Box> boxes = xs.stream().map(Box::new).collect(Collectors.toList());');
    expect(ctorRows(g)).toHaveLength(0);
    const boxCtors = g.files.find(f => f.file === 'src/app/Box.java')!.decls.filter(d => d.name === 'constructor').map(d => d.id);
    expect(g.references.some(r => boxCtors.includes(r.to))).toBe(true);
  });
});
