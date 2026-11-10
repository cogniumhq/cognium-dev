/**
 * #1192 — `new Node()` inside a class that declares a member type `Node` must
 * bind to that member constructor, not a same-package `Node`.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer } from '../../src/analyzer.js';
import { buildJavaGraph, type JavaGraph } from '../../src/navigation/index.js';

const file = (path: string, code: string) => ({ path, code });

const APP: Record<string, string> = {
  'src/app/Node.java': ['package app;', 'public class Node {', '  public Node() {}', '}', ''].join('\n'),
  'src/app/Tree.java': [
    'package app;',
    'public class Tree {',
    '  static class Node { Node() {} }',
    '  Tree build() { return new Node(); }',
    '}',
    '',
  ].join('\n'),
  'src/app/Forest.java': [
    'package app;',
    'public class Forest {',
    '  Forest build() { return new Node(); }',
    '}',
    '',
  ].join('\n'),
};

let g: JavaGraph;
let q: Map<string, string>;

const ctorEdgesAt = (f: string, line: number) =>
  g.edges
    .filter(e => e.site.file === f && e.site.line === line && e.methodName === 'Node')
    .map(e => `Node -> ${q.get(e.to)} [${e.tier}]`);

beforeAll(async () => {
  await initAnalyzer();
  g = await buildJavaGraph(Object.entries(APP).map(([p, c]) => file(p, c)));
  q = new Map(g.files.flatMap(f => f.decls.map(d => [d.id, `${d.qualified_name}${d.kind === 'method' ? d.signature : ''}`] as const)));
}, 60_000);

describe('#1192 new Node() resolves member types in the enclosing class', () => {
  it('Tree.build binds new Node() to the member type constructor', () => {
    expect(ctorEdgesAt('src/app/Tree.java', 4)).toEqual(['Node -> app:Tree.Node.constructor() [exact]']);
  });

  it('Forest.build keeps the package-level Node when no member type exists', () => {
    expect(ctorEdgesAt('src/app/Forest.java', 3)).toEqual(['Node -> app:Node.constructor() [exact]']);
  });
});
