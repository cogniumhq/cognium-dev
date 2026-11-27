/**
 * Maven plugin goals are entry points. Maven instantiates a class annotated
 * `@Mojo` (`org.apache.maven.plugins.annotations`), or one that extends
 * `org.apache.maven.plugin.AbstractMojo` / implements `Mojo` (the older,
 * javadoc-tag goals), injects its parameters and calls `execute()`. Nothing
 * in the project calls either, so without an entry the goal and everything
 * only it reaches read as dead code, and the entry-path gate found no entry.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer } from '../../src/analyzer.js';
import { buildJavaGraph, type JavaGraph } from '../../src/navigation/index.js';
import { deadCode } from '../../src/graph-facts/index.js';
import { classifyEntryPointTier, isSupertypeLifecycleMethod } from '../../src/analysis/entry-point-detection.js';
import type { MethodInfo, TypeInfo } from '../../src/types/index.js';

const f = (path: string, code: string) => ({ path, code });

const SOURCES = [
  f('plugin/src/main/java/t/ReportMojo.java', `package t;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
@Mojo(name = "report", requiresProject = false)
public class ReportMojo extends AbstractMojo {
  @Parameter(property = "configFile")
  String configFile;
  public void execute() { new Writer().write(configFile); }
  public void notAGoal() {}
}
`),
  // Annotation only, no AbstractMojo (implements the interface by a base outside the tree).
  f('plugin/src/main/java/t/CountMojo.java', `package t;
import org.apache.maven.plugins.annotations.*;
@Mojo(name = "count")
public class CountMojo extends Base {
  public void execute() { Helper.help(); }
}
`),
  // Older goal: javadoc tag, found by its supertype.
  f('plugin/src/main/java/t/LegacyMojo.java', `package t;
import org.apache.maven.plugin.AbstractMojo;
/** @goal legacy */
public class LegacyMojo extends AbstractMojo {
  public void execute() {}
}
`),
  // Not a Maven goal: another framework's annotation of the same name.
  f('plugin/src/main/java/t/Other.java', `package t;
import com.acme.Mojo;
@Mojo
public class Other {
  public void execute() {}
}
`),
  // Only the zero-parameter execute() is the goal; an overload is ordinary code.
  f('plugin/src/main/java/t/OverloadMojo.java', `package t;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugins.annotations.Mojo;
@Mojo(name = "overload")
public class OverloadMojo extends AbstractMojo {
  public void execute() {}
  public void execute(String goal) { Writer.class.getName(); }
}
`),
  f('plugin/src/main/java/t/Writer.java', 'package t;\npublic class Writer { public void write(String s) {} }\n'),
  f('plugin/src/main/java/t/Helper.java', 'package t;\npublic class Helper { public static void help() {} }\n'),
  f('plugin/src/main/java/t/Base.java', 'package t;\npublic abstract class Base {}\n'),
  f('plugin/src/main/java/t/Unused.java', 'package t;\npublic class Unused { public void nobody() {} }\n'),
];

let g: JavaGraph;
let qname: Map<string, string>;

beforeAll(async () => {
  await initAnalyzer();
  g = await buildJavaGraph(SOURCES);
  qname = new Map(g.files.flatMap(file => file.decls.map(d => [d.id, d.qualified_name])));
});

describe('entry index: Maven goals', () => {
  it('@Mojo execute() is a declared main entry with the goal name', () => {
    const e = g.entries.filter(x => qname.get(x.id) === 't:ReportMojo.execute');
    expect(e.map(x => [x.kind, x.certainty, x.framework])).toEqual([['main', 'declared', 'maven-plugin']]);
    expect(e[0].evidence).toBe('@Mojo(name = "report")');
  });

  it('the goal class is instantiated by Maven: its constructor (or the type) is a bean entry', () => {
    const e = g.entries.filter(x => qname.get(x.id)?.startsWith('t:ReportMojo') && x.kind === 'bean');
    expect(e).toHaveLength(1);
  });

  it('only execute() is an entry, not every public method', () => {
    expect(g.entries.some(x => qname.get(x.id) === 't:ReportMojo.notAGoal')).toBe(false);
  });

  it('a wildcard import of the annotations package matches; an AbstractMojo subclass matches without @Mojo', () => {
    expect(g.entries.some(x => qname.get(x.id) === 't:CountMojo.execute' && x.kind === 'main')).toBe(true);
    const legacy = g.entries.filter(x => qname.get(x.id) === 't:LegacyMojo.execute');
    expect(legacy.map(x => [x.kind, x.framework, x.evidence])).toEqual([['main', 'maven-plugin', 'AbstractMojo.execute']]);
  });

  it('one entry per goal when both the annotation and the supertype match', () => {
    expect(g.entries.filter(x => qname.get(x.id) === 't:ReportMojo.execute')).toHaveLength(1);
  });

  it('only the zero-parameter execute() is an entry; an overload execute(String) is not', () => {
    const decls = g.files.flatMap(file => file.decls).filter(d => d.qualified_name.startsWith('t:OverloadMojo.execute'));
    expect(decls).toHaveLength(2);
    const lineOf = new Map(decls.map(d => [d.id, d.start_line]));
    const mains = g.entries.filter(x => lineOf.has(x.id) && x.kind === 'main');
    expect(mains.map(x => lineOf.get(x.id))).toEqual([6]);
  });

  it('another package\'s @Mojo is not a Maven goal', () => {
    expect(g.entries.some(x => qname.get(x.id)?.startsWith('t:Other'))).toBe(false);
  });
});

describe('dead code: goals and what they reach are live', () => {
  it('execute(), and the code only it calls, are live; the rest stays dead', () => {
    const v = new Map(deadCode(g).facts.map(x => [qname.get(x.id), x.verdict]));
    expect(v.get('t:ReportMojo.execute')).toBe('live');
    expect(v.get('t:Writer.write')).toBe('live');
    expect(v.get('t:CountMojo.execute')).toBe('live');
    expect(v.get('t:Helper.help')).toBe('live');
    expect(v.get('t:LegacyMojo.execute')).toBe('live');
    expect(v.get('t:ReportMojo.notAGoal')).toBe('dead');
    expect(v.get('t:Other.execute')).toBe('dead');
    expect(v.get('t:Unused.nobody')).toBe('dead');
  });
});

describe('entry-point tier: a goal\'s execute() is Tier 1', () => {
  const method = (name: string): MethodInfo => ({
    name, return_type: 'void', parameters: [], annotations: [], modifiers: ['public'], start_line: 1, end_line: 2,
  });
  const type = (opts: Partial<TypeInfo>): TypeInfo => ({
    name: 'G', kind: 'class', package: 't', extends: null, implements: [], annotations: [],
    methods: [], fields: [], start_line: 1, end_line: 10, ...opts,
  });

  it('@Mojo class: execute() is Tier 1, other methods are not', () => {
    const t = type({ annotations: ['@Mojo(name = "report")'], extends: 'Base' });
    expect(classifyEntryPointTier(method('execute'), t, { language: 'java' })).toBe('TIER_1_ENTRY_POINT');
    expect(classifyEntryPointTier(method('helper'), t, { language: 'java' })).toBe('TIER_3_LIBRARY_API');
  });

  it('an overloaded execute(Foo) is not Tier 1, by annotation or by supertype', () => {
    const withParam: MethodInfo = { ...method('execute'), parameters: [{ name: 'foo', type: 'Foo', annotations: [] }] };
    expect(classifyEntryPointTier(withParam, type({ annotations: ['@Mojo(name = "report")'], extends: 'Base' }), { language: 'java' })).toBe('TIER_3_LIBRARY_API');
    expect(classifyEntryPointTier(withParam, type({ extends: 'AbstractMojo' }), { language: 'java' })).toBe('TIER_3_LIBRARY_API');
    expect(classifyEntryPointTier(withParam, type({ implements: ['Mojo'] }), { language: 'java' })).toBe('TIER_3_LIBRARY_API');
  });

  it('AbstractMojo / Mojo supertypes: execute() is a lifecycle entry', () => {
    expect(classifyEntryPointTier(method('execute'), type({ extends: 'org.apache.maven.plugin.AbstractMojo' }), { language: 'java' })).toBe('TIER_1_ENTRY_POINT');
    expect(classifyEntryPointTier(method('execute'), type({ implements: ['Mojo'] }), { language: 'java' })).toBe('TIER_1_ENTRY_POINT');
    expect(isSupertypeLifecycleMethod('AbstractMojo', 'execute')).toBe(true);
    expect(isSupertypeLifecycleMethod('AbstractMojo', 'getLog')).toBe(false);
  });
});
