/**
 * Java entries from registering files passed in as text: OSGi DS component
 * descriptions, MANIFEST.MF, Eclipse plugin.xml and servlet web.xml. The
 * reader (`scanRegistrations`, `parseXml`), resolution to declarations in
 * `buildJavaGraph` (inherited members, nested types, unresolved names), the
 * `facts@1` rows, and reach: a Java type entry roots its constructors.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { buildJavaGraph, type JavaGraph } from '../../src/navigation/index.js';
import {
  exportedPackageNames,
  manifestHeaders,
  registrationFileKind,
  scanRegistrations,
  type RegistrationFile,
} from '../../src/navigation/java-registrations.js';
import { childText, parseXml, xmlElements } from '../../src/navigation/xml-scan.js';
import { deadCode, reach } from '../../src/graph-facts/index.js';
import { javaGraphFactSet } from '../../src/facts/java-facts.js';
import { FACTS_RELATIONS } from '../../src/facts/schema.js';
import { keyCollisions, tableRows } from '../../src/facts/table.js';
import * as publicApi from '../../src/index.js';

const SOURCES: Record<string, string> = {
  'bundle/src/org/example/ds/Greeter.java': 'package org.example.ds;\n\npublic interface Greeter {\n  String greet();\n}\n',
  'bundle/src/org/example/ds/BaseHandler.java': `package org.example.ds;

public abstract class BaseHandler {
  public void bindEvents(Object events) {}
  public void neverCalled() {}
}
`,
  'bundle/src/org/example/ds/GreeterImpl.java': `package org.example.ds;

public class GreeterImpl extends BaseHandler implements Greeter {
  public GreeterImpl() {}
  protected void activate() {}
  void setLog(Object log) {}
  void unsetLog(Object log) {}
  public String greet() { return helper(); }
  private String helper() { return "hi"; }
}
`,
  'bundle/src/org/example/ds/Outer.java': `package org.example.ds;

public class Outer {
  public static class Inner {
    public Inner() {}
  }
}
`,
  'bundle/src/org/example/Activator.java': `package org.example;

public class Activator {
  public Activator() {}
  public void start(Object context) {}
}
`,
  'bundle/src/org/example/ext/ExportHandler.java': 'package org.example.ext;\n\npublic class ExportHandler {\n  public ExportHandler() {}\n}\n',
  'bundle/src/org/example/ext/App.java': 'package org.example.ext;\n\npublic class App {\n}\n',
  'bundle/src/org/example/api/PublicApi.java': 'package org.example.api;\n\npublic final class PublicApi {\n  public PublicApi() {}\n}\n',
  'bundle/src/org/example/api/Hidden.java': 'package org.example.api;\n\nclass Hidden {\n}\n',
  'bundle/src/org/example/util/Util.java': `package org.example.util;

public class Util {
  public Util() {}
  public static int twice(int x) { return x * 2; }
}
`,
  'bundle/src/org/example/Main.java': `package org.example;

import org.example.util.Util;

public class Main {
  public static void main(String[] args) { Util.twice(2); }
}
`,
  'web/src/org/example/web/MainServlet.java': 'package org.example.web;\n\npublic class MainServlet {\n  public MainServlet() {}\n}\n',
  'web/src/org/example/web/AuthFilter.java': 'package org.example.web;\n\npublic class AuthFilter {\n}\n',
  'web/src/org/example/web/StartupListener.java': 'package org.example.web;\n\npublic class StartupListener {\n}\n',
};

const DS_GREETER = `<?xml version="1.0" encoding="UTF-8"?>
<!-- a component with a <comment> -->
<scr:component xmlns:scr="http://www.osgi.org/xmlns/scr/v1.1.0" name="greeter" modified="reconfigure">
  <implementation class="org.example.ds.GreeterImpl"/>
  <service>
    <provide interface="org.example.ds.Greeter"/>
  </service>
  <reference name="log" interface="org.osgi.service.log.LogService" bind="setLog" unbind="unsetLog"/>
  <reference name="events" interface="x.Events" bind='bindEvents' updated="missingUpdated"/>
</scr:component>
`;

const DS_COMPONENTS = `<components xmlns:scr="http://www.osgi.org/xmlns/scr/v1.2.0">
  <scr:component name="inner" activate="activate">
    <implementation class="org.example.ds.Outer$Inner"/>
  </scr:component>
  <scr:component name="gone">
    <implementation class="org.example.missing.Gone"/>
  </scr:component>
</components>
`;

const MANIFEST = [
  'Manifest-Version: 1.0',
  'Bundle-SymbolicName: org.example;singleton:=true',
  'Bundle-Activator: org.example.Activator',
  'Export-Package: org.example.api;version="1.0.0",',
  ' org.example.empty;x-internal:=true',
  '',
  'Name: second-section',
  'Bundle-Activator: org.example.Ignored',
  '',
].join('\r\n');

const PLUGIN = `<?xml version="1.0" encoding="UTF-8"?>
<?eclipse version="3.4"?>
<plugin>
  <extension-point id="handlers" name="Handlers" schema="schema/handlers.exsd"/>
  <extension point="org.example.handlers">
    <handler class="org.example.ext.ExportHandler:with-data" priority="1"/>
    <handler class="org.example.ext.Missing"/>
  </extension>
  <extension id="app" point="org.eclipse.core.runtime.applications">
    <application>
      <run class="org.example.ext.App"></run>
    </application>
  </extension>
</plugin>
`;

const WEB = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE web-app PUBLIC "-//Sun Microsystems, Inc.//DTD Web Application 2.3//EN" "http://java.sun.com/dtd/web-app_2_3.dtd" [
  <!ENTITY app "example">
]>
<web-app>
  <listener><listener-class>org.example.web.StartupListener</listener-class></listener>
  <filter>
    <filter-name>auth</filter-name>
    <filter-class>
      org.example.web.AuthFilter
    </filter-class>
  </filter>
  <filter-mapping><filter-name>auth</filter-name><url-pattern>/app/*</url-pattern></filter-mapping>
  <servlet>
    <servlet-name>main</servlet-name>
    <servlet-class>org.example.web.MainServlet</servlet-class>
  </servlet>
  <servlet>
    <servlet-name>push</servlet-name>
    <servlet-class>org.external.PushServlet</servlet-class>
  </servlet>
  <servlet-mapping><servlet-name>main</servlet-name><url-pattern>/app/</url-pattern><url-pattern>*.do</url-pattern></servlet-mapping>
</web-app>
`;

const REGISTRATIONS: RegistrationFile[] = [
  { path: 'bundle/OSGI-INF/greeter.xml', text: DS_GREETER },
  { path: 'bundle/OSGI-INF/components.xml', text: DS_COMPONENTS },
  { path: 'bundle/OSGI-INF/metatype/settings.xml', text: '<metatype:MetaData xmlns:metatype="x"><OCD id="a"/></metatype:MetaData>' },
  { path: 'bundle/META-INF/MANIFEST.MF', text: MANIFEST },
  { path: 'bundle/plugin.xml', text: PLUGIN },
  { path: 'web/WEB-INF/web.xml', text: WEB },
  { path: 'bundle/README.md', text: 'not a registering file' },
];

const files = Object.entries(SOURCES).map(([path, code]) => ({ path, code }));
let plain: JavaGraph;
let g: JavaGraph;
let lib: JavaGraph;
let q: Map<string, string>;
let id: Map<string, string>;

beforeAll(async () => {
  plain = await buildJavaGraph(files);
  g = await buildJavaGraph(files, { registrationFiles: REGISTRATIONS });
  lib = await buildJavaGraph(files, { registrationFiles: REGISTRATIONS, exportedPackages: true });
  q = new Map(g.files.flatMap(f => f.decls.map(d => [d.id, d.qualified_name] as const)));
  id = new Map([...q].map(([k, v]) => [v, k]));
}, 60_000);

const rows = (graph: JavaGraph, kinds: readonly string[]): string[] =>
  graph.entries
    .filter(e => kinds.includes(e.kind))
    .map(e => `${e.kind} ${e.certainty} ${q.get(e.id)} [${e.evidence}]${e.method ? ` ${e.method} ${e.path ?? ''}`.trimEnd() : ''}`)
    .sort();

describe('registrationFileKind', () => {
  it('recognises the four kinds by path and nothing else', () => {
    expect(registrationFileKind('b/OSGI-INF/c.xml')).toBe('osgi-ds');
    expect(registrationFileKind('OSGI-INF/l10n/c.xml')).toBe('osgi-ds');
    expect(registrationFileKind('b\\OSGI-INF\\c.xml')).toBe('osgi-ds');
    expect(registrationFileKind('b/OSGI-INF/c.properties')).toBeNull();
    expect(registrationFileKind('b/META-INF/MANIFEST.MF')).toBe('manifest');
    expect(registrationFileKind('b/MANIFEST.MF')).toBeNull();
    expect(registrationFileKind('b/plugin.xml')).toBe('plugin');
    expect(registrationFileKind('b/fragment.xml')).toBe('plugin');
    expect(registrationFileKind('w/WEB-INF/web.xml')).toBe('web');
    expect(registrationFileKind('w/META-INF/web-fragment.xml')).toBe('web');
    expect(registrationFileKind('w/WEB-INF/jetty-web.xml')).toBeNull();
    expect(registrationFileKind('pom.xml')).toBeNull();
  });
});

describe('parseXml', () => {
  it('reads elements, attributes, text, prefixes and positions', () => {
    const [root] = parseXml('<?xml version="1.0"?>\n<!-- c <x/> -->\n<a:root k="v &amp; w" n=\'1\'>\n  <child>t&lt;1&#62;&#x41;&bogus;</child><empty/>\n  <![CDATA[<raw>]]>\n</a:root>');
    expect(root.name).toBe('root');
    expect(root.attrs.get('k')).toBe('v & w');
    expect(root.attrs.get('n')).toBe('1');
    expect(root.line).toBe(3);
    expect(root.col).toBe(0);
    expect(root.children.map(c => c.name)).toEqual(['child', 'empty']);
    expect(childText(root, 'child')).toBe('t<1>A&bogus;');
    expect(root.children[1].line).toBe(4);
    expect(root.children[1].col).toBe(41);
    expect(root.text).toContain('<raw>');
    expect(childText(root, 'missing')).toBeUndefined();
  });

  it('skips a DOCTYPE with an internal subset and closes mismatched tags', () => {
    const roots = parseXml('<!DOCTYPE r [ <!ENTITY e "a>b"> ]><r><a><b></a><c attr/></r>');
    expect(roots).toHaveLength(1);
    expect([...xmlElements(roots)].map(e => e.name)).toEqual(['r', 'a', 'b', 'c']);
    expect(roots[0].children[1].attrs.get('attr')).toBe('');
  });

  it('never throws on malformed input', () => {
    for (const bad of ['<a', '<a b="1', '<!-- open', '<![CDATA[x', '<?pi', '<!DOCTYPE x', '<a></b>', '< a>', '</>', 'text only', '<a b=1>', '<a b c="2"/>']) {
      expect(() => parseXml(bad)).not.toThrow();
    }
    expect(parseXml('< a>')).toEqual([]);
    expect(parseXml('<a b=1>')).toEqual([]);
  });
});

describe('MANIFEST.MF', () => {
  it('joins continuation lines and stops at the main section', () => {
    const h = manifestHeaders(MANIFEST);
    expect(h.get('Bundle-Activator')).toEqual({ value: 'org.example.Activator', line: 3 });
    expect(h.get('Export-Package')?.value).toBe('org.example.api;version="1.0.0",org.example.empty;x-internal:=true');
    expect(h.has('Name')).toBe(false);
  });

  it('reads every package name of Export-Package, quotes respected', () => {
    expect(exportedPackageNames('a.b;c.d;version="[1,2)";uses:="x,y",e.f')).toEqual(['a.b', 'c.d', 'e.f']);
    expect(exportedPackageNames('')).toEqual([]);
  });
});

describe('scanRegistrations', () => {
  it('lists every name with its form, before resolution', () => {
    const scan = scanRegistrations(REGISTRATIONS);
    const got = scan.registrations.map(r => `${r.kind} ${r.source} ${r.className}${r.member ? `#${r.member}` : ''}${r.optional ? ' (optional)' : ''} @${r.file}:${r.line}`);
    expect(got).toEqual([
      'osgi-ds OSGI-INF implementation org.example.ds.GreeterImpl @bundle/OSGI-INF/greeter.xml:4',
      'osgi-ds OSGI-INF modified org.example.ds.GreeterImpl#reconfigure @bundle/OSGI-INF/greeter.xml:3',
      'osgi-ds OSGI-INF activate (default) org.example.ds.GreeterImpl#activate (optional) @bundle/OSGI-INF/greeter.xml:3',
      'osgi-ds OSGI-INF deactivate (default) org.example.ds.GreeterImpl#deactivate (optional) @bundle/OSGI-INF/greeter.xml:3',
      'osgi-ds OSGI-INF bind org.example.ds.GreeterImpl#setLog @bundle/OSGI-INF/greeter.xml:8',
      'osgi-ds OSGI-INF unbind org.example.ds.GreeterImpl#unsetLog @bundle/OSGI-INF/greeter.xml:8',
      'osgi-ds OSGI-INF bind org.example.ds.GreeterImpl#bindEvents @bundle/OSGI-INF/greeter.xml:9',
      'osgi-ds OSGI-INF updated org.example.ds.GreeterImpl#missingUpdated @bundle/OSGI-INF/greeter.xml:9',
      'osgi-ds OSGI-INF implementation org.example.ds.Outer$Inner @bundle/OSGI-INF/components.xml:3',
      'osgi-ds OSGI-INF activate org.example.ds.Outer$Inner#activate @bundle/OSGI-INF/components.xml:2',
      'osgi-ds OSGI-INF deactivate (default) org.example.ds.Outer$Inner#deactivate (optional) @bundle/OSGI-INF/components.xml:2',
      'osgi-ds OSGI-INF implementation org.example.missing.Gone @bundle/OSGI-INF/components.xml:6',
      'osgi-ds OSGI-INF activate (default) org.example.missing.Gone#activate (optional) @bundle/OSGI-INF/components.xml:5',
      'osgi-ds OSGI-INF deactivate (default) org.example.missing.Gone#deactivate (optional) @bundle/OSGI-INF/components.xml:5',
      'lifecycle Bundle-Activator org.example.Activator @bundle/META-INF/MANIFEST.MF:3',
      'extension-point plugin.xml org.example.handlers org.example.ext.ExportHandler @bundle/plugin.xml:6',
      'extension-point plugin.xml org.example.handlers org.example.ext.Missing @bundle/plugin.xml:7',
      'extension-point plugin.xml org.eclipse.core.runtime.applications org.example.ext.App @bundle/plugin.xml:11',
      'lifecycle web.xml listener-class org.example.web.StartupListener @web/WEB-INF/web.xml:6',
      'route web.xml filter-class org.example.web.AuthFilter @web/WEB-INF/web.xml:9',
      'route web.xml servlet-class org.example.web.MainServlet @web/WEB-INF/web.xml:16',
      'route web.xml servlet-class org.example.web.MainServlet @web/WEB-INF/web.xml:16',
      'route web.xml servlet-class org.external.PushServlet @web/WEB-INF/web.xml:20',
    ]);
    expect(scan.exportedPackages).toEqual([
      { name: 'org.example.api', file: 'bundle/META-INF/MANIFEST.MF', line: 4 },
      { name: 'org.example.empty', file: 'bundle/META-INF/MANIFEST.MF', line: 4 },
    ]);
  });

  it('reads fragment.xml and web-fragment.xml under their own names, and skips empty names', () => {
    const scan = scanRegistrations([
      { path: 'f/fragment.xml', text: '<fragment><extension point="p"><x class="a.B"/><y class=""/></extension><extension><z class="a.C"/></extension></fragment>' },
      { path: 'w/META-INF/web-fragment.xml', text: '<web-fragment><servlet><servlet-name>s</servlet-name><servlet-class>a.S</servlet-class></servlet><servlet><servlet-class> </servlet-class></servlet><listener/></web-fragment>' },
      { path: 'd/OSGI-INF/x.xml', text: '<component name="n"><implementation/></component>' },
      { path: 'm/META-INF/MANIFEST.MF', text: 'Bundle-Activator: \nnot a header\n' },
    ]);
    expect(scan.registrations.map(r => `${r.source} ${r.className}${r.method ? ` ${r.method}` : ''}`)).toEqual([
      'fragment.xml p a.B',
      'fragment.xml a.C',
      'web-fragment.xml servlet-class a.S ANY',
    ]);
    expect(scan.exportedPackages).toEqual([]);
  });
});

describe('buildJavaGraph registrationFiles', () => {
  it('without registering files nothing changes', async () => {
    expect(plain.entries.some(e => ['osgi-ds', 'extension-point'].includes(e.kind))).toBe(false);
    const same = await buildJavaGraph(files, { registrationFiles: [] });
    expect(same.entries).toEqual(plain.entries);
  });

  it('roots each named class on its type and each named method on its method', () => {
    expect(rows(g, ['osgi-ds', 'extension-point'])).toEqual([
      'extension-point declared org.example.ext:App [plugin.xml org.eclipse.core.runtime.applications]',
      'extension-point declared org.example.ext:ExportHandler [plugin.xml org.example.handlers]',
      // Inherited from an in-tree superclass: the method DS calls is the superclass's.
      'osgi-ds declared org.example.ds:BaseHandler.bindEvents [OSGI-INF bind]',
      'osgi-ds declared org.example.ds:GreeterImpl [OSGI-INF implementation]',
      'osgi-ds declared org.example.ds:GreeterImpl.setLog [OSGI-INF bind]',
      'osgi-ds declared org.example.ds:GreeterImpl.unsetLog [OSGI-INF unbind]',
      'osgi-ds declared org.example.ds:Outer.Inner [OSGI-INF implementation]',
      // The default lifecycle name, present in the class: conventional.
      'osgi-ds conventional org.example.ds:GreeterImpl.activate [OSGI-INF activate (default)]',
    ].sort());
    const web = rows(g, ['route', 'lifecycle']).filter(r => r.includes('[web.xml') || r.includes('[Bundle-Activator'));
    expect(web).toEqual([
      'lifecycle declared org.example.web:StartupListener [web.xml listener-class]',
      'lifecycle declared org.example:Activator [Bundle-Activator]',
      'route declared org.example.web:AuthFilter [web.xml filter-class] USE /app/*',
      'route declared org.example.web:MainServlet [web.xml servlet-class] ANY *.do',
      'route declared org.example.web:MainServlet [web.xml servlet-class] ANY /app',
    ]);
    const filter = g.entries.find(e => e.evidence === 'web.xml filter-class');
    expect(filter).toMatchObject({ framework: 'servlet', surface: 'middleware', file: 'web/WEB-INF/web.xml', line: 9 });
    expect(g.entries.find(e => e.evidence === 'Bundle-Activator')).toMatchObject({ framework: 'osgi', file: 'bundle/META-INF/MANIFEST.MF', line: 3 });
  });

  it('records every name the tree does not declare, and exports only on request', () => {
    expect(g.unresolvedRegistrations.map(u => `${u.reason} ${u.site.file}:${u.site.line} ${u.evidence}`)).toEqual([
      'manifest-unresolved bundle/OSGI-INF/components.xml:2 OSGI-INF activate: org.example.ds.Outer$Inner#activate is not a method of the class or an in-tree superclass',
      'manifest-unresolved bundle/OSGI-INF/components.xml:6 OSGI-INF implementation: org.example.missing.Gone is not a type in the tree',
      'manifest-unresolved bundle/OSGI-INF/greeter.xml:3 OSGI-INF modified: org.example.ds.GreeterImpl#reconfigure is not a method of the class or an in-tree superclass',
      'manifest-unresolved bundle/OSGI-INF/greeter.xml:9 OSGI-INF updated: org.example.ds.GreeterImpl#missingUpdated is not a method of the class or an in-tree superclass',
      'manifest-unresolved bundle/plugin.xml:7 plugin.xml org.example.handlers: org.example.ext.Missing is not a type in the tree',
      'manifest-unresolved web/WEB-INF/web.xml:20 web.xml servlet-class: org.external.PushServlet is not a type in the tree',
    ]);
    expect(g.entries.some(e => e.kind === 'export')).toBe(false);
    expect(rows(lib, ['export'])).toEqual(['export declared org.example.api:PublicApi [Export-Package]']);
    expect(lib.unresolvedRegistrations.map(u => u.evidence)).toContain('Export-Package: org.example.empty has no public type in the tree');
  });

  it('does not depend on the order the files are given in', async () => {
    const reversed = await buildJavaGraph([...files].reverse(), { registrationFiles: [...REGISTRATIONS].reverse() });
    expect(reversed.entries).toEqual(g.entries);
    expect(reversed.unresolvedRegistrations).toEqual(g.unresolvedRegistrations);
  });

  it('writes the rows into facts@1 entries with no schema change', () => {
    const inputs = files.map(f => ({ ...f, imports: [] }));
    const before = tableRows(FACTS_RELATIONS.entries, javaGraphFactSet(plain, inputs).relations.entries);
    const set = javaGraphFactSet(g, inputs);
    const after = tableRows(FACTS_RELATIONS.entries, set.relations.entries);
    expect(keyCollisions(FACTS_RELATIONS.entries, set.relations.entries)).toBe(0);
    const added = after.map(r => `${String(r[1])} ${String(r[2])} ${String(r[3])}`).filter(r => !before.some(b => `${String(b[1])} ${String(b[2])} ${String(b[3])}` === r));
    expect(new Set(added)).toEqual(new Set([
      'osgi-ds OSGI-INF implementation declared',
      'osgi-ds OSGI-INF bind declared',
      'osgi-ds OSGI-INF unbind declared',
      'osgi-ds OSGI-INF activate (default) conventional',
      'lifecycle Bundle-Activator declared',
      'extension-point plugin.xml org.example.handlers declared',
      'extension-point plugin.xml org.eclipse.core.runtime.applications declared',
      'route web.xml servlet-class declared',
      'route web.xml filter-class declared',
      'lifecycle web.xml listener-class declared',
    ]));
    // One row per (declaration, kind, source): MainServlet's two URL patterns are one fact.
    expect(after.length - before.length).toBe(g.entries.length - plain.entries.length - 1);
    expect(set.duplicatesDropped.entries).toBe(1);
    expect(publicApi.registrationFileKind).toBe(registrationFileKind);
    expect(publicApi.scanRegistrations).toBe(scanRegistrations);
  });
});

describe('reach from registered types', () => {
  it('a registered type roots its constructors; its other members stay unreached', () => {
    const before = Object.fromEntries(deadCode(plain).facts.map(f => [f.qualified_name, f.verdict]));
    const d = deadCode(g);
    const v = Object.fromEntries(d.facts.map(f => [f.qualified_name, f.verdict]));
    expect(before['org.example.ds:GreeterImpl.constructor']).toBe('dead');
    for (const n of ['org.example.ds:GreeterImpl.constructor', 'org.example.ds:Outer.Inner.constructor', 'org.example:Activator.constructor', 'org.example.ext:ExportHandler.constructor', 'org.example.web:MainServlet.constructor']) {
      expect(v[n], n).toBe('live');
    }
    expect(v['org.example.ds:GreeterImpl.setLog']).toBe('live');
    expect(v['org.example.ds:BaseHandler.bindEvents']).toBe('live');
    expect(v['org.example.ds:GreeterImpl.activate']).toBe('live');
    expect(v['org.example.ds:GreeterImpl.greet']).toBe('dead');
    expect(v['org.example.ds:BaseHandler.neverCalled']).toBe('dead');
    // Exported types are roots only when the caller asks for the library's surface.
    expect(v['org.example.api:PublicApi.constructor']).toBe('dead');
    const l = Object.fromEntries(deadCode(lib).facts.map(f => [f.qualified_name, f.verdict]));
    expect(l['org.example.api:PublicApi.constructor']).toBe('live');
    const path = reach(g, { targets: [id.get('org.example.ds:GreeterImpl.constructor') ?? ''] }).facts[0].strong;
    expect(path?.entry).toMatchObject({ kind: 'osgi-ds', id: id.get('org.example.ds:GreeterImpl') });
    expect(path?.steps.map(s => `${s.via} ${q.get(s.decl)}`)).toEqual(['entry org.example.ds:GreeterImpl', 'contains org.example.ds:GreeterImpl.constructor']);
  });

  it('a type only loaded (a static call, no entry) runs no constructor, and an unasked kind roots nothing', () => {
    const v = Object.fromEntries(deadCode(g).facts.map(f => [f.qualified_name, f.verdict]));
    expect(v['org.example.util:Util.twice']).toBe('live');
    expect(v['org.example.util:Util.constructor']).toBe('dead');
    const routesOnly = Object.fromEntries(deadCode(g, { rootKinds: ['route'] }).facts.map(f => [f.qualified_name, f.verdict]));
    expect(routesOnly['org.example.web:MainServlet.constructor']).toBe('live');
    expect(routesOnly['org.example.ds:GreeterImpl.constructor']).toBe('dead');
  });

  it('applies to service-file classes too', async () => {
    const svc = await buildJavaGraph(files, { serviceFiles: [{ path: 'bundle/META-INF/services/org.example.ds.Greeter', text: 'org.example.ext.ExportHandler\n' }] });
    const v = Object.fromEntries(deadCode(svc).facts.map(f => [f.qualified_name, f.verdict]));
    expect(v['org.example.ext:ExportHandler.constructor']).toBe('live');
  });
});
