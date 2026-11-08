/**
 * Java entry points declared outside Java source (`entry-index@0.1`): the
 * classes and methods a runtime instantiates or calls because a registering
 * file names them. The call graph cannot see these; without them every such
 * class looks unreached.
 *
 * The caller passes the files as text (the library reads none). Recognised by
 * path (`registrationFileKind`):
 *
 * - **OSGi Declarative Services** component descriptions (`OSGI-INF/*.xml`):
 *   each component's `implementation` class (`osgi-ds`), and the methods the
 *   runtime calls by name: `activate` / `deactivate` / `modified` on the
 *   component and `bind` / `unbind` / `updated` on its references
 *   (`declared`), plus the specification's default `activate` / `deactivate`
 *   when the class has them (`conventional`). `provide` interfaces are
 *   contracts, not entries: the implementation is the entry.
 * - **`META-INF/MANIFEST.MF`**: `Bundle-Activator` (`lifecycle`); and the
 *   packages of `Export-Package`, whose public top-level types are `export`
 *   entries only when the caller asks for them (a library's surface).
 * - **Eclipse `plugin.xml` / `fragment.xml`**: every `class` attribute inside
 *   an `<extension>`, any `:data` suffix dropped (`extension-point`, the
 *   source naming the point).
 * - **Servlet `web.xml` / `web-fragment.xml`**: `servlet-class` (`route`, its
 *   `servlet-mapping` URL patterns as paths), `filter-class` (`route`,
 *   middleware) and `listener-class` (`lifecycle`).
 *
 * This module only reads the files. `buildJavaGraph` resolves the names
 * against the tree's declarations (a type for a class name, a method for a
 * member name, looked up through in-tree superclasses) and records a name it
 * cannot resolve as an unresolved registration, never dropping it.
 */

import { joinRoutePath } from './ts-call-edges.js';
import type { EntryCertainty, EntryKind } from './ts-entry-tables.js';
import { childText, parseXml, xmlElements, type XmlElement } from './xml-scan.js';

/** A registering file as the caller read it. */
export interface RegistrationFile {
  /** Repository-relative path, `/`-separated. */
  path: string;
  text: string;
}

export type RegistrationFileKind = 'osgi-ds' | 'manifest' | 'plugin' | 'web';

/** Which kind of registering file `path` is, by its name and directory; `null` for any other file. */
export function registrationFileKind(path: string): RegistrationFileKind | null {
  const p = path.replace(/\\/g, '/');
  const base = p.slice(p.lastIndexOf('/') + 1);
  if (base === 'MANIFEST.MF') return /(^|\/)META-INF\/MANIFEST\.MF$/.test(p) ? 'manifest' : null;
  if (base === 'plugin.xml' || base === 'fragment.xml') return 'plugin';
  if (base === 'web.xml' || base === 'web-fragment.xml') return 'web';
  if (/(^|\/)OSGI-INF\/(?:[^/]+\/)*[^/]+\.xml$/.test(p)) return 'osgi-ds';
  return null;
}

/** One name a registering file gives, before it is resolved. */
export interface Registration {
  kind: EntryKind;
  /**
   * The registration form (`OSGI-INF implementation`, `Bundle-Activator`,
   * `plugin.xml <point>`, `web.xml servlet-class` …): the entry's evidence and
   * its `facts@1` `source`. Never a path or a line, so a moved registration keeps its key.
   */
  source: string;
  certainty: EntryCertainty;
  /** The class as written: a binary (`a.B$C`) or canonical (`a.B.C`) name. */
  className: string;
  /** A method of the class the runtime calls by name. */
  member?: string;
  /** Only an entry when the class has the member; otherwise nothing, not an unresolved name. */
  optional?: boolean;
  framework: string;
  /** Routes: the HTTP method (`ANY` for a servlet, `USE` for a filter). */
  method?: string;
  path?: string;
  surface?: 'middleware';
  file: string;
  /** 1-based line and 0-based column of the registration in its file. */
  line: number;
  col: number;
}

/** A package a bundle exports (`Export-Package`). */
export interface ExportedPackage {
  name: string;
  file: string;
  line: number;
}

export interface RegistrationScan {
  registrations: Registration[];
  exportedPackages: ExportedPackage[];
}

const JAVA_NAME = /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*$/;

/** Read every registering file; files of no known kind are ignored. Deterministic in the input order. */
export function scanRegistrations(files: readonly RegistrationFile[]): RegistrationScan {
  const out: RegistrationScan = { registrations: [], exportedPackages: [] };
  for (const f of files) {
    switch (registrationFileKind(f.path)) {
      case 'osgi-ds': dsComponents(f, out.registrations); break;
      case 'manifest': manifest(f, out); break;
      case 'plugin': pluginExtensions(f, out.registrations); break;
      case 'web': webDescriptor(f, out.registrations); break;
      default: break;
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// OSGi Declarative Services

const DS_COMPONENT_METHODS = ['activate', 'deactivate', 'modified'] as const;
const DS_REFERENCE_METHODS = ['bind', 'unbind', 'updated'] as const;
const DS_DEFAULT_METHODS = ['activate', 'deactivate'] as const;

function dsComponents(f: RegistrationFile, out: Registration[]): void {
  for (const c of xmlElements(parseXml(f.text))) {
    if (c.name !== 'component') continue;
    const impl = c.children.find(x => x.name === 'implementation');
    const cls = impl?.attrs.get('class')?.trim();
    if (!impl || !cls) continue;
    const base = { kind: 'osgi-ds' as const, framework: 'osgi', file: f.path, className: cls };
    out.push({ ...base, source: 'OSGI-INF implementation', certainty: 'declared', line: impl.line, col: impl.col });
    for (const a of DS_COMPONENT_METHODS) {
      const m = c.attrs.get(a)?.trim();
      if (m) out.push({ ...base, source: `OSGI-INF ${a}`, certainty: 'declared', member: m, line: c.line, col: c.col });
    }
    for (const a of DS_DEFAULT_METHODS) {
      if (c.attrs.has(a)) continue;
      out.push({ ...base, source: `OSGI-INF ${a} (default)`, certainty: 'conventional', member: a, optional: true, line: c.line, col: c.col });
    }
    for (const r of c.children) {
      if (r.name !== 'reference') continue;
      for (const a of DS_REFERENCE_METHODS) {
        const m = r.attrs.get(a)?.trim();
        if (m) out.push({ ...base, source: `OSGI-INF ${a}`, certainty: 'declared', member: m, line: r.line, col: r.col });
      }
    }
  }
}

// ---------------------------------------------------------------------------
// MANIFEST.MF

interface Header {
  value: string;
  line: number;
}

/**
 * Main-section headers, keyed by lower-cased name (header names are
 * case-insensitive in a JAR manifest); a line starting with one space
 * continues the previous header.
 */
export function manifestHeaders(text: string): Map<string, Header> {
  const heads = new Map<string, Header>();
  let cur: string | null = null;
  const lines = text.split(/\r\n|\r|\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line === '') {
      if (heads.size > 0) break; // the main section ends at the first blank line
      continue;
    }
    if (line.startsWith(' ')) {
      if (cur !== null) (heads.get(cur) as Header).value += line.slice(1);
      continue;
    }
    const colon = line.indexOf(':');
    if (colon <= 0) { cur = null; continue; }
    cur = line.slice(0, colon).trim().toLowerCase();
    heads.set(cur, { value: line.slice(colon + 1).replace(/^ /, ''), line: i + 1 });
  }
  return heads;
}

/** Split on `sep` outside double quotes. */
function splitOutsideQuotes(v: string, sep: string): string[] {
  const out: string[] = [];
  let cur = '';
  let quoted = false;
  for (const ch of v) {
    if (ch === '"') quoted = !quoted;
    if (ch === sep && !quoted) {
      out.push(cur.trim());
      cur = '';
    } else cur += ch;
  }
  out.push(cur.trim());
  return out.filter(s => s !== '');
}

/** The package names of an `Export-Package` value (`a;b;version="1"` exports `a` and `b`). */
export function exportedPackageNames(value: string): string[] {
  const out: string[] = [];
  for (const clause of splitOutsideQuotes(value, ',')) {
    for (const part of splitOutsideQuotes(clause, ';')) {
      if (part.includes('=')) continue; // an attribute or a directive
      if (JAVA_NAME.test(part)) out.push(part);
    }
  }
  return out;
}

function manifest(f: RegistrationFile, out: RegistrationScan): void {
  const h = manifestHeaders(f.text);
  const activator = h.get('bundle-activator');
  const cls = activator?.value.trim();
  if (activator && cls) {
    out.registrations.push({ kind: 'lifecycle', source: 'Bundle-Activator', certainty: 'declared', className: cls, framework: 'osgi', file: f.path, line: activator.line, col: 0 });
  }
  const exp = h.get('export-package');
  if (exp) for (const name of exportedPackageNames(exp.value)) out.exportedPackages.push({ name, file: f.path, line: exp.line });
}

// ---------------------------------------------------------------------------
// Eclipse plugin.xml / fragment.xml

function pluginExtensions(f: RegistrationFile, out: Registration[]): void {
  const base = f.path.slice(f.path.lastIndexOf('/') + 1);
  for (const root of parseXml(f.text)) {
    for (const ext of root.children) {
      if (ext.name !== 'extension') continue;
      const point = ext.attrs.get('point')?.trim() ?? '';
      // Only `class` attributes name an entry. Other class-valued attributes some points
      // define (`contributorClass`, `defaultHandler`, `launcher` …) are not read.
      for (const el of xmlElements([ext])) {
        const raw = el.attrs.get('class');
        if (raw === undefined) continue;
        const cls = raw.split(':')[0].trim();
        if (!cls) continue;
        out.push({ kind: 'extension-point', source: `${base} ${point}`.trim(), certainty: 'declared', className: cls, framework: 'eclipse', file: f.path, line: el.line, col: el.col });
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Servlet web.xml / web-fragment.xml

function urlPatterns(roots: readonly XmlElement[], mapping: string, nameTag: string): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const root of roots) {
    for (const m of root.children) {
      if (m.name !== mapping) continue;
      const name = childText(m, nameTag);
      if (!name) continue;
      const list = out.get(name) ?? [];
      for (const u of m.children) if (u.name === 'url-pattern' && u.text.trim()) list.push(u.text.trim());
      out.set(name, list);
    }
  }
  return out;
}

function webDescriptor(f: RegistrationFile, out: Registration[]): void {
  const base = f.path.slice(f.path.lastIndexOf('/') + 1);
  const roots = parseXml(f.text);
  const servletPaths = urlPatterns(roots, 'servlet-mapping', 'servlet-name');
  const filterPaths = urlPatterns(roots, 'filter-mapping', 'filter-name');
  for (const root of roots) {
    for (const el of root.children) {
      const tag = el.name === 'servlet' ? 'servlet-class' : el.name === 'filter' ? 'filter-class' : el.name === 'listener' ? 'listener-class' : null;
      if (!tag) continue;
      const clsEl = el.children.find(x => x.name === tag);
      const cls = clsEl?.text.trim();
      if (!clsEl || !cls) continue;
      const at = { file: f.path, line: clsEl.line, col: clsEl.col, className: cls, framework: 'servlet', certainty: 'declared' as const, source: `${base} ${tag}` };
      if (el.name === 'listener') {
        out.push({ ...at, kind: 'lifecycle' });
        continue;
      }
      const name = childText(el, el.name === 'servlet' ? 'servlet-name' : 'filter-name') ?? '';
      const paths = [...new Set((el.name === 'servlet' ? servletPaths : filterPaths).get(name) ?? [])];
      const route = el.name === 'servlet' ? { method: 'ANY' } : { method: 'USE', surface: 'middleware' as const };
      if (paths.length === 0) out.push({ ...at, kind: 'route', ...route });
      // An extension mapping (`*.do`) is kept as written; a path mapping is normalised like `@WebServlet` paths.
      for (const p of paths) out.push({ ...at, kind: 'route', ...route, path: p.startsWith('*.') ? p : joinRoutePath([p]) });
    }
  }
}
