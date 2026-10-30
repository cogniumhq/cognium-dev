/**
 * The version a Maven project's own build files declare for a coordinate,
 * and where that declaration comes from.
 *
 * A resolved dependency set says which version the build used; this says
 * which version the POMs ask for, read from the raw POM of a module and its
 * parents found among the POMs the caller supplies. The two differ when a
 * parent's `<dependencyManagement>` or an imported BOM overrides a module's
 * own bump, which is exactly what a dependency fix has to rule out.
 *
 * Origins, in the order Maven applies them:
 *   - `direct` — a literal `<version>` on a `<dependency>` of the module or of
 *     a parent (inherited); an explicit version beats `<dependencyManagement>`;
 *   - `property` — a `${name}` on it, resolved along the module → parent chain;
 *   - `dependencyManagement` — the module's own `<dependencyManagement>`;
 *   - `parent-dependencyManagement` — a parent's in the supplied set;
 *   - `bom` — managed by an imported BOM (`<scope>import</scope>`): the BOM's
 *     content is not in the source tree, so `version` is null unless an
 *     effective POM is supplied;
 *   - `external-parent` — the module names it without a version and its
 *     parent is not in the supplied set (e.g. a framework parent POM);
 *   - `unknown` — named without a version and nothing above explains it.
 * A coordinate no POM in the chain names gives `null` (a plain transitive).
 *
 * Regex-scoped XML reading, like the rest of the SBOM module: comments,
 * `<build>`, `<profiles>` and `<reporting>` are set aside, so plugin
 * dependencies and profile-only declarations are not read. Pure; the caller
 * supplies file text and repository-relative paths.
 */

export type DeclaredOrigin =
  | 'direct'
  | 'property'
  | 'dependencyManagement'
  | 'parent-dependencyManagement'
  | 'bom'
  | 'external-parent'
  | 'unknown';

export interface DeclaredVersion {
  /** The declared version after property resolution, or null when the build files do not say. */
  version: string | null;
  origin: DeclaredOrigin;
  /** Repository-relative path of the POM holding the declaration that decided it. */
  file: string;
  /** The property the version came through, when it was `${…}`. */
  property?: string;
  /** Imported BOMs (`g:a:v`) that may manage the coordinate, in declaration order. */
  boms?: string[];
  /** The parent coordinate, when it is outside the supplied POMs. */
  parent?: string;
}

/** One POM as the caller read it: repository-relative path and text. */
export interface PomFile {
  path: string;
  content: string;
}

interface PomDep {
  name: string;
  version?: string;
  scope?: string;
  type?: string;
}

interface ParsedPom {
  path: string;
  coord: { groupId?: string; artifactId?: string; version?: string };
  parent?: { groupId: string; artifactId: string; version?: string; relativePath: string };
  properties: Map<string, string>;
  dependencies: PomDep[];
  managed: PomDep[];
}

const tag = (block: string, name: string): string | undefined =>
  new RegExp(`<${name}>\\s*([^<]*?)\\s*</${name}>`).exec(block)?.[1];

function stripSection(xml: string, name: string): string {
  return xml.replace(new RegExp(`<${name}>[\\s\\S]*?</${name}>`, 'g'), '');
}

function readDeps(block: string): PomDep[] {
  const out: PomDep[] = [];
  const re = /<dependency>([\s\S]*?)<\/dependency>/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(block)) !== null) {
    const b = m[1];
    const g = tag(b, 'groupId');
    const a = tag(b, 'artifactId');
    if (!g || !a) continue;
    out.push({ name: `${g}:${a}`, version: tag(b, 'version'), scope: tag(b, 'scope'), type: tag(b, 'type') });
  }
  return out;
}

function parsePom(file: PomFile): ParsedPom {
  let xml = file.content.replace(/<!--[\s\S]*?-->/g, '');
  for (const s of ['build', 'profiles', 'reporting']) xml = stripSection(xml, s);

  const managedBlock = /<dependencyManagement>([\s\S]*?)<\/dependencyManagement>/.exec(xml)?.[1] ?? '';
  xml = stripSection(xml, 'dependencyManagement');

  const parentBlock = /<parent>([\s\S]*?)<\/parent>/.exec(xml)?.[1];
  let parent: ParsedPom['parent'];
  if (parentBlock) {
    const g = tag(parentBlock, 'groupId');
    const a = tag(parentBlock, 'artifactId');
    if (g && a) {
      parent = { groupId: g, artifactId: a, version: tag(parentBlock, 'version'), relativePath: tag(parentBlock, 'relativePath') ?? '../pom.xml' };
    }
    xml = stripSection(xml, 'parent');
  }

  const properties = new Map<string, string>();
  const propsBlock = /<properties>([\s\S]*?)<\/properties>/.exec(xml)?.[1];
  if (propsBlock) {
    const re = /<([A-Za-z0-9._-]+)>\s*([^<]*?)\s*<\/\1>/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(propsBlock)) !== null) properties.set(m[1], m[2]);
  }
  xml = stripSection(xml, 'properties');

  const depsBlock = /<dependencies>([\s\S]*?)<\/dependencies>/.exec(xml)?.[1] ?? '';
  const head = stripSection(xml, 'dependencies');
  return {
    path: file.path,
    coord: { groupId: tag(head, 'groupId') ?? parent?.groupId, artifactId: tag(head, 'artifactId'), version: tag(head, 'version') ?? parent?.version },
    parent,
    properties,
    dependencies: readDeps(depsBlock),
    managed: readDeps(managedBlock),
  };
}

/** POSIX-style join and normalisation of repository-relative paths. */
function joinPath(dir: string, rel: string): string {
  const parts = (dir ? `${dir}/${rel}` : rel).split('/');
  const out: string[] = [];
  for (const p of parts) {
    if (p === '' || p === '.') continue;
    if (p === '..') out.pop();
    else out.push(p);
  }
  return out.join('/');
}

const dirOf = (p: string): string => (p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : '');

/**
 * Index of the POMs of one source tree, answering the declared version of a
 * coordinate for any module in it.
 */
export class MavenDeclaredIndex {
  private readonly poms = new Map<string, ParsedPom>();
  private readonly effective?: ParsedPom;

  /**
   * @param poms every POM of the tree, with repository-relative paths
   * @param effectivePom optional `mvn help:effective-pom` output for a module:
   *   used only to fill in a version the raw POMs leave null (a BOM-managed
   *   or external-parent-managed coordinate); the origin still comes from
   *   the raw POMs.
   */
  constructor(poms: PomFile[], effectivePom?: string) {
    for (const p of poms) this.poms.set(joinPath('', p.path), parsePom(p));
    if (effectivePom) this.effective = parsePom({ path: '(effective)', content: effectivePom });
  }

  /** The module POM followed by every ancestor found in the supplied set. */
  private chain(modulePath: string): { chain: ParsedPom[]; externalParent?: string } {
    const chain: ParsedPom[] = [];
    let cur = this.poms.get(joinPath('', modulePath));
    const visited = new Set<string>();
    while (cur && !visited.has(cur.path)) {
      visited.add(cur.path);
      chain.push(cur);
      const parent = cur.parent;
      if (!parent) return { chain };
      const byPath = this.poms.get(joinPath(dirOf(cur.path), parent.relativePath.endsWith('.xml') ? parent.relativePath : `${parent.relativePath}/pom.xml`));
      const matches = (p: ParsedPom | undefined): boolean =>
        !!p && p.coord.artifactId === parent.artifactId && (p.coord.groupId ?? parent.groupId) === parent.groupId;
      let next = matches(byPath) ? byPath : undefined;
      if (!next) for (const p of this.poms.values()) if (matches(p)) { next = p; break; }
      if (!next) return { chain, externalParent: `${parent.groupId}:${parent.artifactId}${parent.version ? `:${parent.version}` : ''}` };
      cur = next;
    }
    return { chain };
  }

  /**
   * The declared version of `name` (`groupId:artifactId`) for the module whose
   * POM is at `modulePath`, or null when no POM in its chain names it.
   */
  declared(modulePath: string, name: string): DeclaredVersion | null {
    const { chain, externalParent } = this.chain(modulePath);
    if (chain.length === 0) return null;
    const module = chain[0];

    const resolve = (raw: string): { version: string | null; property?: string } => {
      const m = /^\$\{([^}]+)\}$/.exec(raw.trim());
      if (!m) return { version: raw.trim() };
      const prop = m[1];
      if (prop === 'project.version' || prop === 'pom.version') {
        return { version: module.coord.version ?? null, property: prop };
      }
      for (const p of chain) {
        const v = p.properties.get(prop);
        if (v !== undefined) return /\$\{/.test(v) ? { version: null, property: prop } : { version: v, property: prop };
      }
      return { version: null, property: prop };
    };

    const boms: string[] = [];
    for (const p of chain) {
      for (const d of p.managed) {
        if (d.scope === 'import' && d.type === 'pom') boms.push(`${d.name}${d.version ? `:${resolve(d.version).version ?? d.version}` : ''}`);
      }
    }
    const fillFromEffective = (r: DeclaredVersion): DeclaredVersion => {
      if (r.version !== null || !this.effective) return r;
      const hit = [...this.effective.dependencies, ...this.effective.managed].find((d) => d.name === name && d.version);
      return hit?.version ? { ...r, version: hit.version } : r;
    };

    // A versioned <dependency> (in the module or inherited from a parent's
    // <dependencies>) beats <dependencyManagement> for that coordinate.
    for (const p of chain) {
      const own = p.dependencies.find((d) => d.name === name && d.version);
      if (!own?.version) continue;
      const r = resolve(own.version);
      return r.property
        ? { version: r.version, origin: 'property', file: p.path, property: r.property }
        : { version: r.version, origin: 'direct', file: p.path };
    }

    for (let i = 0; i < chain.length; i++) {
      const managed = chain[i].managed.find((d) => d.name === name && d.scope !== 'import');
      if (managed?.version) {
        const r = resolve(managed.version);
        return {
          version: r.version,
          origin: i === 0 ? 'dependencyManagement' : 'parent-dependencyManagement',
          file: chain[i].path,
          ...(r.property ? { property: r.property } : {}),
        };
      }
    }

    // Named without a version (or not named at all) and not managed in the tree.
    const namedHere = chain.find((p) => p.dependencies.some((d) => d.name === name));
    if (boms.length > 0 && namedHere) return fillFromEffective({ version: null, origin: 'bom', file: namedHere.path, boms });
    if (externalParent && namedHere) return fillFromEffective({ version: null, origin: 'external-parent', file: namedHere.path, parent: externalParent });
    if (namedHere) return fillFromEffective({ version: null, origin: 'unknown', file: namedHere.path, ...(boms.length ? { boms } : {}) });
    return null;
  }
}
