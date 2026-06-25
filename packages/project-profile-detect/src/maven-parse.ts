/**
 * Minimal `pom.xml` parser for project-profile detection.
 *
 * Extracts: `<groupId>`, `<artifactId>`, `<version>`, `<packaging>`,
 * plugins by `<artifactId>` (spring-boot-maven-plugin, maven-plugin-plugin,
 * exec-maven-plugin, …), and `<distributionManagement>` repository URLs.
 *
 * Regex-based — we don't want a runtime dependency on an XML library and
 * the surface we need is tiny. Best-effort: malformed POMs return whatever
 * fields parsed successfully.
 */

import type { BuildModule, MavenParentRef, ModuleSignals } from './types.js';

const TAG = (name: string) => new RegExp(`<${name}\\b[^>]*>([\\s\\S]*?)<\\/${name}>`, 'i');
const ALL_TAGS = (name: string) => new RegExp(`<${name}\\b[^>]*>([\\s\\S]*?)<\\/${name}>`, 'gi');

function firstTag(xml: string, name: string): string | undefined {
  const m = TAG(name).exec(xml);
  return m?.[1].trim();
}

function allTags(xml: string, name: string): string[] {
  const out: string[] = [];
  let m: RegExpExecArray | null;
  const re = ALL_TAGS(name);
  while ((m = re.exec(xml)) !== null) out.push(m[1].trim());
  return out;
}

/**
 * Map Maven plugin `<artifactId>` to the generic plugin tag used by the
 * resolver. Unknown plugin artifactIds are ignored.
 */
const MAVEN_PLUGIN_MAP: Record<string, string> = {
  'spring-boot-maven-plugin': 'spring-boot',
  'maven-plugin-plugin':      'maven-plugin',
  'maven-war-plugin':         'war',
  'maven-ear-plugin':         'ear',
  'maven-shade-plugin':       'application',
  'exec-maven-plugin':        'application',
  'maven-assembly-plugin':    'application',
};

/**
 * Plugins that, by their mere presence, imply public-registry publication.
 * Each maps to a canonical URL whose host is on `PUBLIC_REGISTRY_HOSTS`, so
 * `isPubliclyPublished` fires without requiring a `<distributionManagement>`
 * block. Modern Maven projects (e.g. langchain4j) deploy via
 * `central-publishing-maven-plugin` and omit the legacy block entirely.
 */
const MAVEN_PUBLISH_PLUGIN_URLS: Record<string, string> = {
  'central-publishing-maven-plugin': 'https://central.sonatype.com/',
  'nexus-staging-maven-plugin':      'https://oss.sonatype.org/',
};

/**
 * Parse a `pom.xml` into a `BuildModule`. `directorySignals` is supplied
 * by the walker (JPMS, SPI, main-method presence) and merged into the
 * returned module's `signals`.
 */
export function parseMavenPom(
  xml: string,
  moduleRoot: string,
  buildFile: string,
  directorySignals: ModuleSignals,
): BuildModule {
  // Extract the parent block (if any) before stripping. The inheritance
  // pass (`maven-inherit.ts`) consumes `parentRef` to walk the parent
  // chain and merge inherited signals.
  const parentRef = extractParentRef(xml);

  // Strip the parent block so its <groupId>/<version> don't shadow the
  // module's own coordinates.
  const stripped = xml.replace(/<parent\b[\s\S]*?<\/parent>/i, '');

  const groupId    = firstTag(stripped, 'groupId');
  const artifactId = firstTag(stripped, 'artifactId');
  const version    = firstTag(stripped, 'version');
  const packaging  = firstTag(stripped, 'packaging');

  // Plugins live under <build><plugins><plugin>…</plugin>. Look at the
  // first <build> block.
  const buildBlock = firstTag(xml, 'build') ?? '';
  const pluginBlocks = allTags(buildBlock, 'plugin');
  const plugins = new Set<string>();
  const publishUrls = new Set<string>();
  for (const p of pluginBlocks) {
    const aid = firstTag(p, 'artifactId');
    if (!aid) continue;
    if (MAVEN_PLUGIN_MAP[aid]) plugins.add(MAVEN_PLUGIN_MAP[aid]);
    if (MAVEN_PUBLISH_PLUGIN_URLS[aid]) publishUrls.add(MAVEN_PUBLISH_PLUGIN_URLS[aid]);
  }
  // Spring Boot detection via parent (<parent><artifactId>spring-boot-starter-parent</artifactId>…).
  if (/<parent\b[\s\S]*?<artifactId>\s*spring-boot-starter-parent\s*<\/artifactId>/i.test(xml)) {
    plugins.add('spring-boot');
  }
  // Packaging → plugin tag normalization for downstream resolver.
  if (packaging === 'war') plugins.add('war');
  if (packaging === 'ear') plugins.add('ear');
  if (packaging === 'maven-plugin') plugins.add('maven-plugin');

  // <distributionManagement> repository URLs (snapshot + release).
  const distBlock = firstTag(xml, 'distributionManagement') ?? '';
  const urls = [
    ...allTags(distBlock, 'url'),
    ...publishUrls,
  ].map(u => u.trim()).filter(Boolean);

  const signals: ModuleSignals = {
    ...directorySignals,
    plugins: [...directorySignals.plugins, ...plugins],
    packaging,
    distributionUrls: [...directorySignals.distributionUrls, ...urls],
  };

  return {
    root: moduleRoot,
    buildSystem: 'maven',
    buildFile,
    groupId,
    artifactId,
    version,
    signals,
    parentRef,
  };
}

/**
 * Extract the `<parent>` element into a `MavenParentRef`, distinguishing:
 *  - tag absent              → returns `undefined`
 *  - `<relativePath/>` empty → returned ref carries `emptyRelativePath: true`
 *  - `<relativePath>foo</…>` → returned ref carries `relativePath: 'foo'`
 *  - no `<relativePath>`     → returned ref carries `relativePath: undefined`,
 *                              `emptyRelativePath: false` (caller defaults
 *                              to `../pom.xml` per Maven convention)
 */
function extractParentRef(xml: string): MavenParentRef | undefined {
  const block = TAG('parent').exec(xml);
  if (!block) return undefined;
  const inner = block[1];

  const groupId    = firstTag(inner, 'groupId');
  const artifactId = firstTag(inner, 'artifactId');
  const version    = firstTag(inner, 'version');

  // Detect self-closing or empty <relativePath/> separately from a missing
  // tag (Maven's "don't walk the workspace" signal).
  let relativePath: string | undefined;
  let emptyRelativePath = false;
  const selfClosing = /<relativePath\b[^>]*\/\s*>/i.test(inner);
  if (selfClosing) {
    emptyRelativePath = true;
  } else {
    const rp = firstTag(inner, 'relativePath');
    if (rp !== undefined) {
      if (rp.length === 0) emptyRelativePath = true;
      else relativePath = rp;
    }
  }

  return { groupId, artifactId, version, relativePath, emptyRelativePath };
}
