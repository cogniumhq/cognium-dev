/**
 * Public-publication classifier for distribution URLs.
 *
 * Per ADR-008 the registry list is **strict** and **closed**: only
 * well-known Maven Central / Sonatype / Gradle Plugins Portal hosts count
 * as public publication. Corporate Nexus / Artifactory URLs explicitly do
 * NOT promote a module to `library/...`.
 *
 * Rationale: the threat model for `library/<env>` downgrades is "this
 * artifact is exposed to untrusted external callers." Internal-mirror
 * publishing doesn't change the trust boundary.
 */

const PUBLIC_REGISTRY_HOSTS: ReadonlySet<string> = new Set([
  // Maven Central + Sonatype OSSRH
  'repo.maven.apache.org',
  'repo1.maven.org',
  'oss.sonatype.org',
  's01.oss.sonatype.org',
  'central.sonatype.com',
  'central.sonatype.org',
  // Gradle Plugins Portal
  'plugins.gradle.org',
  // Legacy / dormant but still in use
  'jcenter.bintray.com',
]);

/**
 * Return `true` if any of the supplied distribution URLs resolves to a
 * public-registry host. URLs that fail `URL` parsing are ignored.
 */
export function isPubliclyPublished(urls: string[]): boolean {
  for (const u of urls) {
    let host: string;
    try {
      host = new URL(u).hostname.toLowerCase();
    } catch {
      continue;
    }
    if (PUBLIC_REGISTRY_HOSTS.has(host)) return true;
  }
  return false;
}

/** Exposed for tests + the `--profile-explain` reason chain. */
export const PUBLIC_REGISTRY_HOSTS_LIST: ReadonlySet<string> = PUBLIC_REGISTRY_HOSTS;
