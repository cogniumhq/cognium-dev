/**
 * Semver version matching for RustSec advisory version constraints
 * Supports: "1.0.0", "^1.0.0", ">=1.0.0", "<2.0.0", etc.
 */

export interface ParsedVersion {
  major: number;
  minor: number;
  patch: number;
  prerelease?: string;
}

/**
 * Parse a version string into components
 */
export function parseVersion(version: string): ParsedVersion {
  // Remove leading 'v' if present
  const v = version.replace(/^v/, '').trim();

  // Handle prerelease versions
  const [mainPart, prerelease] = v.split('-');
  const parts = mainPart.split('.');

  return {
    major: parseInt(parts[0] ?? '0', 10) || 0,
    minor: parseInt(parts[1] ?? '0', 10) || 0,
    patch: parseInt(parts[2] ?? '0', 10) || 0,
    prerelease,
  };
}

/**
 * Compare two versions
 * Returns: -1 if a < b, 0 if a == b, 1 if a > b
 */
export function compareVersions(a: string, b: string): number {
  const va = parseVersion(a);
  const vb = parseVersion(b);

  if (va.major !== vb.major) return va.major < vb.major ? -1 : 1;
  if (va.minor !== vb.minor) return va.minor < vb.minor ? -1 : 1;
  if (va.patch !== vb.patch) return va.patch < vb.patch ? -1 : 1;

  // Prerelease versions are lower than release
  if (va.prerelease && !vb.prerelease) return -1;
  if (!va.prerelease && vb.prerelease) return 1;
  if (va.prerelease && vb.prerelease) {
    return va.prerelease.localeCompare(vb.prerelease);
  }

  return 0;
}

/**
 * Check if a version satisfies a semver specification
 */
export function semverSatisfies(version: string, spec: string): boolean {
  const trimmedSpec = spec.trim();

  // Handle caret range: ^1.2.3 means >=1.2.3 and <2.0.0
  if (trimmedSpec.startsWith('^')) {
    const specParts = parseVersion(trimmedSpec.slice(1));
    const vParts = parseVersion(version);

    // Major must match (or be higher minor/patch)
    if (vParts.major !== specParts.major) return false;
    if (vParts.minor < specParts.minor) return false;
    if (vParts.minor === specParts.minor && vParts.patch < specParts.patch)
      return false;
    return true;
  }

  // Handle tilde range: ~1.2.3 means >=1.2.3 and <1.3.0
  if (trimmedSpec.startsWith('~')) {
    const specParts = parseVersion(trimmedSpec.slice(1));
    const vParts = parseVersion(version);

    if (vParts.major !== specParts.major) return false;
    if (vParts.minor !== specParts.minor) return false;
    return vParts.patch >= specParts.patch;
  }

  // Handle >= comparison
  if (trimmedSpec.startsWith('>=')) {
    return compareVersions(version, trimmedSpec.slice(2).trim()) >= 0;
  }

  // Handle > comparison
  if (trimmedSpec.startsWith('>') && !trimmedSpec.startsWith('>=')) {
    return compareVersions(version, trimmedSpec.slice(1).trim()) > 0;
  }

  // Handle <= comparison
  if (trimmedSpec.startsWith('<=')) {
    return compareVersions(version, trimmedSpec.slice(2).trim()) <= 0;
  }

  // Handle < comparison
  if (trimmedSpec.startsWith('<') && !trimmedSpec.startsWith('<=')) {
    return compareVersions(version, trimmedSpec.slice(1).trim()) < 0;
  }

  // Handle = comparison (explicit)
  if (trimmedSpec.startsWith('=')) {
    return compareVersions(version, trimmedSpec.slice(1).trim()) === 0;
  }

  // Handle range: "1.0.0 - 2.0.0"
  if (trimmedSpec.includes(' - ')) {
    const [min, max] = trimmedSpec.split(' - ').map((s) => s.trim());
    return (
      compareVersions(version, min) >= 0 && compareVersions(version, max) <= 0
    );
  }

  // Handle wildcard: "*" or "x"
  if (trimmedSpec === '*' || trimmedSpec === 'x') {
    return true;
  }

  // Exact match
  return compareVersions(version, trimmedSpec) === 0;
}

/**
 * Check if a version is in a vulnerable range based on patched/unaffected specs
 */
export function isVersionVulnerable(
  version: string,
  patched?: string[],
  unaffected?: string[]
): boolean {
  // Check if version is unaffected
  if (unaffected) {
    for (const spec of unaffected) {
      if (semverSatisfies(version, spec)) {
        return false; // Not vulnerable - in unaffected range
      }
    }
  }

  // Check if version is patched
  if (patched) {
    for (const spec of patched) {
      if (semverSatisfies(version, spec)) {
        return false; // Not vulnerable - patched version
      }
    }
  }

  // If not in unaffected or patched ranges, it's vulnerable
  return true;
}
