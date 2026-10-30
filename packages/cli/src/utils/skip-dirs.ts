/**
 * Directories the CLI's tree walkers do not descend into by default (#1025).
 *
 * This is the one list. `scan` / `metrics` (`collectFiles`,
 * `collectResourceFiles`), `sbom` (`collectManifestFiles`) and `deadcode` /
 * `reach` / `entries` (`graph-facts` `walk`) all read it. Every walker also
 * skips names starting with `.`; dot-named entries below are listed so the
 * documented list is complete.
 *
 * Opting back in: the path given on the command line is always read, even when
 * its own name is on the list (`cognium-dev scan ./coverage`). For `scan` and
 * `metrics`, a config `include` pattern that names a skipped directory
 * (`"coverage/**"`, `"**\/vendor/**"`) lets the walk enter it.
 */

/** Third-party code installed by a package manager, and interpreter caches. */
export const DEPENDENCY_DIRECTORIES = [
  'node_modules', 'vendor', 'Pods', 'venv', '.venv', '__pycache__',
] as const;

/** Test-coverage reports: Istanbul / nyc / Jest, lcov HTML, coverage.py HTML. */
export const REPORT_DIRECTORIES = [
  'coverage', '.nyc_output', 'lcov-report', 'htmlcov',
] as const;

/**
 * Compiler and bundler output. Skipped by `sbom`, `deadcode`, `reach` and
 * `entries`, which read build structure. `scan` and `metrics` do read these
 * names: `bin/` often holds hand-written shell scripts and `build/` can be a
 * source package, so skipping them would hide real code from the security
 * scan. Exclude them in config when they only hold output.
 */
export const BUILD_OUTPUT_DIRECTORIES = [
  'dist', 'build', 'out', 'target', 'bin', 'obj',
] as const;

/** Skipped by `scan` and `metrics`: dependencies and generated reports. */
export const SCAN_SKIPPED_DIRECTORIES: readonly string[] = [
  ...DEPENDENCY_DIRECTORIES,
  ...REPORT_DIRECTORIES,
];

/** Skipped by `sbom`, `deadcode`, `reach` and `entries`: the scan list plus build output. */
export const STRUCTURE_SKIPPED_DIRECTORIES: readonly string[] = [
  ...SCAN_SKIPPED_DIRECTORIES,
  ...BUILD_OUTPUT_DIRECTORIES,
];

const scanSkipped = new Set<string>(SCAN_SKIPPED_DIRECTORIES);
const structureSkipped = new Set<string>(STRUCTURE_SKIPPED_DIRECTORIES);

/** True when `scan` / `metrics` skip a directory with this name by default. */
export function isScanSkippedDirectory(name: string): boolean {
  return name.startsWith('.') || scanSkipped.has(name);
}

/** True when `sbom` / `deadcode` / `reach` / `entries` skip a directory with this name. */
export function isStructureSkippedDirectory(name: string): boolean {
  return name.startsWith('.') || structureSkipped.has(name);
}
