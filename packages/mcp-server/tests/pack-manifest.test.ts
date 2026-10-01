/**
 * Packaging — `spec.md` §7's licence gate: "the MIT packages contain no
 * PolyForm file (a packaging test, `npm pack` + manifest diff)".
 *
 * The check is on the tarball manifest, not on the source tree, because what
 * matters is what a user receives from npm. It builds first so `dist` is in
 * the manifest; a pack test against a missing `dist` would pass by asserting
 * nothing.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const pkgRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

interface PackManifest {
  readonly name: string;
  readonly version: string;
  readonly files: ReadonlyArray<{ readonly path: string }>;
}

let manifest: PackManifest;
let paths: string[];

beforeAll(() => {
  if (!existsSync(resolve(pkgRoot, 'dist/index.js'))) {
    execFileSync('npm', ['run', 'build'], { cwd: pkgRoot, stdio: 'pipe' });
  }
  const out = execFileSync('npm', ['pack', '--dry-run', '--json'], { cwd: pkgRoot, stdio: 'pipe' }).toString();
  manifest = (JSON.parse(out) as PackManifest[])[0]!;
  paths = manifest.files.map((f) => f.path);
}, 120_000);

describe('the published tarball', () => {
  it('is the package and version we think it is', () => {
    expect(manifest.name).toBe('@cognium/mcp-server');
    expect(manifest.version).toMatch(/^\d+\.\d+\.\d+/);
  });

  it('carries no PolyForm file', () => {
    const polyform = paths.filter((p) => /polyform/i.test(p));
    expect(polyform, `PolyForm files in an MIT tarball: ${polyform.join(', ')}`).toEqual([]);
  });

  it('declares MIT, and ships exactly one licence file', () => {
    const pkg = JSON.parse(readFileSync(resolve(pkgRoot, 'package.json'), 'utf8')) as { license: string };
    expect(pkg.license).toBe('MIT');

    const licences = paths.filter((p) => /^LICEN[CS]E/i.test(p));
    expect(licences).toEqual(['LICENSE']);
    expect(readFileSync(resolve(pkgRoot, 'LICENSE'), 'utf8')).toContain('MIT License');
  });

  it('ships both the library entry and the bin, which are now separate files', () => {
    expect(paths).toContain('dist/index.js');
    expect(paths).toContain('dist/index.d.ts');
    expect(paths).toContain('dist/bin.js');
  });

  it('has a bin that points at a file the tarball actually contains', () => {
    const pkg = JSON.parse(readFileSync(resolve(pkgRoot, 'package.json'), 'utf8')) as {
      bin: Record<string, string>;
      exports: Record<string, { import?: string; types?: string }>;
    };
    for (const target of Object.values(pkg.bin)) {
      expect(paths, `bin target missing from the tarball: ${target}`).toContain(target);
    }
    // The package's single export must be the library entry, not the bin:
    // importing it used to attach a stdio transport to the host process.
    expect(pkg.exports['.']?.import).toBe('./dist/index.js');
    const exported = pkg.exports['.']?.import?.replace(/^\.\//, '');
    expect(exported).not.toBe(Object.values(pkg.bin)[0]);
  });

  it('ships no test, fixture or source file', () => {
    const strays = paths.filter((p) => /^(tests|src)\//.test(p) || /\.test\./.test(p));
    expect(strays, `unexpected files in the tarball: ${strays.join(', ')}`).toEqual([]);
  });

  it('ships no licence token, key or config file', () => {
    // The top-level MIT LICENSE is expected and asserted above. What must
    // never ship is a *token* file — `cognium license set` writes one named
    // `license` into the config dir — or any key or dotenv file.
    const secrets = paths.filter(
      (p) => /\/(license|licence)$/i.test(p) || /\.pem$|\.key$|(^|\/)\.env/.test(p),
    );
    expect(secrets, `credential-shaped files in the tarball: ${secrets.join(', ')}`).toEqual([]);
  });
});
