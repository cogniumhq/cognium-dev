/**
 * #591 — the CLI collects `*.properties` from a directory scan and hands them to
 * circle-ir as `resources`, so a weak algorithm held in a resource file is found.
 */
import { test, expect } from 'bun:test';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { collectResourceFiles } from './cli.js';

function project(): string {
  const root = mkdtempSync(join(tmpdir(), 'cog-res-'));
  mkdirSync(join(root, 'src/main/resources'), { recursive: true });
  mkdirSync(join(root, 'node_modules/dep'), { recursive: true });
  mkdirSync(join(root, 'src/test/resources'), { recursive: true });
  mkdirSync(join(root, 'dist'), { recursive: true });
  writeFileSync(join(root, 'src/main/resources/app.properties'), 'digest.alg=MD5\n');
  writeFileSync(join(root, 'src/main/resources/notes.txt'), 'not a resource');
  writeFileSync(join(root, 'node_modules/dep/x.properties'), 'a=b');
  writeFileSync(join(root, 'src/test/resources/t.properties'), 'a=b');
  writeFileSync(join(root, 'dist/built.properties'), 'a=b');
  return root;
}

test('collectResourceFiles: collects *.properties, skips node_modules and other file types', async () => {
  const root = project();
  try {
    const found = await collectResourceFiles(root, { basePath: root });
    const names = [...found.keys()].map((k) => k.slice(root.length + 1)).sort();
    expect(names).toEqual(['dist/built.properties', 'src/main/resources/app.properties', 'src/test/resources/t.properties']);
    expect(found.get(join(root, 'src/main/resources/app.properties'))).toBe('digest.alg=MD5\n');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('collectResourceFiles: honours --exclude-tests and config exclude patterns', async () => {
  const root = project();
  try {
    const found = await collectResourceFiles(root, { basePath: root, excludeTests: true, excludePatterns: ['dist/**'] });
    const names = [...found.keys()].map((k) => k.slice(root.length + 1)).sort();
    expect(names).toEqual(['src/main/resources/app.properties']);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('collectResourceFiles: a single file target yields only a properties file', async () => {
  const root = project();
  try {
    expect((await collectResourceFiles(join(root, 'src/main/resources/notes.txt'))).size).toBe(0);
    expect((await collectResourceFiles(join(root, 'src/main/resources/app.properties'))).size).toBe(1);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
