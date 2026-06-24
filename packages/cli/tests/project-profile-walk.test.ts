/**
 * Unit tests for the filesystem walker (3.106.0, #169).
 * Builds a temporary directory tree on disk and validates
 * `discoverBuildModules`, `enumerateScanFiles`, and `ownerOf`.
 *
 * Pillar I: no LLM identifiers.
 */

import { describe, test, expect, beforeAll, afterAll } from 'bun:test';
import { mkdir, writeFile, rm } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import {
  discoverBuildModules,
  enumerateScanFiles,
  ownerOf,
} from '../src/project-profile-detect/walk.js';

let tmpRoot: string;

beforeAll(async () => {
  tmpRoot = join(tmpdir(), `cognium-walk-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  await mkdir(tmpRoot, { recursive: true });

  // Top-level Maven module.
  await writeFile(join(tmpRoot, 'pom.xml'), '<project><artifactId>root</artifactId></project>');
  await mkdir(join(tmpRoot, 'src', 'main', 'java', 'com', 'example'), { recursive: true });
  await writeFile(
    join(tmpRoot, 'src', 'main', 'java', 'com', 'example', 'Main.java'),
    'public class Main { public static void main(String[] args) {} }',
  );

  // Nested Gradle submodule.
  await mkdir(join(tmpRoot, 'sub', 'src', 'main', 'java'), { recursive: true });
  await writeFile(join(tmpRoot, 'sub', 'build.gradle'), `plugins { id 'java-library' }`);
  await writeFile(join(tmpRoot, 'sub', 'src', 'main', 'java', 'Lib.java'), 'public class Lib {}');

  // Nested Kotlin-DSL submodule with JPMS module-info and SPI.
  await mkdir(join(tmpRoot, 'kts', 'src', 'main', 'java'), { recursive: true });
  await mkdir(join(tmpRoot, 'kts', 'src', 'main', 'resources', 'META-INF', 'services'), { recursive: true });
  await writeFile(join(tmpRoot, 'kts', 'build.gradle.kts'), `plugins { id("java-library") }`);
  await writeFile(join(tmpRoot, 'kts', 'src', 'main', 'java', 'module-info.java'), 'module foo.bar {}');
  await writeFile(
    join(tmpRoot, 'kts', 'src', 'main', 'resources', 'META-INF', 'services', 'com.example.Provider'),
    'com.example.ProviderImpl\n',
  );

  // SKIP_DIRS should be skipped.
  await mkdir(join(tmpRoot, 'node_modules', 'inner'), { recursive: true });
  await writeFile(join(tmpRoot, 'node_modules', 'inner', 'ignored.java'), 'public class Ignored {}');
  await mkdir(join(tmpRoot, 'target'), { recursive: true });
  await writeFile(join(tmpRoot, 'target', 'ignored.class'), 'binary');

  // Orphan file outside any module.
  await mkdir(join(tmpRoot, 'orphan'), { recursive: true });
  await writeFile(join(tmpRoot, 'orphan', 'Loose.java'), 'public class Loose {}');
});

afterAll(async () => {
  await rm(tmpRoot, { recursive: true, force: true });
});

describe('discoverBuildModules', () => {
  test('finds the three build files (Maven + Gradle + Kotlin DSL)', async () => {
    const mods = await discoverBuildModules(tmpRoot);
    expect(mods.length).toBe(3);
    const systems = mods.map(m => m.buildSystem).sort();
    expect(systems).toEqual(['gradle', 'gradle-kts', 'maven']);
  });

  test('Maven module gets hasMainMethod=true from src/main/java scan', async () => {
    const mods = await discoverBuildModules(tmpRoot);
    const maven = mods.find(m => m.buildSystem === 'maven')!;
    expect(maven.signals.hasMainMethod).toBe(true);
  });

  test('Kotlin-DSL module gets hasJpmsModuleInfo + hasSpiServices', async () => {
    const mods = await discoverBuildModules(tmpRoot);
    const kts = mods.find(m => m.buildSystem === 'gradle-kts')!;
    expect(kts.signals.hasJpmsModuleInfo).toBe(true);
    expect(kts.signals.hasSpiServices).toBe(true);
  });

  test('skips node_modules and target', async () => {
    const mods = await discoverBuildModules(tmpRoot);
    for (const m of mods) {
      expect(m.root).not.toContain('node_modules');
      expect(m.root).not.toContain('target');
    }
  });
});

describe('enumerateScanFiles', () => {
  test('returns all regular files except those in SKIP_DIRS', async () => {
    const files = await enumerateScanFiles(tmpRoot);
    // Should include source files.
    expect(files.some(f => f.endsWith('Main.java'))).toBe(true);
    expect(files.some(f => f.endsWith('Lib.java'))).toBe(true);
    expect(files.some(f => f.endsWith('Loose.java'))).toBe(true);
    // Should NOT include skipped dirs.
    expect(files.some(f => f.includes('node_modules'))).toBe(false);
    expect(files.some(f => f.includes('/target/'))).toBe(false);
  });
});

describe('ownerOf', () => {
  test('returns the deepest matching module', async () => {
    const mods = await discoverBuildModules(tmpRoot);
    const subFile = join(tmpRoot, 'sub', 'src', 'main', 'java', 'Lib.java');
    const owner = ownerOf(subFile, mods);
    expect(owner?.root).toBe(join(tmpRoot, 'sub'));
  });

  test('returns the parent module when no deeper one matches', async () => {
    const mods = await discoverBuildModules(tmpRoot);
    const mainFile = join(tmpRoot, 'src', 'main', 'java', 'com', 'example', 'Main.java');
    const owner = ownerOf(mainFile, mods);
    expect(owner?.root).toBe(tmpRoot);
  });

  test('returns undefined for files outside any module root', () => {
    expect(ownerOf('/nowhere/Foo.java', [])).toBeUndefined();
  });
});
