/**
 * End-to-end orchestrator tests for `detectProjectProfiles` (3.106.0, #169).
 *
 * Tests the three-tier resolution: glob overrides > forced profile >
 * owner-module-driven detection > unknown. Pillar I: no LLM identifiers.
 */

import { describe, test, expect, beforeAll, afterAll } from 'bun:test';
import { mkdir, writeFile, rm } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { detectProjectProfiles } from '../src/index.js';

let tmpRoot: string;

beforeAll(async () => {
  tmpRoot = join(tmpdir(), `cognium-detect-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  await mkdir(tmpRoot, { recursive: true });

  // Module A: spring-boot → server.
  await mkdir(join(tmpRoot, 'svc', 'src', 'main', 'java'), { recursive: true });
  await writeFile(join(tmpRoot, 'svc', 'pom.xml'), `<project>
    <parent>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-parent</artifactId>
      <version>3.2.0</version>
    </parent>
    <artifactId>svc</artifactId>
  </project>`);
  await writeFile(join(tmpRoot, 'svc', 'src', 'main', 'java', 'App.java'), 'public class App {}');

  // Module B: java-library published to Maven Central → library.
  await mkdir(join(tmpRoot, 'lib', 'src', 'main', 'java'), { recursive: true });
  await writeFile(join(tmpRoot, 'lib', 'build.gradle'), `
plugins { id 'java-library' }
publishing {
  repositories {
    maven { url = uri('https://repo1.maven.org/maven2/') }
  }
}`);
  await writeFile(join(tmpRoot, 'lib', 'src', 'main', 'java', 'Lib.java'), 'public class Lib {}');

  // Module C: java-library NOT publicly published → application (hybrid).
  await mkdir(join(tmpRoot, 'internal', 'src', 'main', 'java'), { recursive: true });
  await writeFile(join(tmpRoot, 'internal', 'build.gradle'), `plugins { id 'java-library' }`);
  await writeFile(join(tmpRoot, 'internal', 'src', 'main', 'java', 'Helper.java'), 'public class Helper {}');

  // Test file under svc/ — env should be 'test' regardless of module env.
  await mkdir(join(tmpRoot, 'svc', 'src', 'test', 'java'), { recursive: true });
  await writeFile(join(tmpRoot, 'svc', 'src', 'test', 'java', 'AppTest.java'), 'public class AppTest {}');

  // Orphan file outside any module.
  await mkdir(join(tmpRoot, 'orphan'), { recursive: true });
  await writeFile(join(tmpRoot, 'orphan', 'Loose.java'), 'public class Loose {}');
});

afterAll(async () => {
  await rm(tmpRoot, { recursive: true, force: true });
});

describe('detectProjectProfiles — owner-module-driven resolution', () => {
  test('spring-boot module → server/<env>', async () => {
    const r = await detectProjectProfiles(tmpRoot);
    const f = join(tmpRoot, 'svc', 'src', 'main', 'java', 'App.java');
    expect(r.profileByFile.get(f)).toBe('server/production');
  });

  test('publicly published java-library → library/<env>', async () => {
    const r = await detectProjectProfiles(tmpRoot);
    const f = join(tmpRoot, 'lib', 'src', 'main', 'java', 'Lib.java');
    expect(r.profileByFile.get(f)).toBe('library/production');
  });

  test('internal java-library (no public publication) → application/<env>', async () => {
    const r = await detectProjectProfiles(tmpRoot);
    const f = join(tmpRoot, 'internal', 'src', 'main', 'java', 'Helper.java');
    expect(r.profileByFile.get(f)).toBe('application/production');
  });

  test('per-file env axis overrides module env (test file under spring-boot module)', async () => {
    const r = await detectProjectProfiles(tmpRoot);
    const f = join(tmpRoot, 'svc', 'src', 'test', 'java', 'AppTest.java');
    expect(r.profileByFile.get(f)).toBe('server/test');
  });

  test('file outside any module → unknown', async () => {
    const r = await detectProjectProfiles(tmpRoot);
    const f = join(tmpRoot, 'orphan', 'Loose.java');
    expect(r.profileByFile.get(f)).toBe('unknown');
    expect(r.unknownFiles).toContain(f);
  });

  test('modules array contains resolved metadata with reasons', async () => {
    const r = await detectProjectProfiles(tmpRoot);
    expect(r.modules.length).toBe(3);
    const svc = r.modules.find(m => m.module.root.endsWith('/svc'));
    // Module-level env is derived from the module root directory, which
    // does NOT contain `src/main/`, so it resolves to `dev`. Per-file env
    // (e.g. `server/production` for files under src/main/) is computed
    // separately during the file → profile mapping.
    expect(svc?.profile).toBe('server/dev');
    expect(svc?.reasons.join(',')).toContain('spring-boot');
  });
});

describe('detectProjectProfiles — forced profile', () => {
  test('forced profile applies to all in-module files but env is path-derived', async () => {
    const r = await detectProjectProfiles(tmpRoot, { forcedProfile: 'cli/production' });
    const main = join(tmpRoot, 'svc', 'src', 'main', 'java', 'App.java');
    const test = join(tmpRoot, 'svc', 'src', 'test', 'java', 'AppTest.java');
    expect(r.profileByFile.get(main)).toBe('cli/production');
    expect(r.profileByFile.get(test)).toBe('cli/test');
  });
});

describe('detectProjectProfiles — glob overrides', () => {
  test('overrides win over detection', async () => {
    const r = await detectProjectProfiles(tmpRoot, {
      overrides: {
        'svc/**/*.java': 'library/dev',
      },
    });
    const f = join(tmpRoot, 'svc', 'src', 'main', 'java', 'App.java');
    expect(r.profileByFile.get(f)).toBe('library/dev');
  });

  test('overrides win even over forced profile', async () => {
    const r = await detectProjectProfiles(tmpRoot, {
      forcedProfile: 'cli/production',
      overrides: { 'svc/**/*.java': 'library/dev' },
    });
    const f = join(tmpRoot, 'svc', 'src', 'main', 'java', 'App.java');
    expect(r.profileByFile.get(f)).toBe('library/dev');
  });

  test('explicit "unknown" override masks detection', async () => {
    const r = await detectProjectProfiles(tmpRoot, {
      overrides: { 'svc/**': 'unknown' },
    });
    const f = join(tmpRoot, 'svc', 'src', 'main', 'java', 'App.java');
    expect(r.profileByFile.get(f)).toBe('unknown');
  });
});

describe('detectProjectProfiles — Pillar I guard', () => {
  test('no resolved-module reason contains LLM-themed identifier', async () => {
    const r = await detectProjectProfiles(tmpRoot);
    for (const m of r.modules) {
      for (const reason of m.reasons) {
        expect(reason).not.toMatch(/llm|ai|verify/i);
      }
    }
  });
});
