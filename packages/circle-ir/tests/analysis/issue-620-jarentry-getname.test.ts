/**
 * cognium-dev#620 — `JarEntry.getName()` is an archive-entry source, the
 * same as `ZipEntry.getName()`. A declared `JarEntry` whose name is not the
 * `entry` heuristic does not match the `ZipEntry` row.
 *
 * SAST regression fixtures — the vulnerable handlers are deliberate.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('cognium-dev#620 — JarEntry.getName is a zip-slip source', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('JarEntry.getName() flowing directly into new File(dir, name) is path_traversal', async () => {
    const code = `
import java.io.*;
import java.util.jar.*;
public class Unjar {
  public void unjar(JarInputStream jis, File destDir) throws Exception {
    JarEntry item = jis.getNextJarEntry();
    File outFile = new File(destDir, item.getName());
    new FileOutputStream(outFile);
  }
}
`;
    const r = await analyze(code, 'Unjar.java', 'java');
    const pt = (r.taint.flows ?? []).filter((f) => f.sink_type === 'path_traversal');
    expect(pt.length).toBeGreaterThanOrEqual(1);
  });

  it('JarEntry.getName() stored in a local then passed to new File is path_traversal', async () => {
    const code = `
import java.io.*;
import java.util.jar.*;
public class UnjarHelper {
  public void unjar(JarInputStream jis, File destDir) throws Exception {
    JarEntry item = jis.getNextJarEntry();
    String name = item.getName();
    File outFile = new File(destDir, name);
  }
}
`;
    const r = await analyze(code, 'UnjarHelper.java', 'java');
    const pt = (r.taint.flows ?? []).filter((f) => f.sink_type === 'path_traversal');
    expect(pt.length).toBeGreaterThanOrEqual(1);
  });

  it('File.getName() is not an archive source', async () => {
    const code = `
import java.io.*;
public class SafeName {
  public void copy(File destDir) throws Exception {
    File base = new File("/tmp/safe.txt");
    File outFile = new File(destDir, base.getName());
    new FileOutputStream(outFile);
  }
}
`;
    const r = await analyze(code, 'SafeName.java', 'java');
    const pt = (r.taint.flows ?? []).filter((f) => f.sink_type === 'path_traversal');
    expect(pt.length).toBe(0);
  });
});
