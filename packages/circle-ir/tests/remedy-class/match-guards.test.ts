import { describe, it, expect } from 'vitest';
import { analyzeProject, deriveBranchFacts, pathSetDiff, remedyClassOf, loadSafeConstructTable } from '../../src/index.js';
import type { BranchFact, RemedyClassResult } from '../../src/index.js';

/* Synthetic tables and Java written for these tests (safe-construct-table@0.1 vocabulary). */

const HEAD = (cwe: number): string => `format: safe-construct-table@0.1
check-set: example/java
cwe: ${cwe}
cwe-list-version: '4.20'
language: java
version: 1.0.0
settles: signal
sources:
  doc:
    kind: vendor-docs
    publisher: Example
    title: Example API notes
    url: https://example.org/api
    fetched: '2026-10-29'
    quote: Example.
`;

const PATH_TABLE = `${HEAD(22)}
sinks:
  - id: build
    call: { type: java.nio.file.Path, methods: [of, resolve], arg: 0 }
  - id: io
    call: { type: java.nio.file.Files, static: true, methods: [readAllBytes, readString], arg: 0 }
constructs:
  - id: S22-1
    class: safe
    remedy-class: canonicalize-then-contain
    applies-to: [build, io]
    match:
      all:
        - { name: n, any: [ { call: { type: java.nio.file.Path, methods: [normalize, toRealPath] }, role: normalizer } ] }
        - { name: g, call: { type: java.nio.file.Path, methods: [startsWith], arg: 0 }, arg-is: untainted, role: guard, on: true }
        - { order: [n, g] }
    level: SHOULD
    basis: cited
    sources: [doc]
  - id: S22-2
    class: safe
    remedy-class: value-allowlist
    applies-to: [build, io]
    match: { call: { type: java.lang.Object, methods: ["*"], arg: 0 }, arg-is: from-allowlist, role: sink-replacement }
    level: SHOULD
    basis: cited
    sources: [doc]
  - id: W22-1
    class: weak
    remedy-class: canonicalize-then-contain
    applies-to: [build, io]
    match:
      all:
        - { call: { type: java.nio.file.Path, methods: [normalize, toRealPath] }, role: normalizer }
        - { missing: { call: { type: java.lang.Object, methods: [startsWith] }, role: guard } }
    level: SHOULD
    basis: own
    sources: [doc]
  - id: W22-2
    class: weak
    remedy-class: canonicalize-then-contain
    applies-to: [build, io]
    match:
      all:
        - { call: { type: java.lang.String, methods: [startsWith], arg: 0 }, role: guard, on: true }
        - { missing: { call: { type: java.nio.file.Path, methods: [normalize, toRealPath] }, role: normalizer } }
    level: SHOULD
    basis: own
    sources: [doc]
`;

const FILE = 'src/main/java/demo/Reader.java';
const cls = (body: string): string => `package demo;
import java.nio.file.*;
import javax.servlet.http.*;
public class Reader {
  private final Path base = Path.of("/srv/data");
  public byte[] read(HttpServletRequest req) throws Exception {
    String name = req.getParameter("name");
${body}
  }
}`;

const BASE = cls(`    return Files.readAllBytes(base.resolve(name));`);
const CONTAINED = cls(`    Path p = base.resolve(name).normalize();
    if (!p.startsWith(base)) {
      throw new IllegalArgumentException("outside");
    }
    return Files.readAllBytes(p);`);
const INVERTED = cls(`    Path p = base.resolve(name).normalize();
    if (p.startsWith(base)) {
      throw new IllegalArgumentException("inside");
    }
    return Files.readAllBytes(p);`);
const STRING_PREFIX = cls(`    String raw = "/srv/data/" + name;
    if (!raw.startsWith("/srv/data/")) {
      throw new IllegalArgumentException("outside");
    }
    return Files.readAllBytes(Path.of(raw));`);
const CHOSEN = cls(`    String file;
    switch (name) {
      case "terms": file = "terms.txt"; break;
      case "privacy": file = "privacy.txt"; break;
      default: throw new IllegalArgumentException("unknown");
    }
    return Files.readAllBytes(base.resolve(file));`);
const ONE_LITERAL = cls(`    String file = "terms.txt";
    if (name.isEmpty()) {
      throw new IllegalArgumentException("empty");
    }
    return Files.readAllBytes(base.resolve(file));`);

async function observe(before: string, after: string, withBranches = true): Promise<RemedyClassResult> {
  const b = await analyzeProject([{ code: before, filePath: FILE, language: 'java' }]);
  const a = await analyzeProject([{ code: after, filePath: FILE, language: 'java' }]);
  const branches: { before: Record<string, BranchFact[]>; after: Record<string, BranchFact[]> } = {
    before: { [FILE]: await deriveBranchFacts(before, 'java') },
    after: { [FILE]: await deriveBranchFacts(after, 'java') },
  };
  const diff = pathSetDiff(b, a, { cwe: 22, ...(withBranches ? { branches } : {}) });
  return remedyClassOf(diff, b, a, loadSafeConstructTable(PATH_TABLE), withBranches ? { branches: { after: branches.after } } : {});
}

describe('remedyClassOf — guards, normalizers, allowlists (CWE-22)', () => {
  it('normalize, then a containment check that dominates the read: the contain row', async () => {
    const r = await observe(BASE, CONTAINED);
    expect(r.sinks).toHaveLength(1);
    expect(r.sinks[0]).toMatchObject({ match: 'S22-1', class: 'safe' });
    expect(r.sinks[0].rows[0].steps.every(s => s.holds)).toBe(true);
  });

  it('an inverted check is not a guard on the read: the weak normalize-only row', async () => {
    const r = await observe(BASE, INVERTED);
    const ids = r.sinks.flatMap(s => s.rows.map(x => x.id));
    expect(ids).not.toContain('S22-1');
    expect(ids).toContain('W22-1');
  });

  it('a prefix check on the raw string, with no normalizer: the weak string-prefix row', async () => {
    const r = await observe(BASE, STRING_PREFIX);
    const ids = r.sinks.flatMap(s => s.rows.map(x => x.id));
    expect(ids).toContain('W22-2');
    expect(ids).not.toContain('S22-1');
  });

  it('a name chosen from literals by a switch: the allowlist row', async () => {
    const r = await observe(BASE, CHOSEN);
    expect(r.sinks.length).toBeGreaterThan(0);
    for (const s of r.sinks) expect(s.rows.map(x => x.id)).toContain('S22-2');
  });

  it('one literal is a constant, not a choice: no allowlist row', async () => {
    const r = await observe(BASE, ONE_LITERAL);
    expect(r.sinks.length).toBeGreaterThan(0);
    for (const s of r.sinks) expect(s.rows.map(x => x.id)).not.toContain('S22-2');
  });

  it('without branch facts, rows with a guard step abstain', async () => {
    const r = await observe(BASE, CONTAINED, false);
    expect(r.sinks.length).toBeGreaterThan(0);
    for (const s of r.sinks) {
      expect(s.rows.map(x => x.id)).not.toContain('S22-1');
      expect(s.abstainedRows).toContainEqual({ id: 'S22-1', reason: 'step-not-observed:guard-without-branch-facts' });
    }
  });
});
