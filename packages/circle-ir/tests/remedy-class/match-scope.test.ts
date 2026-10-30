import { describe, it, expect } from 'vitest';
import { analyzeProject, pathSetDiff, remedyClassOf, loadSafeConstructTable } from '../../src/index.js';

/* Synthetic table and Java written for this test. */
const TABLE = `format: safe-construct-table@0.1
check-set: example/java
cwe: 78
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
sinks:
  - id: exec
    call: { type: java.lang.Runtime, methods: [exec], arg: 0 }
constructs:
  - id: W78-9
    class: weak
    remedy-class: value-allowlist
    applies-to: [exec]
    match: { call: { type: java.lang.String, methods: [replace, replaceAll] , arg: 0 }, role: sanitizer }
    level: SHOULD
    basis: own
    sources: [doc]
`;

const FILE = 'src/main/java/demo/Git.java';
const cls = (body: string): string => `package demo;
import javax.servlet.http.*;
public class Git {
  public int log(HttpServletRequest req) throws Exception {
    String rev = req.getParameter("rev");
${body}
  }
}`;
const BASE = cls(`    return Runtime.getRuntime().exec("git log " + rev).waitFor();`);
const STRIPPED = cls(`    String clean = rev.replace(";", "");
    return Runtime.getRuntime().exec("git log " + clean).waitFor();`);

describe('remedyClassOf — scope', () => {
  it('describes a fix that left the path open only under scope: all', async () => {
    const b = await analyzeProject([{ code: BASE, filePath: FILE, language: 'java' }]);
    const a = await analyzeProject([{ code: STRIPPED, filePath: FILE, language: 'java' }]);
    const diff = pathSetDiff(b, a, { cwe: 78 });
    expect(diff.counts.unchanged).toBe(1);
    const table = loadSafeConstructTable(TABLE);
    expect(remedyClassOf(diff, b, a, table).sinks).toEqual([]);
    expect(remedyClassOf(diff, b, a, table, { scope: 'closed' }).sinks).toEqual([]);
    const all = remedyClassOf(diff, b, a, table, { scope: 'all' });
    expect(all.sinks).toHaveLength(1);
    expect(all.sinks[0]).toMatchObject({ change: 'unchanged', match: 'W78-9', class: 'weak' });
  });
});
