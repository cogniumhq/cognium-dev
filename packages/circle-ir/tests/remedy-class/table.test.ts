import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { loadSafeConstructTable, SAFE_CONSTRUCT_TABLE_FORMAT } from '../../src/index.js';
import type { LoadTableResult, TableProblem } from '../../src/index.js';

/**
 * A synthetic table written for these tests. It uses every key the format
 * allows at every level, so the accepted shape and each refusal can be
 * exercised from one fixture.
 */
const TABLE = `# synthetic table for tests
format: safe-construct-table@0.1
check-set: example/java
cwe: 89
cwe-list-version: '4.20'
language: java
version: 0.1.0
settles: signal

sources:
  std-a:
    kind: standard
    publisher: Example Standards Body
    title: Example standard
    url: https://example.org/standard
    fetched: '2026-10-29'
    quote: Use parameters.
  doc-b:
    kind: vendor-docs
    publisher: Example Vendor
    title: Example API
    url: https://example.org/api
    via: https://mirror.example.org/api
    fetched: '2026-10-29'
    quote: Setter methods bind values.

sinks:
  - id: stmt
    call: { type: java.sql.Statement, methods: [execute, executeQuery], arg: 0 }
  - id: prep
    call: { type: java.sql.Connection, methods: [prepareStatement], arg: 0 }
    note: a sink when the text is tainted
  - id: writer
    call: { type: java.io.PrintWriter, methods: [print], arg: 0, receiver-from: "javax.servlet.ServletResponse.getWriter" }
  - id: pb
    call: { type: java.lang.ProcessBuilder, ctor: true, methods: [], arg: all }
  - id: tmpl
    template: { engine: thymeleaf, construct: "th:utext" }

constructs:
  - id: S89-1
    class: safe
    remedy-class: bind-parameters
    applies-to: [stmt, prep]
    match:
      all:
        - { name: p, call: { type: java.sql.Connection, methods: [prepareStatement], arg: 0 }, arg-is: untainted, role: sink-replacement }
        - { name: b, call: { type: java.sql.PreparedStatement, methods: ["set*"], arg: 1 }, arg-is: tainted, role: binder }
        - { order: [p, b] }
    level: SHOULD
    basis: cited
    sources: [std-a, doc-b]
    note: bind
  - id: S89-2
    class: safe
    remedy-class: canonicalize-then-contain
    applies-to: [stmt]
    context: html-content
    match:
      all:
        - { name: n, any: [ { call: { type: java.nio.file.Path, methods: [normalize] }, role: normalizer } ] }
        - { name: g, call: { type: java.nio.file.Path, methods: [startsWith], arg: 0, static: false }, arg-is: from-allowlist, role: guard, on: true }
        - { order: [n, g] }
    level: SHOULD
    basis: cited
    sources: [std-a]
    residual: links
  - id: S89-3
    class: safe
    remedy-class: library-call
    applies-to: [pb]
    match: { sink-removed: true }
    level: MUST
    basis: cited
    sources: [std-a]
  - id: S89-4
    class: safe
    remedy-class: auto-escaping-template
    applies-to: [tmpl]
    match: { template: { engine: jsp, construct: "c:out", attribute: escapeXml, value: [absent, "true"] }, role: sink-replacement }
    level: SHOULD
    basis: cited
    sources: [doc-b]
  - id: W89-1
    class: weak
    remedy-class: argument-vector
    applies-to: [pb, writer]
    match:
      all:
        - { arg-literal-in: [sh, bash] }
        - { missing: { call: { type: java.lang.Object, methods: ["*"] }, role: guard } }
    level: SHOULD
    basis: own
    sources: [std-a]
  - id: W89-2
    class: weak
    remedy-class: bind-parameters
    applies-to: [stmt]
    match: { template: { engine: jsp, construct: "c:out", value: "false" } }
    level: SHOULD
    basis: own
    sources: [doc-b]
    retired: 0.1.0
`;

function refused(r: LoadTableResult): TableProblem[] {
  if (r.ok) throw new Error('expected a refusal');
  return r.problems;
}

/** Replace exactly one occurrence of `from` in the fixture. */
function edit(from: string, to: string): string {
  const i = TABLE.indexOf(from);
  if (i < 0 || TABLE.indexOf(from, i + 1) >= 0) throw new Error(`fixture edit not unique: ${from}`);
  return TABLE.slice(0, i) + to + TABLE.slice(i + from.length);
}

describe('loadSafeConstructTable — accepted', () => {
  it('loads every key the format allows', () => {
    const r = loadSafeConstructTable(TABLE);
    if (!r.ok) throw new Error(JSON.stringify(r.problems, null, 2));
    const t = r.table;
    expect(t.format).toBe(SAFE_CONSTRUCT_TABLE_FORMAT);
    expect(t).toMatchObject({ checkSet: 'example/java', cwe: 89, cweListVersion: '4.20', language: 'java', version: '0.1.0', settles: 'signal' });
    expect(Object.keys(t.sources)).toEqual(['std-a', 'doc-b']);
    expect(t.sources['doc-b'].via).toBe('https://mirror.example.org/api');
    expect(t.sinks.map(s => s.id)).toEqual(['stmt', 'prep', 'writer', 'pb', 'tmpl']);
    expect(t.sinks[2].call?.receiverFrom).toBe('javax.servlet.ServletResponse.getWriter');
    expect(t.sinks[3].call).toEqual({ type: 'java.lang.ProcessBuilder', methods: [], arg: 'all', ctor: true });
    expect(t.sinks[4].template).toEqual({ engine: 'thymeleaf', construct: 'th:utext' });
    expect(t.sinks[1].note).toBe('a sink when the text is tainted');
  });

  it('keeps rows in file order with their match trees', () => {
    const r = loadSafeConstructTable(TABLE);
    if (!r.ok) throw new Error('refused');
    const rows = r.table.constructs;
    expect(rows.map(x => x.id)).toEqual(['S89-1', 'S89-2', 'S89-3', 'S89-4', 'W89-1', 'W89-2']);
    expect(rows[0]).toMatchObject({ class: 'safe', remedyClass: 'bind-parameters', appliesTo: ['stmt', 'prep'], level: 'SHOULD', basis: 'cited', note: 'bind' });
    expect(rows[0].match.all?.[0]).toEqual({
      name: 'p', call: { type: 'java.sql.Connection', methods: ['prepareStatement'], arg: 0 }, argIs: 'untainted', role: 'sink-replacement',
    });
    expect(rows[0].match.all?.[2].order).toEqual(['p', 'b']);
    expect(rows[1].context).toBe('html-content');
    expect(rows[1].residual).toBe('links');
    expect(rows[1].match.all?.[1]).toMatchObject({ role: 'guard', on: true, argIs: 'from-allowlist' });
    expect(rows[2].match).toEqual({ sinkRemoved: true });
    expect(rows[3].match.template).toEqual({ engine: 'jsp', construct: 'c:out', attribute: 'escapeXml', value: ['absent', 'true'] });
    expect(rows[4].match.all?.[0].argLiteralIn).toEqual(['sh', 'bash']);
    expect(rows[4].match.all?.[1].missing).toEqual({ call: { type: 'java.lang.Object', methods: ['*'] }, role: 'guard' });
    expect(rows[5].retired).toBe('0.1.0');
    expect(rows[5].match.template?.value).toEqual(['false']);
  });

  it('does not interpret labels: an unfamiliar remedy-class or context passes through', () => {
    const r = loadSafeConstructTable(edit('remedy-class: library-call', 'remedy-class: some-new-family').replace('context: html-content', 'context: css-value'));
    expect(r.ok).toBe(true);
  });

  it('digests exactly the bytes given', () => {
    const bytes = new TextEncoder().encode(TABLE);
    const expected = `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
    expect(loadSafeConstructTable(bytes).digest).toBe(expected);
    expect(loadSafeConstructTable(TABLE).digest).toBe(expected);
    // a change that YAML ignores still changes the digest: no normalisation
    const r = loadSafeConstructTable(TABLE + '\n# trailing comment\n');
    expect(r.ok).toBe(true);
    expect(r.digest).not.toBe(expected);
  });

  it('is deterministic', () => {
    expect(JSON.stringify(loadSafeConstructTable(TABLE))).toBe(JSON.stringify(loadSafeConstructTable(TABLE)));
  });
});

describe('loadSafeConstructTable — refused', () => {
  const unknownKeyCases: [string, string, string, string][] = [
    ['top level', 'settles: signal\n', 'settles: signal\nextra: 1\n', '/extra'],
    ['a source', '    quote: Use parameters.\n', '    quote: Use parameters.\n    license: CC\n', '/sources/std-a/license'],
    ['a sink', '    note: a sink when the text is tainted\n', '    note: a sink when the text is tainted\n    severity: high\n', '/sinks/1/severity'],
    ['a sink call', 'methods: [execute, executeQuery], arg: 0 }', 'methods: [execute, executeQuery], arg: 0, overload: 2 }', '/sinks/0/call/overload'],
    ['a sink template', 'construct: "th:utext" }', 'construct: "th:utext", mode: html }', '/sinks/4/template/mode'],
    ['a row', '    note: bind\n', '    note: bind\n    weight: 3\n', '/constructs/0/weight'],
    ['a step', 'arg-is: tainted, role: binder }', 'arg-is: tainted, role: binder, flows-to: x }', '/constructs/0/match/all/1/flows-to'],
    ['a step call', 'methods: ["set*"], arg: 1 }', 'methods: ["set*"], arg: 1, varargs: true }', '/constructs/0/match/all/1/call/varargs'],
    ['a step template', 'attribute: escapeXml, value: [absent, "true"] }', 'attribute: escapeXml, value: [absent, "true"], scope: page }', '/constructs/3/match/template/scope'],
    ['a nested missing step', '{ missing: { call: { type: java.lang.Object, methods: ["*"] }, role: guard } }', '{ missing: { call: { type: java.lang.Object, methods: ["*"] }, role: guard, near: true } }', '/constructs/4/match/all/1/missing/near'],
  ];
  for (const [where, from, to, path] of unknownKeyCases) {
    it(`refuses an unknown key in ${where}`, () => {
      const problems = refused(loadSafeConstructTable(edit(from, to)));
      expect(problems).toContainEqual(expect.objectContaining({ code: 'unknown-key', path }));
    });
  }

  it('refuses a different format and says what it saw', () => {
    const r = loadSafeConstructTable(edit('format: safe-construct-table@0.1', 'format: safe-construct-table@0.2'));
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.format).toBe('safe-construct-table@0.2');
    expect(r.problems).toEqual([expect.objectContaining({ code: 'unknown-format', path: '/format' })]);
  });

  it('refuses a missing format', () => {
    const r = loadSafeConstructTable(edit('format: safe-construct-table@0.1\n', ''));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.format).toBeNull();
  });

  const badValueCases: [string, string, string, string][] = [
    ['class', 'class: weak\n    remedy-class: argument-vector', 'class: risky\n    remedy-class: argument-vector', '/constructs/4/class'],
    ['arg-is', 'arg-is: tainted, role: binder', 'arg-is: maybe, role: binder', '/constructs/0/match/all/1/arg-is'],
    ['role', 'role: binder', 'role: setter', '/constructs/0/match/all/1/role'],
    ['on', 'role: guard, on: true', 'role: guard, on: yes', '/constructs/1/match/all/1/on'],
    ['sink-removed', 'match: { sink-removed: true }', 'match: { sink-removed: false }', '/constructs/2/match/sink-removed'],
    ['call.arg', 'methods: ["set*"], arg: 1 }', 'methods: ["set*"], arg: -1 }', '/constructs/0/match/all/1/call/arg'],
    ['call.methods', 'methods: [prepareStatement], arg: 0 }\n    note', 'methods: prepareStatement, arg: 0 }\n    note', '/sinks/1/call/methods'],
    ['level', 'level: MUST', 'level: MAY', '/constructs/2/level'],
    ['basis', 'basis: own\n    sources: [std-a]', 'basis: guess\n    sources: [std-a]', '/constructs/4/basis'],
    ['cwe', 'cwe: 89', 'cwe: CWE-89', '/cwe'],
    ['order', '{ order: [p, b] }', '{ order: [p] }', '/constructs/0/match/all/2/order'],
    ['empty any', '{ name: n, any: [ { call: { type: java.nio.file.Path, methods: [normalize] }, role: normalizer } ] }', '{ name: n, any: [] }', '/constructs/1/match/all/0/any'],
    ['empty step', '- { order: [p, b] }', '- {}', '/constructs/0/match/all/2'],
    ['arg-literal-in', '{ arg-literal-in: [sh, bash] }', '{ arg-literal-in: sh }', '/constructs/4/match/all/0/arg-literal-in'],
    ['applies-to', 'applies-to: [pb]', 'applies-to: []', '/constructs/2/applies-to'],
    ['row sources', 'sources: [doc-b]\n    retired', 'sources: []\n    retired', '/constructs/5/sources'],
    ['a string field', 'version: 0.1.0', 'version: ""', '/version'],
    ['a template value list', 'value: [absent, "true"]', 'value: [absent, 1]', '/constructs/3/match/template/value'],
  ];
  for (const [what, from, to, path] of badValueCases) {
    it(`refuses a bad ${what}`, () => {
      const problems = refused(loadSafeConstructTable(edit(from, to)));
      expect(problems).toContainEqual(expect.objectContaining({ code: 'bad-value', path }));
    });
  }

  it('refuses dangling references', () => {
    expect(refused(loadSafeConstructTable(edit('applies-to: [pb]', 'applies-to: [pb, nosuch]'))))
      .toContainEqual(expect.objectContaining({ code: 'dangling-ref', path: '/constructs/2/applies-to/1' }));
    expect(refused(loadSafeConstructTable(edit('{ order: [p, b] }', '{ order: [p, z] }'))))
      .toContainEqual(expect.objectContaining({ code: 'dangling-ref', path: '/constructs/0/match/all/2/order' }));
    expect(refused(loadSafeConstructTable(edit('sources: [std-a, doc-b]', 'sources: [std-a, nosuch]'))))
      .toContainEqual(expect.objectContaining({ code: 'dangling-ref', path: '/constructs/0/sources/1' }));
  });

  it('refuses duplicate ids and step names', () => {
    expect(refused(loadSafeConstructTable(edit('  - id: S89-2', '  - id: S89-1'))))
      .toContainEqual(expect.objectContaining({ code: 'duplicate-id', path: '/constructs/1/id' }));
    expect(refused(loadSafeConstructTable(edit('  - id: prep', '  - id: stmt'))))
      .toContainEqual(expect.objectContaining({ code: 'duplicate-id', path: '/sinks/1/id' }));
    expect(refused(loadSafeConstructTable(edit('{ name: b, call', '{ name: p, call'))))
      .toContainEqual(expect.objectContaining({ code: 'duplicate-id', path: '/constructs/0/match/all/1/name' }));
  });

  it('refuses missing required keys', () => {
    expect(refused(loadSafeConstructTable(edit('    basis: cited\n    sources: [std-a]\n    residual: links\n', '    sources: [std-a]\n    residual: links\n'))))
      .toContainEqual(expect.objectContaining({ code: 'missing-key', path: '/constructs/1/basis' }));
    expect(refused(loadSafeConstructTable(edit('    quote: Use parameters.\n', ''))))
      .toContainEqual(expect.objectContaining({ code: 'missing-key', path: '/sources/std-a/quote' }));
    expect(refused(loadSafeConstructTable(edit("cwe-list-version: '4.20'\n", ''))))
      .toContainEqual(expect.objectContaining({ code: 'missing-key', path: '/cwe-list-version' }));
    expect(refused(loadSafeConstructTable(edit('call: { type: java.sql.Statement, methods: [execute, executeQuery], arg: 0 }', 'call: { methods: [execute, executeQuery], arg: 0 }'))))
      .toContainEqual(expect.objectContaining({ code: 'missing-key', path: '/sinks/0/call/type' }));
  });

  it('refuses a sink with both or neither of call and template', () => {
    const both = edit('    template: { engine: thymeleaf, construct: "th:utext" }', '    template: { engine: thymeleaf, construct: "th:utext" }\n    call: { type: X, methods: [m] }');
    expect(refused(loadSafeConstructTable(both))).toContainEqual(expect.objectContaining({ code: 'bad-value', path: '/sinks/4' }));
    const neither = edit('    template: { engine: thymeleaf, construct: "th:utext" }\n', '');
    expect(refused(loadSafeConstructTable(neither))).toContainEqual(expect.objectContaining({ code: 'bad-value', path: '/sinks/4' }));
  });

  it('lists every problem, not only the first', () => {
    const text = edit('role: binder', 'role: setter').replace('settles: signal\n', 'settles: signal\nextra: 1\n').replace('applies-to: [pb]', 'applies-to: [nosuch]');
    const codes = refused(loadSafeConstructTable(text)).map(p => p.code).sort();
    expect(codes).toEqual(['bad-value', 'dangling-ref', 'unknown-key']);
  });

  it('refuses wrong container shapes', () => {
    const base = `format: safe-construct-table@0.1\ncheck-set: x\ncwe: 1\ncwe-list-version: '1'\nlanguage: java\nversion: 0.1.0\nsettles: signal\n`;
    const problems = refused(loadSafeConstructTable(`${base}sources: [a]\nsinks: {a: 1}\nconstructs: 3\n`));
    expect(problems.map(p => p.path).sort()).toEqual(['/constructs', '/sinks', '/sources']);
    expect(refused(loadSafeConstructTable(`${base}sources: {a: 1}\nsinks: [1]\nconstructs: [x]\n`)).map(p => p.path).sort())
      .toEqual(['/constructs/0', '/sinks/0', '/sources/a']);
    expect(refused(loadSafeConstructTable('- a\n- b\n'))).toEqual([expect.objectContaining({ code: 'bad-value', path: '' })]);
  });

  it('refuses YAML it cannot read', () => {
    expect(refused(loadSafeConstructTable('a: [1, 2\n'))[0].code).toBe('parse-error');
    expect(refused(loadSafeConstructTable(edit('language: java', 'language: java\nlanguage: kotlin')))[0].code).toBe('parse-error');
    expect(refused(loadSafeConstructTable(`${TABLE}\n---\nformat: x\n`))[0].message).toMatch(/one YAML document/);
    expect(refused(loadSafeConstructTable(''))[0].code).toBe('parse-error');
    expect(refused(loadSafeConstructTable(new Uint8Array([0x66, 0x3a, 0x20, 0xff, 0xfe])))[0].message).toBe('not valid UTF-8');
  });

  it('returns the digest with a refusal', () => {
    const text = edit('role: binder', 'role: setter');
    const r = loadSafeConstructTable(text);
    expect(r.ok).toBe(false);
    expect(r.digest).toBe(`sha256:${createHash('sha256').update(text, 'utf8').digest('hex')}`);
  });
});
