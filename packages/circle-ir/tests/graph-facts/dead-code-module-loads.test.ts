/**
 * #1023: modules loaded with `import()` or `require()` inside a body were
 * reported dead, and a removal hint followed. A literal specifier is a strong
 * load edge from the body that runs it; a computed specifier is an
 * unresolved site, so any module is at most `may-be-live`. Tool configs a
 * test runner loads by name (`vitest.config.ts`) are entry points too.
 */

import { describe, it, expect } from 'vitest';
import { buildTsCallGraph, COMPUTED_MODULE_LOAD, type TsCallGraph } from '../../src/navigation/index.js';
import { deadCode, removalReach, COMPUTED_LOAD } from '../../src/graph-facts/index.js';

const files = Object.entries({
  'src/runner.ts': [
    'export async function run(kind: string) {',
    "  if (kind === 'spec') {",
    "    const { generate } = await import('./lazy/generate.js');",
    '    return generate();',
    '  }',
    "  if (kind === 'ns') {",
    "    const ns = await import('./lazy/ns');",
    '    return ns.fromNamespace();',
    '  }',
    "  if (kind === 'inline') return (await import(`./lazy/inline`)).inline();",
    "  if (kind === 'cjs') { const { legacy: old } = require('./lazy/legacy'); return old(); }",
    "  if (kind === 'side') { await import('./lazy/side'); return 0; }",
    '  return 1;',
    '}',
    'export async function plugin(name: string) {',
    '  return import(`./plugins/${name}`);',
    '}',
  ].join('\n'),
  'src/lazy/generate.ts': 'export function generate() { return helper(); }\nfunction helper() { return 1; }\nexport function unusedInLazy() { return 2; }',
  'src/lazy/ns.ts': 'export function fromNamespace() { return 3; }',
  'src/lazy/inline.ts': 'export function inline() { return 4; }',
  'src/lazy/legacy.js': 'function legacy() { return 5; }\nmodule.exports = { legacy };',
  'src/lazy/side.ts': 'export const ready = 1;',
  'src/plugins/one.ts': 'export default function one() { return 6; }',
  'src/orphan.ts': 'export function orphan() { return 7; }',
}).map(([path, code]) => ({ path, code }));

const verdicts = (g: TsCallGraph): Record<string, string> =>
  Object.fromEntries(deadCode(g).facts.map(f => [f.qualified_name, f.verdict]));

describe('dead code: module loads in bodies (#1023)', () => {
  it('a literal import() or require() is a load edge from the enclosing body', async () => {
    const g = await buildTsCallGraph(files, { exportRoots: ['src/runner.ts'] });
    const q = new Map(g.files.flatMap(f => f.decls.map(d => [d.id, d.qualified_name] as const)));
    const rows = g.loads.map(l => `${q.get(l.from)} > ${q.get(l.to)}`);
    expect(rows).toEqual([
      'src/runner:run > src/lazy/generate',
      'src/runner:run > src/lazy/ns',
      'src/runner:run > src/lazy/inline',
      'src/runner:run > src/lazy/legacy',
      'src/runner:run > src/lazy/side',
    ]);
    // Bindings from the load resolve like imports.
    const calls = g.edges.map(e => `${q.get(e.from)} > ${q.get(e.to)} ${e.tier}`);
    expect(calls).toContain('src/runner:run > src/lazy/generate:generate exact');
    expect(calls).toContain('src/runner:run > src/lazy/ns:fromNamespace exact');
    expect(calls).toContain('src/runner:run > src/lazy/inline:inline exact');
    // A computed specifier is an unresolved site, counted with the others.
    const computed = g.unresolved.filter(u => u.methodName === COMPUTED_MODULE_LOAD);
    expect(computed.map(u => q.get(u.from))).toEqual(['src/runner:plugin']);
    expect(computed[0].reason).toBe('dynamic');
    expect(COMPUTED_LOAD).toBe(COMPUTED_MODULE_LOAD);
    const distinct = new Set([...g.edges, ...g.unresolved].map(e => `${e.site.file}:${e.site.line}:${e.site.col}`));
    expect(g.sites).toBe(distinct.size);
  });

  it('modules loaded by a literal specifier are live; a computed one leaves modules may-be-live', async () => {
    const g = await buildTsCallGraph(files, { exportRoots: ['src/runner.ts'] });
    const v = verdicts(g);
    for (const m of ['src/lazy/generate', 'src/lazy/ns', 'src/lazy/inline', 'src/lazy/legacy', 'src/lazy/side']) expect(v[m], m).toBe('live');
    expect(v['src/lazy/generate:generate']).toBe('live');
    expect(v['src/lazy/generate:helper']).toBe('live');
    expect(v['src/lazy/ns:fromNamespace']).toBe('live');
    expect(v['src/lazy/inline:inline']).toBe('live');
    expect(v['src/lazy/side:ready']).toBe('live');
    // Not loaded by name: only the computed site could load it.
    expect(v['src/plugins/one']).toBe('may-be-live');
    expect(v['src/orphan']).toBe('may-be-live');
    const generate = deadCode(g).facts.find(f => f.qualified_name === 'src/lazy/generate');
    expect(generate?.strong?.steps.map(s => s.via)).toEqual(['entry', 'loads']);
    // Functions are not reached by a module load alone.
    expect(v['src/lazy/generate:unusedInLazy']).toBe('dead');
    expect(v['src/orphan:orphan']).toBe('dead');
  });

  it('without the computed site, an unloaded module is dead', async () => {
    const only = files.map(f => (f.path === 'src/runner.ts' ? { ...f, code: f.code.replace('return import(`./plugins/${name}`);', 'return name;') } : f));
    const g = await buildTsCallGraph(only, { exportRoots: ['src/runner.ts'] });
    const v = verdicts(g);
    expect(v['src/lazy/generate']).toBe('live');
    expect(v['src/orphan']).toBe('dead');
    expect(v['src/plugins/one']).toBe('dead');
  });

  it('removal-reach: removing a module loaded by import() removes live code', async () => {
    const base = await buildTsCallGraph(files, { exportRoots: ['src/runner.ts'] });
    const headFiles = files.filter(f => f.path !== 'src/lazy/generate.ts');
    const head = await buildTsCallGraph(headFiles, { exportRoots: ['src/runner.ts'] });
    const r = removalReach(base, head.files);
    const mod = r.removed.find(d => d.qualified_name === 'src/lazy/generate');
    expect(mod?.strong?.steps.at(-1)?.via).toBe('loads');
    const plugin = await buildTsCallGraph(files.filter(f => f.path !== 'src/plugins/one.ts'), { exportRoots: ['src/runner.ts'] });
    const p = removalReach(base, plugin.files).removed.find(d => d.qualified_name === 'src/plugins/one');
    expect(p?.strong).toBeNull();
    expect(p?.unresolved.map(u => u.methodName)).toEqual([COMPUTED_MODULE_LOAD]);
  });

  it('a body that did not parse keeps the modules it loads in partial scope', async () => {
    const broken = [
      { path: 'src/a.ts', code: "export async function a() { const m = await import('./b'); return m.b( ; }" },
      { path: 'src/b.ts', code: 'export function b() { return 1; }\nexport function c() { return 2; }' },
    ];
    const g = await buildTsCallGraph(broken);
    expect(g.partial).toContain('src/a.ts');
    const r = deadCode(g);
    const c = r.facts.find(f => f.qualified_name === 'src/b:c');
    expect(c?.reasons).toContain('partial-files');
  });
});

describe('dead code: test runner configs (#1023)', () => {
  const pkgFiles = [
    { path: 'vitest.config.ts', code: "import { defineConfig } from 'vitest/config';\nexport default defineConfig({ test: { setupFiles: ['./vitest.setup.ts'] } });" },
    { path: 'vitest.setup.ts', code: 'export function setup() { return 1; }\nsetup();' },
    { path: 'vite.config.ts', code: 'export default { base: "/" };' },
    { path: 'src/idle.ts', code: 'export function idle() { return 1; }' },
  ];

  it('vitest and vite configs are entries when the package depends on them', async () => {
    const g = await buildTsCallGraph(pkgFiles, { packages: [{ root: '', packageJson: JSON.stringify({ devDependencies: { vitest: '3.0.0' } }) }] });
    const v = verdicts(g);
    expect(v['vitest.config']).toBe('live');
    expect(v['vite.config']).toBe('live');
    expect(v['src/idle']).toBe('dead');
    const kinds = g.entries.filter(e => e.file === 'vitest.config.ts' || e.file === 'vitest.setup.ts').map(e => `${e.file} ${e.kind}`);
    expect(kinds).toContain('vitest.config.ts main');
    expect(kinds).toContain('vitest.setup.ts test');
  });

  it('without the dependency they are not', async () => {
    const g = await buildTsCallGraph(pkgFiles, { packages: [{ root: '', packageJson: JSON.stringify({ dependencies: {} }) }] });
    expect(verdicts(g)['vitest.config']).toBe('dead');
  });
});
