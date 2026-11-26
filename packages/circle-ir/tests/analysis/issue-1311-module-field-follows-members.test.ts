/**
 * #1311 part 1: a module's and a field's dead verdict follows its members.
 *
 * #1366 (#1288 S2) lifted a dead module or type to may-be-live when a member is
 * may-be-live, and a field of a *type* with a may-be-live method. A field of a
 * *module* (a top-level `const`) was left out. A module-level field is the
 * module's own initializer: it runs when the module is loaded. A live module's
 * fields are already live; but when the module is may-be-live (lifted by its
 * may-be-live functions, or reached only by an unresolved site), its fields
 * stayed `dead`, though they run whenever the module does and its functions
 * may read them. A field of a module now follows the module's verdict.
 *
 * Unchanged: a live module's fields stay live, a dead module's fields stay
 * dead, and the type-field rule is as before.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initParser } from '../../src/core/parser.js';
import { buildTsCallGraph } from '../../src/navigation/index.js';
import { deadCode, deadCodeConsistencyViolations } from '../../src/graph-facts/index.js';

beforeAll(async () => {
  await initParser();
});

const root = 'expo-app';
const pkg = JSON.stringify({
  main: 'expo-router/entry',
  dependencies: { expo: '52.0.0', 'expo-router': '4.0.0', react: '18.0.0' },
});
const file = (path: string, code: string[]) => ({ path: `${root}/${path}`, code: code.join('\n'), ids: { packageName: 'app' } });

// One dynamic property call (the issue's `(obj as any)[key]()`) makes every function may-be-live.
const files = [
  file('app/_layout.tsx', ['export default function Layout() { return null; }']),
  file('app/settings/index.tsx', [
    "import * as handlers from '../../src/lib/handlers';",
    'export default function Settings(p: { k: string }) { return (handlers as any)[p.k](); }',
  ]),
  // Unimported: its functions are may-be-live through the dynamic call; its fields were dead.
  file('src/lib/pricing.ts', [
    "export const config = { currency: 'USD' };",
    'export const RATE = 1.2;',
    'export function formatPrice(n: number) { return (n * RATE).toFixed(2) + config.currency; }',
  ]),
  file('src/lib/store.ts', [
    'export class Store {',
    '  count = 0;',
    '  bump() { this.count++; }',
    '}',
    'export const store = new Store();',
  ]),
  // Only fields: no member that may run, so nothing to follow.
  file('src/lib/constants.ts', ["export const BRAND = 'acme';", 'export const MAX = 9;']),
];

describe('#1311 part 1: a module-level field follows its module', () => {
  it('fields next to may-be-live functions are not dead; a module of only fields stays dead', async () => {
    const g = await buildTsCallGraph(files, { packages: [{ root, packageJson: pkg, appJson: '{}' }] });
    const r = deadCode(g);
    const v = Object.fromEntries(r.facts.map(f => [f.qualified_name, f.verdict]));
    const why = Object.fromEntries(r.facts.map(f => [f.qualified_name, f.reasons]));

    // The members that may run, and their module (#1366, unchanged).
    expect(v['app/expo-app/src/lib/pricing:formatPrice']).toBe('may-be-live');
    expect(v['app/expo-app/src/lib/pricing']).toBe('may-be-live');
    // The fields now follow them (dead before).
    expect(v['app/expo-app/src/lib/pricing:config']).toBe('may-be-live');
    expect(v['app/expo-app/src/lib/pricing:RATE']).toBe('may-be-live');
    expect(why['app/expo-app/src/lib/pricing:config']).toEqual(['unresolved-sites']);
    // A module-level instance of a class whose method may run.
    expect(v['app/expo-app/src/lib/store:Store.bump']).toBe('may-be-live');
    expect(v['app/expo-app/src/lib/store:store']).toBe('may-be-live');
    // The type-field rule, unchanged.
    expect(v['app/expo-app/src/lib/store:Store.count']).toBe('may-be-live');

    // No member may run: still dead.
    expect(v['app/expo-app/src/lib/constants:BRAND']).toBe('dead');
    expect(v['app/expo-app/src/lib/constants:MAX']).toBe('dead');
    expect(v['app/expo-app/src/lib/constants']).toBe('dead');

    expect(deadCodeConsistencyViolations(r.facts, g)).toEqual([]);
    expect(r.summary.dead).toBe(r.facts.filter(f => f.verdict === 'dead').length);
  });

  it('#1288 fixture: handlers VERSION, beside may-be-live onA / onB, is no longer dead', async () => {
    const g = await buildTsCallGraph([
      file('app/_layout.tsx', ['export default function Layout() { return null; }']),
      file('app/settings/index.tsx', [
        "import * as handlers from '../../src/lib/handlers';",
        'export default function Settings(p: { k: string }) { return (handlers as any)[p.k](); }',
      ]),
      file('src/lib/handlers.ts', ['export const VERSION = 3;', "export function onA() { return 'a'; }", "export function onB() { return 'b'; }"]),
    ], { packages: [{ root, packageJson: pkg, appJson: '{}' }] });
    const v = Object.fromEntries(deadCode(g).facts.map(f => [f.qualified_name, f.verdict]));
    expect(v['app/expo-app/src/lib/handlers:onA']).toBe('may-be-live');
    expect(v['app/expo-app/src/lib/handlers:VERSION']).not.toBe('dead');
  });

  it('unchanged: a live module keeps its fields live (its initializers run on load), a dead one keeps them dead', async () => {
    const g = await buildTsCallGraph([
      file('app/_layout.tsx', ['export default function Layout() { return null; }']),
      file('app/live.tsx', ["import { fp } from '../src/lib/live';", 'export default function LivePage() { return fp(2); }']),
      file('src/lib/live.ts', ['export function fp(n: number) { return n.toFixed(2); }', 'const unusedLocal = 4;']),
      file('src/lib/constants.ts', ["export const BRAND = 'acme';"]),
    ], { packages: [{ root, packageJson: pkg, appJson: '{}' }] });
    const v = Object.fromEntries(deadCode(g).facts.map(f => [f.qualified_name, f.verdict]));
    expect(v['app/expo-app/src/lib/live']).toBe('live');
    expect(v['app/expo-app/src/lib/live:unusedLocal']).toBe('live');
    expect(v['app/expo-app/src/lib/constants']).toBe('dead');
    expect(v['app/expo-app/src/lib/constants:BRAND']).toBe('dead');
  });
});
