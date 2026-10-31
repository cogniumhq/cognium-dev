/**
 * #1002: fields read or written only through `this.x` are in use whenever
 * the body runs. They were reported dead when the class itself was never
 * reached (only its methods were, through a value of the class's type).
 */

import { describe, it, expect } from 'vitest';
import { buildTsCallGraph } from '../../src/navigation/index.js';
import { deadCode } from '../../src/graph-facts/index.js';

const files = [
  {
    path: 'src/gate.ts',
    code: [
      'export class Base {',
      '  protected limit = 3;',
      '}',
      'export class Gate extends Base {',
      '  private running = 0;',
      '  private waiters: number[] = [];',
      '  private unused = 1;',
      '  get busy() { return this.running > 0; }',
      '  enter(): boolean {',
      '    if (this.running >= this.limit) { this.waiters.push(1); return false; }',
      '    this.running++;',
      '    return !this.busy;',
      '  }',
      '}',
    ].join('\n'),
  },
  {
    path: 'src/main.ts',
    code: [
      "import type { Gate } from './gate';",
      'export function run(g: Gate) { return g.enter(); }',
    ].join('\n'),
  },
];

describe('dead code: fields used through this (#1002)', () => {
  it('this.x reads and writes are strong field-use edges', async () => {
    const g = await buildTsCallGraph(files);
    const q = new Map(g.files.flatMap(f => f.decls.map(d => [d.id, d.qualified_name] as const)));
    const rows = g.fieldUses.map(u => `${q.get(u.from)} > ${q.get(u.to)}`);
    expect(rows).toContain('src/gate:Gate.enter > src/gate:Gate.running');
    expect(rows).toContain('src/gate:Gate.enter > src/gate:Gate.waiters');
    expect(rows).toContain('src/gate:Gate.enter > src/gate:Base.limit'); // inherited
    expect(rows).toContain('src/gate:Gate.enter > src/gate:Gate.busy'); // accessor
    expect(rows.some(r => r.endsWith('Gate.unused'))).toBe(false);
  });

  it('a reached method keeps its fields live; an untouched field stays dead', async () => {
    const g = await buildTsCallGraph(files, { exportRoots: ['src/main.ts'] });
    const r = deadCode(g);
    const v = Object.fromEntries(r.facts.map(f => [f.qualified_name, f.verdict]));
    expect(v['src/gate:Gate.enter']).toBe('live');
    expect(v['src/gate:Gate.running']).toBe('live');
    expect(v['src/gate:Gate.waiters']).toBe('live');
    expect(v['src/gate:Base.limit']).toBe('live');
    expect(v['src/gate:Gate.busy']).toBe('live');
    expect(v['src/gate:Gate.unused']).toBe('dead');
    const running = r.facts.find(f => f.qualified_name === 'src/gate:Gate.running');
    expect(running?.strong?.steps.at(-1)?.via).toBe('field');
  });
});
