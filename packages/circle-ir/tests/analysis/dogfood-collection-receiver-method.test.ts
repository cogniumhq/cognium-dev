/**
 * Dogfood 2026-10-31 (cognium-ai circle-ir-ai/src/cache/file-cache.ts):
 * inter-procedural call resolution is by method NAME on any receiver, so in a
 * class with its own `get` / `set`, `this.memoryCache.set(hash, entry)` on a
 * `Map<…>` field resolved to the class's `set` and produced path_traversal
 * flows into that method's `fs.writeFileSync` / `fs.readFileSync`. A method
 * of a receiver declared as a built-in Map / Set is never a class method here.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const flows = async (code: string) =>
  (await analyze(code, 'store.ts', 'typescript')).taint.flows ?? [];

const store = (fieldDecl: string, recv: string) => `import * as fs from 'fs';
import * as path from 'path';

let version: string | null = null;
try {
  const pkg = JSON.parse(fs.readFileSync('/opt/app/package.json', 'utf-8'));
  version = pkg.version;
} catch {
  version = 'unknown';
}

export class Store<T> {
  private dir: string = '/var/cache/app';
  ${fieldDecl}

  private remember(key: string, value: T): void {
    ${recv}.set(key, value);
  }

  get(key: string): T | null {
    const hit = ${recv}.get(key);
    if (hit) return hit;
    const p = path.join(this.dir, key + '.json');
    if (fs.existsSync(p)) return JSON.parse(fs.readFileSync(p, 'utf-8')) as T;
    return null;
  }

  set(key: string, value: T): void {
    const p = path.join(this.dir, key + '.json');
    this.remember(key, value);
    fs.writeFileSync(p, JSON.stringify({ version, value }));
  }
}
`;

describe('a built-in Map/Set receiver method is not resolved to a same-named class method', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('drops the flows through this.mem.set / this.mem.get on a Map-typed field', async () => {
    const f = await flows(store('private mem: Map<string, T> = new Map();', 'this.mem'));
    expect(f.filter(x => x.sink_type === 'path_traversal')).toHaveLength(0);
  });

  it('drops them for an untyped field initialised with new Map()', async () => {
    const f = await flows(store('private mem = new Map<string, T>();', 'this.mem'));
    expect(f.filter(x => x.sink_type === 'path_traversal')).toHaveLength(0);
  });

  it('keeps resolution for a receiver not declared as a collection', async () => {
    const code = `import * as fs from 'fs';
export class Writer {
  write(p: string): void { fs.writeFileSync(p, 'x'); }
}
export class Svc {
  private helper: Writer = new Writer();
  run(): void {
    const p = fs.readFileSync('/etc/target', 'utf-8');
    this.helper.write(p);
  }
}
`;
    const f = await flows(code);
    expect(f.filter(x => x.sink_type === 'path_traversal').length).toBeGreaterThan(0);
  });
});
