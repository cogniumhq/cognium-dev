/**
 * cognium-dev#1000 — ordinary array methods are not sinks.
 *  - `out.push(x)` on an array matched the Next.js `router.push` open-redirect
 *    entry through the receiver-name heuristic (`out` ⊂ `router`).
 *  - `ancestors.find(meaningful)` with a named predicate matched the classless
 *    JS `find` NoSQL entry; only the arrow / `function` forms were dropped (cognium-ai#279).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const sinkTypes = async (code: string, file = 'x.ts') => {
  const r = await analyze(code, file, 'typescript');
  return r.taint.sinks.map(s => `${s.method}:${s.type}`);
};

describe('#1000 — Array.push / Array.find are not open_redirect / nosql sinks', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('out.push(tainted) on an array has no open_redirect sink', async () => {
    const sinks = await sinkTypes(`
export function collect(req: any) {
  const out: string[] = [];
  out.push(req.query.next);
  return out;
}
`);
    expect(sinks).not.toContain('push:open_redirect');
  });

  it('router.push / this.router.push / router.replace with tainted URL still fire', async () => {
    const sinks = await sinkTypes(`
export function go(req: any, router: any, history: any) {
  router.push(req.query.next);
  router.replace(req.query.next);
}
export class Nav { constructor(private router: any) {} go(req: any) { this.router.push(req.query.to); } }
`);
    expect(sinks.filter(s => s === 'push:open_redirect').length).toBe(2);
    expect(sinks).toContain('replace:open_redirect');
  });

  it('array.find(namedPredicate) and declared-array receivers have no nosql sink', async () => {
    const sinks = await sinkTypes(`
function meaningful(n: any) { return !!n; }
const isHit = (x: string) => x.length > 0;
export function f(req: any, ancestors: any[], items: string[]) {
  const q = req.query.q;
  const a = ancestors.find(meaningful);
  const b = items.find(isHit);
  const tags: string[] = [q];
  const c = tags.find(q);
  return [a, b, c];
}
`);
    expect(sinks).not.toContain('find:nosql_injection');
  });

  it('collection.find(query) with a query object or variable still fires', async () => {
    const sinks = await sinkTypes(`
export async function list(db: any, req: any) {
  const filter = { name: req.query.name };
  await db.collection('users').find({ name: req.query.name });
  return db.collection('users').find(filter);
}
`);
    expect(sinks.filter(s => s === 'find:nosql_injection').length).toBe(2);
  });
});
