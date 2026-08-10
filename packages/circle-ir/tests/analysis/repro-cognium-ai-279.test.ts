/**
 * Regression tests for cognium-ai#279 — JS/TS static-detector FP round 2.
 *
 * Three residual crit/high FP classes reproduced on our engine and fixed as
 * SinkFilter drops (recall-preserving):
 *   R-1 — object-literal ORM query-builder arg (`findOne({ where: … })`) is a
 *         bound parameter, not raw injection (Stage 15h).
 *   R-2 — `.find(fn)` / `.filter(fn)` is Array.prototype iteration, not a Mongo
 *         query (Stage 15g).
 *   R-6 — a template-literal URL with a fixed literal host is not SSRF; only the
 *         path is interpolated (Stage 15i).
 *
 * (R-4/R-7/R-8/R-9 were already clean on the current engine; R-5 is a
 * threat-model/context concern, not a detector bug.)
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const HIGH = new Set(['sql_injection', 'nosql_injection', 'ssrf']);
const fires = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint?.flows ?? []).some(f => HIGH.has(f.sink_type));

describe('cognium-ai#279 R-2: Array.find(fn) is not a NoSQL sink', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('does NOT flag user.accounts.find(a => …) as nosql injection', async () => {
    const code = `
export function f(user, req) {
  const pid = req.query.pid;
  return user.accounts.find(a => a.providerId === pid);
}`;
    expect(fires(await analyze(code, 'a.ts', 'typescript'))).toBe(false);
  });

  it('STILL flags a real collection.find({ query }) with an object arg', async () => {
    const code = `
export async function f(collection, req) {
  const q = req.query.q;
  return await collection.find({ name: q });
}`;
    expect(fires(await analyze(code, 'b.ts', 'typescript'))).toBe(true);
  });
});

describe('cognium-ai#279 R-1: ORM query-builder object arg is not injection', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('does NOT flag adapter.findOne({ where: [...] }) as nosql injection', async () => {
    const code = `
export async function f(req) {
  const email = req.query.email;
  return await adapter.findOne({ model: "user", where: [{ field: "email", value: email }] });
}`;
    expect(fires(await analyze(code, 'c.ts', 'typescript'))).toBe(false);
  });

  it('STILL flags raw string-concatenated SQL', async () => {
    const code = `
export async function f(client, req) {
  const id = req.query.id;
  return await client.query("SELECT * FROM u WHERE id=" + id);
}`;
    expect(fires(await analyze(code, 'd.ts', 'typescript'))).toBe(true);
  });
});

describe('cognium-ai#279 R-6: fixed-host URL template is not SSRF', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('does NOT flag fetch(`https://api.github.com/...${path}`) as SSRF', async () => {
    const code = `
export async function f(req) {
  const owner = req.query.o;
  return await fetch(\`https://api.github.com/repos/\${owner}/x\`);
}`;
    expect(fires(await analyze(code, 'e.ts', 'typescript'))).toBe(false);
  });

  it('STILL flags an interpolated-HOST template as SSRF', async () => {
    const code = `
export async function f(req) {
  const host = req.query.h;
  return await fetch(\`https://\${host}/path\`);
}`;
    expect(fires(await analyze(code, 'f.ts', 'typescript'))).toBe(true);
  });
});
