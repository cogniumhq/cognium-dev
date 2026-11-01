/**
 * cognium-dev#988 follow-up (dogfood 2026-10-31, cognium-ai agent-inventory.ts):
 * `server.args.find(\n  (a) => …,\n)` — the predicate on the next line — was
 * still a nosql_injection sink after #1015, which reads only the sink line.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const nosql = async (code: string) =>
  (await analyze(code, 'inv.ts', 'typescript')).taint.sinks.filter(s => s.type === 'nosql_injection');

describe('Array.find with the predicate on the next line is not a NoSQL sink', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('drops the sink for a wrapped arrow predicate', async () => {
    const code = `export function pick(server: { args: string[] }) {\n  const packageArg = server.args.find(\n    (a) => !a.startsWith('-'),\n  );\n  return packageArg;\n}`;
    expect(await nosql(code)).toHaveLength(0);
  });

  it('keeps a wrapped Mongo query object', async () => {
    const code = `export async function q(users: any, name: string) {\n  return users.find(\n    { name: name },\n  );\n}`;
    expect((await nosql(code)).length).toBeGreaterThan(0);
  });
});
