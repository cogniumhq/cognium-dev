/**
 * Dogfood 2026-10-31 (controldeck auth.ts): a Drizzle
 * `db.delete(Db.session).where(eq(...))` matched the Python ldap3
 * `Connection.delete` LDAP sink through the receiver-name heuristic. The
 * python-ldap / ldap3 sinks are Python-only.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('Python LDAP sinks apply to Python only', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('a TS Drizzle db.delete(...) is not an LDAP sink', async () => {
    const code = `export async function logout(db: any, id: string) {\n  await db.delete(sessions).where(eq(sessions.id, id));\n}`;
    const r = await analyze(code, 'auth.ts', 'typescript');
    expect(r.taint.sinks.filter(s => s.type === 'ldap_injection')).toHaveLength(0);
  });

  it('Python ldap3 conn.search is still a sink', async () => {
    const code = `from ldap3 import Connection\ndef find(conn: Connection, name):\n    conn.search('dc=x', '(uid=' + name + ')')\n`;
    const r = await analyze(code, 'f.py', 'python');
    expect(r.taint.sinks.filter(s => s.type === 'ldap_injection' && s.line === 3).length).toBeGreaterThan(0);
  });
});
