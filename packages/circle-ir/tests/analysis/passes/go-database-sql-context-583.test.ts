/**
 * #583 — database/sql context, transaction, and prepare forms are
 * sql_injection sinks. Parameterised calls stay clean.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

async function scan(body: string) {
  const code = `package main\n\nfunc h(r *http.Request, db *sql.DB, tx *sql.Tx, conn *sql.Conn) {\n  f := r.URL.Query().Get("f")\n  q := "SELECT id FROM items WHERE " + f\n  ${body}\n}\n`;
  const ir = await analyze(code, 'q.go', 'go');
  const sqlFlows = (ir.taint.flows ?? []).filter(f => f.sink_type === 'sql_injection');
  const sqlSinks = ir.taint.sinks.filter(s => s.type === 'sql_injection');
  return { sqlFlows, sqlSinks };
}

describe('cognium-dev #583 — Go database/sql context sinks', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it.each([
    ['db.Query(q)', 'control Query'],
    ['db.QueryContext(r.Context(), q)', 'QueryContext'],
    ['db.QueryRowContext(r.Context(), q)', 'QueryRowContext'],
    ['db.ExecContext(r.Context(), q)', 'ExecContext'],
    ['db.Prepare(q)', 'Prepare'],
    ['db.PrepareContext(r.Context(), q)', 'PrepareContext'],
    ['tx.Exec(q)', 'Tx.Exec'],
    ['tx.QueryRow(q)', 'Tx.QueryRow'],
    ['tx.ExecContext(r.Context(), q)', 'Tx.ExecContext'],
    ['tx.QueryContext(r.Context(), q)', 'Tx.QueryContext'],
    ['conn.QueryContext(r.Context(), q)', 'Conn.QueryContext'],
  ])('flow-backed sql_injection for %s', async (call) => {
    const { sqlFlows, sqlSinks } = await scan(call);
    expect(sqlSinks.length).toBeGreaterThan(0);
    expect(sqlFlows.length).toBeGreaterThan(0);
  });

  it.each([
    ['db.QueryContext(r.Context(), "SELECT id FROM items WHERE id = $1", f)', 'QueryContext $1'],
    ['tx.Exec("DELETE FROM items WHERE id = ?", f)', 'Tx.Exec ?'],
    ['db.QueryRowContext(r.Context(), "SELECT id FROM items WHERE id = $1", f)', 'QueryRowContext $1'],
  ])('parameterised %s stays clean', async (call) => {
    const { sqlFlows, sqlSinks } = await scan(call);
    expect(sqlSinks).toHaveLength(0);
    expect(sqlFlows).toHaveLength(0);
  });
});
