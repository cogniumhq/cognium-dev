import { Pool } from 'pg';

/** Minimal client interface — matches both `pg.Pool` and `pg.PoolClient`. */
export interface SqlClient {
  query(text: string, values?: unknown[]): Promise<{ rows: unknown[] }>;
}

const pool = new Pool();

export async function findUnsafe(req: { query: { id: string } }) {
  const id = req.query.id;
  return pool.query('SELECT * FROM users WHERE id = ' + id);
}

export async function findSafe(req: { query: { id: string } }) {
  const id = req.query.id;
  return pool.query('SELECT * FROM users WHERE id = $1', [id]);
}
