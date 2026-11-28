/**
 * Go `github.com/jmoiron/sqlx` query methods are SQL injection sinks on
 * their query-string argument. Values passed after the query are bound
 * parameters and must not fire.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

type Result = Awaited<ReturnType<typeof analyze>>;

/** A Go file importing sqlx, with `body` after a `User` type. */
const source = (body: string[], extraImports: string[] = []): string => [
  'package store',
  '',
  'import (',
  '\t"context"',
  '\t"net/http"',
  '',
  '\t"github.com/jmoiron/sqlx"',
  ...extraImports.map(i => `\t${i}`),
  ')',
  '',
  'type User struct {',
  '\tID   int    `db:"id"`',
  '\tName string `db:"name"`',
  '}',
  '',
  ...body,
].join('\n');

/** 1-based line of the first line of `code` that contains `needle`. */
const lineOf = (code: string, needle: string): number =>
  code.split('\n').findIndex(l => l.includes(needle)) + 1;

const sqlFlowsTo = (r: Result, line: number) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === 'sql_injection' && f.sink_line === line);

beforeAll(async () => {
  await initAnalyzer();
});

describe('Go sqlx query methods are SQL injection sinks', () => {
  it('concatenated queries reach every sqlx query method on a *sqlx.DB parameter', async () => {
    const calls = [
      'db.Queryx("SELECT * FROM users WHERE id = " + id)',
      'db.QueryRowx("SELECT * FROM users WHERE id = " + id)',
      'db.Select(&users, "SELECT * FROM users WHERE id = "+id)',
      'db.Get(&u, "SELECT * FROM users WHERE id = "+id)',
      'db.NamedExec("UPDATE users SET name = \'"+id+"\' WHERE id = :id", u)',
      'db.NamedQuery("SELECT * FROM users WHERE name = \'"+id+"\'", u)',
      'db.MustExec("DELETE FROM users WHERE id = " + id)',
      'db.QueryxContext(ctx, "SELECT * FROM users WHERE id = "+id)',
      'db.QueryRowxContext(ctx, "SELECT * FROM users WHERE id = "+id)',
      'db.SelectContext(ctx, &users, "SELECT * FROM users WHERE id = "+id)',
      'db.GetContext(ctx, &u, "SELECT * FROM users WHERE id = "+id)',
      'db.NamedExecContext(ctx, "DELETE FROM users WHERE name = \'"+id+"\'", u)',
      'db.NamedQueryContext(ctx, "SELECT * FROM users WHERE name = \'"+id+"\'", u)',
      'db.MustExecContext(ctx, "DELETE FROM users WHERE id = " + id)',
    ];
    const code = source([
      'func Handle(db *sqlx.DB, w http.ResponseWriter, r *http.Request) {',
      '\tctx := context.Background()',
      '\tid := r.URL.Query().Get("id")',
      '\tvar users []User',
      '\tvar u User',
      ...calls.map(c => `\t${c}`),
      '}',
    ]);
    const r = await analyze(code, 'store.go', 'go');
    for (const c of calls) {
      expect(sqlFlowsTo(r, lineOf(code, c)), c).not.toHaveLength(0);
    }
  });

  it('struct-field and transaction receivers, and the package-level helpers', async () => {
    const calls = [
      's.db.Select(&users, "SELECT * FROM users WHERE name = \'"+name+"\'")',
      'tx.MustExec("DELETE FROM users WHERE name = \'" + name + "\'")',
      'sqlx.Get(s.db, &users, "SELECT * FROM users WHERE name = \'"+name+"\'")',
      'sqlx.SelectContext(r.Context(), s.db, &users, "SELECT * FROM users WHERE name = \'"+name+"\'")',
    ];
    const code = source([
      'type Repo struct {',
      '\tdb *sqlx.DB',
      '}',
      '',
      'func (s *Repo) Find(w http.ResponseWriter, r *http.Request) {',
      '\tname := r.FormValue("name")',
      '\tvar users []User',
      `\t${calls[0]}`,
      '\ttx := s.db.MustBegin()',
      ...calls.slice(1).map(c => `\t${c}`),
      '}',
    ]);
    const r = await analyze(code, 'store.go', 'go');
    for (const c of calls) {
      expect(sqlFlowsTo(r, lineOf(code, c)), c).not.toHaveLength(0);
    }
  });

  // ---------------------------------------------------------------------
  // Negatives
  // ---------------------------------------------------------------------

  it('negative: parameterised queries (bound values after the query) do not fire', async () => {
    const r = await analyze(source([
      'func Handle(db *sqlx.DB, w http.ResponseWriter, r *http.Request) {',
      '\tid := r.URL.Query().Get("id")',
      '\tvar rows []User',
      '\tvar u User',
      '\tdb.Select(&rows, "SELECT * FROM users WHERE id = $1", id)',
      '\tdb.Get(&u, "SELECT * FROM users WHERE id = ?", id)',
      '\tdb.NamedExec("UPDATE users SET name = :name WHERE id = :id", map[string]interface{}{"id": id})',
      '\tdb.SelectContext(r.Context(), &rows, "SELECT * FROM users WHERE id = $1", id)',
      '\tsqlx.Get(db, &u, "SELECT * FROM users WHERE id = $1", id)',
      '}',
    ]), 'store.go', 'go');
    expect(r.taint.sinks.filter(s => s.type === 'sql_injection')).toHaveLength(0);
    // No flow of any kind: a bound parameter has not escaped into unknown code.
    expect(r.taint.flows ?? []).toHaveLength(0);
  });

  it('negative: a constant query does not fire', async () => {
    const r = await analyze(source([
      'func Handle(db *sqlx.DB, w http.ResponseWriter, r *http.Request) {',
      '\t_ = r.URL.Query().Get("id")',
      '\tvar rows []User',
      '\tdb.Select(&rows, "SELECT * FROM users ORDER BY id")',
      '\tdb.MustExec("DELETE FROM sessions WHERE expired")',
      '}',
    ]), 'store.go', 'go');
    expect((r.taint.flows ?? []).filter(f => f.sink_type === 'sql_injection')).toHaveLength(0);
  });

  it('negative: a cache client Get(ctx, key) in a sqlx file is not a SQL sink', async () => {
    const r = await analyze(source([
      'type Repo struct {',
      '\tdb  *sqlx.DB',
      '\trdb *redis.Client',
      '}',
      '',
      'func (s *Repo) Find(w http.ResponseWriter, r *http.Request) {',
      '\tkey := r.URL.Query().Get("k")',
      '\ts.rdb.Get(context.Background(), key)',
      '\ts.rdb.Get(r.Context(), key)',
      '\ts.rdb.Get(ctx, key)',
      '}',
    ], ['"github.com/redis/go-redis/v9"']), 'store.go', 'go');
    expect(r.taint.sinks.filter(s => s.type === 'sql_injection')).toHaveLength(0);
  });

  it('negative: without the sqlx import, Get / Select are not SQL sinks', async () => {
    const r = await analyze([
      'package store',
      '',
      'import "net/http"',
      '',
      'func Handle(db *Cache, w http.ResponseWriter, r *http.Request) {',
      '\tid := r.URL.Query().Get("id")',
      '\tvar out string',
      '\tdb.Get(&out, "user:"+id)',
      '\tdb.Select(&out, "user:"+id)',
      '}',
    ].join('\n'), 'store.go', 'go');
    expect(r.taint.sinks.filter(s => s.type === 'sql_injection')).toHaveLength(0);
  });
});
