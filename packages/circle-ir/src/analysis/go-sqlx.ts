/**
 * Go `github.com/jmoiron/sqlx` query methods.
 *
 * The query-string argument of the sqlx query methods on `DB` / `Tx` /
 * `Conn` is a SQL injection sink, as is the query argument of the
 * package-level helpers that take the queryer first
 * (`sqlx.Get(db, &u, q, args...)`). Values after the query are bound
 * parameters: `db.Select(&rows, "... WHERE id = $1", id)` is not a sink use,
 * and the parameterised form is recognised the same way as `database/sql`'s
 * (`isParameterizedQueryCall` in the taint matcher; `isGoSqlxBoundArgsCall`
 * below for the CWE-668 escape fallback).
 *
 * The sinks are import-gated, because `Get` and `Select` are common method
 * names. `Get` / `Select` take a destination before the query, so a context
 * in that slot (`rdb.Get(ctx, key)`) marks another library's method.
 */

import type { CallInfo, ImportInfo } from '../types/index.js';
import type { SinkPattern } from '../types/config.js';

export const GO_SQLX_MODULE = 'github.com/jmoiron/sqlx';

/** Method → position of the query string on a `DB` / `Tx` / `Conn` receiver. */
const RECEIVER_QUERY_POSITION: ReadonlyMap<string, number> = new Map([
  ['Queryx', 0], ['QueryRowx', 0], ['Select', 1], ['Get', 1],
  ['NamedExec', 0], ['NamedQuery', 0], ['MustExec', 0],
  ['QueryxContext', 1], ['QueryRowxContext', 1], ['SelectContext', 2], ['GetContext', 2],
  ['NamedExecContext', 1], ['NamedQueryContext', 1], ['MustExecContext', 1],
]);

/** Package-level helpers: the queryer comes first, so the query sits one position later. */
const PACKAGE_FUNCS: ReadonlySet<string> = new Set([
  'Select', 'Get', 'NamedExec', 'NamedQuery', 'MustExec',
  'SelectContext', 'GetContext', 'NamedExecContext', 'NamedQueryContext', 'MustExecContext',
]);

/** Methods whose argument 0 is a destination (`&rows`), not a context. */
const DESTINATION_FIRST = new Set(['Select', 'Get']);

const RECEIVER_CLASSES = ['DB', 'Tx', 'Conn'] as const;

export const GO_SQLX_SINKS: SinkPattern[] = [
  ...RECEIVER_CLASSES.flatMap(cls => [...RECEIVER_QUERY_POSITION].map(([method, pos]): SinkPattern => ({
    method,
    class: cls,
    type: 'sql_injection',
    cwe: 'CWE-89',
    severity: 'critical',
    arg_positions: [pos],
    languages: ['go'],
    requires_import: [GO_SQLX_MODULE],
    ...(DESTINATION_FIRST.has(method) ? { safe_if_context_arg_at: 0 } : {}),
  }))),
  ...[...RECEIVER_QUERY_POSITION]
    .filter(([method]) => PACKAGE_FUNCS.has(method))
    .map(([method, pos]): SinkPattern => ({
      method,
      class: 'sqlx',
      type: 'sql_injection',
      cwe: 'CWE-89',
      severity: 'critical',
      arg_positions: [pos + 1],
      languages: ['go'],
      requires_import: [GO_SQLX_MODULE],
    })),
];

/**
 * True when `call` is a sqlx query call (in a file that imports sqlx) and every
 * tainted argument sits after the query string, i.e. is a bound parameter.
 * Such a value is handed to the driver for binding; it has not escaped into
 * unknown code.
 */
export function isGoSqlxBoundArgsCall(
  call: CallInfo,
  taintedPositions: readonly number[],
  imports: ReadonlyArray<ImportInfo>,
): boolean {
  if (taintedPositions.length === 0) return false;
  const receiverPos = RECEIVER_QUERY_POSITION.get(call.method_name);
  if (receiverPos === undefined) return false;
  if (!imports.some(i => i.from_package === GO_SQLX_MODULE || i.from_package?.startsWith(`${GO_SQLX_MODULE}/`))) return false;
  const receiver = call.receiver ?? '';
  let queryPos: number;
  if (receiver === 'sqlx') {
    if (!PACKAGE_FUNCS.has(call.method_name)) return false;
    queryPos = receiverPos + 1;
  } else {
    // A DB / Tx / Conn handle: `db`, `s.db`, `tx`, `h.DB`, a parameter typed `*sqlx.DB` (`DB`).
    const last = (receiver.split('.').pop() ?? '').toLowerCase();
    if (!/db|tx|conn/.test(last)) return false;
    queryPos = receiverPos;
  }
  return taintedPositions.every(p => p > queryPos);
}
