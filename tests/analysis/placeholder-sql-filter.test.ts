/**
 * Tests for placeholder-aware SQL injection sink filtering (P1 FP precision).
 *
 * Verifies that parameterized queries with placeholder patterns (?, $1, :name, %s)
 * are NOT flagged as SQL injection, while concatenated queries still fire.
 */

import { describe, it, expect } from 'vitest';
import { analyzeTaint } from '../../src/analysis/taint-matcher.js';
import type { CallInfo } from '../../src/types/index.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeCall(
  method: string,
  receiver: string | null,
  args: Array<{ expression: string; variable?: string; literal?: string | null }>,
  line = 10,
): CallInfo {
  return {
    method_name: method,
    receiver,
    arguments: args.map((a, i) => ({
      position: i,
      expression: a.expression,
      variable: a.variable ?? null,
      literal: a.literal ?? null,
    })),
    location: { line, column: 0 },
    in_method: 'testMethod',
  };
}

function sqlSinks(calls: CallInfo[]) {
  const result = analyzeTaint(calls, []);
  return result.sinks.filter(s => s.type === 'sql_injection');
}

// ---------------------------------------------------------------------------
// Go: db.Query("SELECT ... WHERE id = ?", input)
// ---------------------------------------------------------------------------

describe('Go-style parameterized queries', () => {
  // Go uses db.Query / db.QueryRow — method names that match existing sink patterns
  // when using class-matched receivers (Connection, Pool, Client).
  it('should NOT flag conn.query("...?", input) as sql_injection', () => {
    const calls = [makeCall('query', 'conn', [
      { expression: '"SELECT * FROM users WHERE id = ?"', literal: 'SELECT * FROM users WHERE id = ?' },
      { expression: 'input', variable: 'input' },
    ])];
    expect(sqlSinks(calls)).toHaveLength(0);
  });

  it('should NOT flag pool.query("...$1", input) as sql_injection', () => {
    const calls = [makeCall('query', 'pool', [
      { expression: '"SELECT name FROM users WHERE id = $1"', literal: 'SELECT name FROM users WHERE id = $1' },
      { expression: 'id', variable: 'id' },
    ])];
    expect(sqlSinks(calls)).toHaveLength(0);
  });

  it('should still flag conn.query(userInput) as sql_injection (no literal, no placeholder)', () => {
    const calls = [makeCall('query', 'conn', [
      { expression: 'userInput', variable: 'userInput' },
    ])];
    expect(sqlSinks(calls).length).toBeGreaterThanOrEqual(1);
  });

  it('should still flag pool.query("SELECT ... " + input, cb) as sql_injection (concatenation)', () => {
    const calls = [makeCall('query', 'pool', [
      { expression: '"SELECT * FROM users WHERE id = " + input', literal: null },
      { expression: 'callback', variable: 'callback' },
    ])];
    expect(sqlSinks(calls).length).toBeGreaterThanOrEqual(1);
  });
});

// ---------------------------------------------------------------------------
// Python: cursor.execute("SELECT ... WHERE id = %s", (param,))
// ---------------------------------------------------------------------------

describe('Python parameterized queries', () => {
  it('should NOT flag cursor.execute("...%s", (param,)) as sql_injection', () => {
    const calls = [makeCall('execute', 'cursor', [
      { expression: '"SELECT * FROM users WHERE id = %s"', literal: 'SELECT * FROM users WHERE id = %s' },
      { expression: '(param,)', variable: null },
    ])];
    expect(sqlSinks(calls)).toHaveLength(0);
  });

  it('should NOT flag cursor.execute("...%s...%s", (a, b)) as sql_injection', () => {
    const calls = [makeCall('execute', 'cursor', [
      { expression: '"SELECT * FROM t WHERE a = %s AND b = %s"', literal: 'SELECT * FROM t WHERE a = %s AND b = %s' },
      { expression: '(a, b)', variable: null },
    ])];
    expect(sqlSinks(calls)).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Java: jdbcTemplate.query("SELECT ... WHERE id = ?", mapper, args)
// ---------------------------------------------------------------------------

describe('Java parameterized queries', () => {
  it('should NOT flag jdbcTemplate.query("...?", mapper, arg) as sql_injection', () => {
    const calls = [makeCall('query', 'jdbcTemplate', [
      { expression: '"SELECT * FROM users WHERE id = ?"', literal: 'SELECT * FROM users WHERE id = ?' },
      { expression: 'rowMapper', variable: 'rowMapper' },
      { expression: 'id', variable: 'id' },
    ])];
    expect(sqlSinks(calls)).toHaveLength(0);
  });

  it('should NOT flag stmt.executeQuery("...?") with named params as sql_injection', () => {
    const calls = [makeCall('executeQuery', 'stmt', [
      { expression: '"SELECT * FROM users WHERE name = :name"', literal: 'SELECT * FROM users WHERE name = :name' },
      { expression: 'params', variable: 'params' },
    ])];
    expect(sqlSinks(calls)).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Node.js: existing [params] pattern (regression check)
// ---------------------------------------------------------------------------

describe('Node.js parameterized queries (regression)', () => {
  it('should NOT flag db.query(sql, [id]) as sql_injection', () => {
    const calls = [makeCall('query', 'db', [
      { expression: '"SELECT * FROM users WHERE id = ?"', literal: 'SELECT * FROM users WHERE id = ?' },
      { expression: '[id]', variable: null },
    ])];
    expect(sqlSinks(calls)).toHaveLength(0);
  });

  it('should NOT flag pool.query(sql, [id, name]) as sql_injection', () => {
    const calls = [makeCall('query', 'pool', [
      { expression: '"SELECT * FROM users WHERE id = ? AND name = ?"', literal: null },
      { expression: '[id, name]', variable: null },
    ])];
    expect(sqlSinks(calls)).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Unsafe patterns — these MUST still fire
// ---------------------------------------------------------------------------

describe('Unsafe SQL patterns (true positives)', () => {
  it('should flag stmt.executeQuery("..." + input) as sql_injection', () => {
    const calls = [makeCall('executeQuery', 'stmt', [
      { expression: '"SELECT * FROM users WHERE id = " + userInput', literal: null },
    ])];
    expect(sqlSinks(calls).length).toBeGreaterThanOrEqual(1);
  });

  it('should flag stmt.executeQuery(dynamicQuery) as sql_injection (no literal)', () => {
    const calls = [makeCall('executeQuery', 'stmt', [
      { expression: 'dynamicQuery', variable: 'dynamicQuery' },
    ])];
    expect(sqlSinks(calls).length).toBeGreaterThanOrEqual(1);
  });

  it('should flag template string with interpolation as sql_injection', () => {
    const calls = [makeCall('query', 'db', [
      { expression: '`SELECT * FROM users WHERE id = ${id}`', literal: null },
      { expression: 'callback', variable: 'callback' },
    ])];
    expect(sqlSinks(calls).length).toBeGreaterThanOrEqual(1);
  });
});
