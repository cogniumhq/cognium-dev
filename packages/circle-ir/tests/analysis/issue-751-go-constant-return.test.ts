/**
 * cognium-dev#751 (case 1): a Go helper that ignores its parameter and returns a
 * constant must not propagate taint to the sink.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

async function sinkLines(code: string, type: string, file = 'lookup.go'): Promise<number[]> {
  const r = await analyze(code, file, 'go');
  return [...new Set((r.taint.flows ?? []).filter((f) => f.sink_type === type).map((f) => f.sink_line))].sort(
    (a, b) => a - b,
  );
}

const sqlApp = (helper: string, call = 'sanitize') => `package main

import (
	"database/sql"
	"net/http"
)

${helper}

func byID(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	uid := ${call}(r.URL.Query().Get("id"))
	db.Query("SELECT * FROM t WHERE id='" + uid + "'")
}
`;

const sqlLine = (code: string) => code.split('\n').findIndex((l) => l.includes('db.Query')) + 1;

describe('cognium-dev#751 — Go constant-return helper', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('sanitize() returning a fixed string does not report sql_injection', async () => {
    const code = sqlApp(`func sanitize(v string) string {
	return "fixed"
}`);
    expect(await sinkLines(code, 'sql_injection')).toEqual([]);
  });

  it('the same body under a neutral name also stays clean', async () => {
    const code = sqlApp(`func tidy(v string) string {
	return "fixed"
}`, 'tidy');
    expect(await sinkLines(code, 'sql_injection')).toEqual([]);
  });

  it('a pass-through helper still reports (control)', async () => {
    const code = sqlApp(`func sanitize(v string) string {
	return v
}`);
    expect(await sinkLines(code, 'sql_injection')).toEqual([sqlLine(code)]);
  });
});
