/**
 * cognium-dev#783: rule-(E) constant-return veto must see `var uid = helper(...)`
 * and `uid := pkg.helper(...)` callees, not only `uid := helper(...)`.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

async function sinkLines(code: string, type: string, file = 'shapes.go'): Promise<number[]> {
  const r = await analyze(code, file, 'go');
  return [...new Set((r.taint.flows ?? []).filter((f) => f.sink_type === type).map((f) => f.sink_line))].sort(
    (a, b) => a - b,
  );
}

const sqlApp = (bodyLine: string, helper: string) => `package main

import (
	"database/sql"
	"net/http"
)

${helper}

func byID(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	${bodyLine}
	db.Query("SELECT * FROM t WHERE id='" + uid + "'")
}
`;

describe('cognium-dev#783 — Go constant-return callee shapes', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const helper = `func sanitize(v string) string {
	return "fixed"
}`;

  it('var uid = sanitize(...) stays clean', async () => {
    const code = sqlApp('var uid = sanitize(r.URL.Query().Get("id"))', helper);
    expect(await sinkLines(code, 'sql_injection')).toEqual([]);
  });

  it('uid := recv.sanitize(...) stays clean when the callee is qualified', async () => {
    const code = `package main

import (
	"database/sql"
	"net/http"
)

type sanitizer struct{}

func (sanitizer) sanitize(v string) string {
	return "fixed"
}

var defaultSanitizer sanitizer

func byID(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	uid := defaultSanitizer.sanitize(r.URL.Query().Get("id"))
	db.Query("SELECT * FROM t WHERE id='" + uid + "'")
}
`;
    expect(await sinkLines(code, 'sql_injection')).toEqual([]);
  });

  it('multiline uid := sanitize(...) stays clean when callee is on the next line', async () => {
    const code = sqlApp(
      `uid :=\n\t\tsanitize(r.URL.Query().Get("id"))`,
      helper,
    );
    expect(await sinkLines(code, 'sql_injection')).toEqual([]);
  });

  it('multiline var uid = sanitize(...) stays clean', async () => {
    const code = sqlApp(
      `var uid = sanitize(\n\t\tr.URL.Query().Get("id"))`,
      helper,
    );
    expect(await sinkLines(code, 'sql_injection')).toEqual([]);
  });

  it('pass-through helper with var form still reports', async () => {
    const leaky = `func sanitize(v string) string {
	return v
}`;
    const code = sqlApp('var uid = sanitize(r.URL.Query().Get("id"))', leaky);
    const sinkLine = code.split('\n').findIndex((l) => l.includes('db.Query')) + 1;
    expect(await sinkLines(code, 'sql_injection')).toEqual([sinkLine]);
  });
});
