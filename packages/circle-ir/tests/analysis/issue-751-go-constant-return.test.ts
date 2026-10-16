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

  // A right-hand side that is merely unknown to const-prop (a request read, a
  // concat of one) must not be recorded as clean: that vetoes real flows.
  const handler = (body: string, imports = '"database/sql"\n\t"net/http"') => `package main

import (
	${imports}
)

func h(w http.ResponseWriter, r *http.Request, db *sql.DB) {
${body}
}
`;

  it('a Query().Get read chained through := concat still reports', async () => {
    const code = handler(`	f := r.URL.Query().Get("f")
	q := "SELECT id FROM items WHERE " + f
	db.Query(q)`);
    expect(await sinkLines(code, 'sql_injection')).toEqual([sqlLine(code)]);
  });

  it('a FormValue read chained through two := concats still reports', async () => {
    const code = handler(`	name := r.FormValue("name")
	where := "name = '" + name + "'"
	q := "SELECT id FROM items WHERE " + where
	db.Query(q)`);
    expect(await sinkLines(code, 'sql_injection')).toEqual([sqlLine(code)]);
  });

  it('a constant overwritten by a request-built value still reports', async () => {
    const code = handler(`	q := "SELECT 1"
	q = "SELECT id FROM items WHERE id = " + r.FormValue("id")
	db.Query(q)`);
    expect(await sinkLines(code, 'sql_injection')).toEqual([sqlLine(code)]);
  });

  it('a constant reassigned from the request in one branch still reports', async () => {
    const code = handler(`	cmd := "ls"
	if r.Method == "POST" {
		cmd = r.FormValue("c")
	}
	exec.Command(cmd).Run()`, '"database/sql"\n\t"net/http"\n\t"os/exec"');
    const line = code.split('\n').findIndex((l) => l.includes('exec.Command')) + 1;
    expect(await sinkLines(code, 'command_injection')).toEqual([line]);
  });

  it('a constant local in one function does not clear the same name in another', async () => {
    const code = `package main

import (
	"database/sql"
	"net/http"
)

func fixed(db *sql.DB) {
	query := "SELECT 1"
	db.Query(query)
}

func byName(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	name := r.URL.Query().Get("name")
	query := "SELECT id FROM users WHERE name = '" + name + "'"
	db.Query(query)
}
`;
    const queryLines = code
      .split('\n')
      .flatMap((l, i) => (l.includes('db.Query(query)') ? [i + 1] : []));
    expect(await sinkLines(code, 'sql_injection')).toEqual([queryLines[1]]);
  });
});
