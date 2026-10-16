/**
 * cognium-dev#751 (slice, Go): grouped parameter lists in `isGoNoopBody` must
 * credit every name in the signature, not only the first name per declaration.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

async function sinkLines(code: string, type: string, file = 'lookup.go'): Promise<number[]> {
  const r = await analyze(code, file, 'go');
  return [...new Set((r.taint.flows ?? []).filter((f) => f.sink_type === type).map((f) => f.sink_line))].sort((a, b) => a - b);
}

const sqlApp = (helper: string, call = 'sanitize') => `package main

import (
	"database/sql"
	"net/http"
	"strings"
)

var _ = strings.ToLower

${helper}

func byID(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	uid := ${call}(r.URL.Query().Get("id"))
	db.Query("SELECT * FROM t WHERE id='" + uid + "'")
}
`;

const sqlLine = (code: string) => code.split('\n').findIndex((l) => l.includes('db.Query')) + 1;

describe('cognium-dev#751 Go grouped parameter names in isGoNoopBody', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('TrimSpace on grouped (a, b string) when body uses b reports', async () => {
    const code = sqlApp('func sanitize(a, b string) string {\n\treturn strings.TrimSpace(b)\n}');
    expect(await sinkLines(code, 'sql_injection')).toEqual([sqlLine(code)]);
  });

  it('ToLower on three grouped names when body uses last reports', async () => {
    const code = sqlApp('func sanitize(a, b, c string) string {\n\treturn strings.ToLower(c)\n}');
    expect(await sinkLines(code, 'sql_injection')).toEqual([sqlLine(code)]);
  });

  it('concatenation using v and w in grouped (v, w string) reports', async () => {
    const code = sqlApp('func sanitize(v, w string) string {\n\treturn strings.TrimSpace(v) + w\n}');
    expect(await sinkLines(code, 'sql_injection')).toEqual([sqlLine(code)]);
  });

  it('TrimSpace on b with trailing int param reports', async () => {
    const code = sqlApp('func sanitize(a, b string, n int) string {\n\treturn strings.TrimSpace(b)\n}');
    expect(await sinkLines(code, 'sql_injection')).toEqual([sqlLine(code)]);
  });

  it('neutral tidy name with grouped params still reports (control)', async () => {
    const code = sqlApp('func tidy(a, b string) string {\n\treturn strings.TrimSpace(b)\n}', 'tidy');
    expect(await sinkLines(code, 'sql_injection')).toEqual([sqlLine(code)]);
  });

  it('grouped ReplaceAll on b keeps by-name credit (negative)', async () => {
    const code = sqlApp('func sanitize(a, b string) string {\n\treturn strings.ReplaceAll(b, "\'", "\'\'")\n}');
    expect(await sinkLines(code, 'sql_injection')).toEqual([]);
  });
});
