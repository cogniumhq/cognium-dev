/**
 * cognium-dev#581 (slice, Go): a same-file `func` whose body is a single
 * `return <expr>` built only from its own parameters, string literals, `+`, the
 * pass-through calls `strings.TrimSpace` / `ToLower` / `ToUpper` and the
 * `string()` conversion is not credited as a sanitizer by the class-less
 * `sanitize` / `escape` rows. A helper that really escapes keeps today's by-name
 * credit, and so does a call through a package or receiver.
 *
 * SAST regression fixtures — the handlers are deliberately vulnerable.
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

const trimOnly = (name = 'sanitize') => `func ${name}(v string) string {
	return strings.TrimSpace(v)
}`;

describe('cognium-dev#581 Go no-op helper is not credited by name', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('a TrimSpace-only sanitize() helper reports sql_injection', async () => {
    const code = sqlApp(trimOnly());
    expect(await sinkLines(code, 'sql_injection')).toEqual([sqlLine(code)]);
  });

  it('the same helper under a neutral name reports too (control)', async () => {
    const code = sqlApp(trimOnly('tidy'), 'tidy');
    expect(await sinkLines(code, 'sql_injection')).toEqual([sqlLine(code)]);
  });

  for (const [label, body] of [
    ['a lower-case wrap', 'return "[" + strings.ToLower(v) + "]"'],
    ['a string() conversion', 'return string(v)'],
    ['a pass-through', 'return v'],
    ['a trailing comment', 'return strings.TrimSpace(v) // keep it short'],
    ['a call split over two lines', 'return strings.\n\t\tTrimSpace(v)'],
  ] as const) {
    it(`reports for ${label}`, async () => {
      const code = sqlApp(`func sanitize(v string) string {\n\t${body}\n}`);
      expect(await sinkLines(code, 'sql_injection')).toEqual([sqlLine(code)]);
    });
  }

  it('renamed parameter and a second unused parameter still report', async () => {
    const code = sqlApp('func sanitize(raw string, limit int) string {\n\treturn strings.TrimSpace(raw)\n}');
    expect(await sinkLines(code, 'sql_injection')).toEqual([sqlLine(code)]);
  });

  describe('keeps its by-name credit', () => {
    it('a helper that really escapes the quote (ReplaceAll)', async () => {
      const code = sqlApp('func sanitize(v string) string {\n\treturn strings.ReplaceAll(v, "\'", "\'\'")\n}');
      expect(await sinkLines(code, 'sql_injection')).toEqual([]);
    });

    it('a helper with a second statement', async () => {
      const code = sqlApp('func sanitize(v string) string {\n\tv = strings.TrimSpace(v)\n\treturn strings.ReplaceAll(v, "\'", "\'\'")\n}');
      expect(await sinkLines(code, 'sql_injection')).toEqual([]);
    });

    it('a helper with a branch', async () => {
      const code = sqlApp('func sanitize(v string) string {\n\tif strings.Contains(v, "\'") {\n\t\treturn ""\n\t}\n\treturn v\n}');
      expect(await sinkLines(code, 'sql_injection')).toEqual([]);
    });

    it('a call through a package qualifier is not read as the local helper', async () => {
      const code = sqlApp(trimOnly(), 'sanitizer.sanitize');
      expect(await sinkLines(code, 'sql_injection')).toEqual([]);
    });

    it('a same-named method with a real body keeps the credit', async () => {
      const code = sqlApp(`${trimOnly()}

type store struct{}

func (s *store) sanitize(v string) string {
	return strings.ReplaceAll(v, "'", "''")
}`);
      expect(await sinkLines(code, 'sql_injection')).toEqual([]);
    });

    it('a local closure with the same name is a different helper', async () => {
      const code = `package main

import (
	"database/sql"
	"net/http"
	"strings"
)

func sanitize(v string) string {
	return strings.TrimSpace(v)
}

func byID(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	sanitize := func(v string) string { return strings.ReplaceAll(v, "'", "''") }
	uid := sanitize(r.URL.Query().Get("id"))
	db.Query("SELECT * FROM t WHERE id='" + uid + "'")
}
`;
      expect(await sinkLines(code, 'sql_injection')).toEqual([]);
    });

    it('a class-scoped sanitizer row is untouched: html.EscapeString still credits xss', async () => {
      const code = `package main

import (
	"fmt"
	"html"
	"net/http"
)

func page(w http.ResponseWriter, r *http.Request) {
	name := html.EscapeString(r.URL.Query().Get("n"))
	fmt.Fprint(w, "<p>"+name+"</p>")
}
`;
      expect(await sinkLines(code, 'xss')).toEqual([]);
    });
  });

  it('xss: a trim-only escape() helper reports, a renamed twin matches', async () => {
    const page = (name: string) => `package main

import (
	"fmt"
	"net/http"
	"strings"
)

func ${name}(v string) string {
	return strings.TrimSpace(v)
}

func page(w http.ResponseWriter, r *http.Request) {
	n := ${name}(r.URL.Query().Get("n"))
	fmt.Fprint(w, "<p>"+n+"</p>")
}
`;
    const a = await sinkLines(page('escape'), 'xss');
    const b = await sinkLines(page('trimmed'), 'xss');
    expect(a.length).toBeGreaterThanOrEqual(1);
    expect(a).toEqual(b);
  });
});
