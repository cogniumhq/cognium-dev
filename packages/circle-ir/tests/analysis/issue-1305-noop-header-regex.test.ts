/**
 * cognium-dev#1305 R2: the `def` / `func` header regexes behind the #581 no-op
 * helper check run over every Python and Go function. Their return-annotation
 * tails (`\s*[\w.\[\], ]+\s*` and `\s*\(?[\w.\[\]*, ]*\)?\s*`) let three
 * quantifiers share one run of spaces, so a long gap before a result type the
 * class does not cover backtracked cubically: 4000 spaces took about 12 s per
 * file. The rewritten tails start and end on a non-space and stay linear, and
 * still read the spaced headers the old ones did.
 *
 * SAST regression fixtures — the handlers are deliberately vulnerable.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const GAP = ' '.repeat(4000);

async function timed(code: string, file: string, language: 'go' | 'python'): Promise<number> {
  const t = performance.now();
  await analyze(code, file, language);
  return performance.now() - t;
}

async function sqlLines(code: string, file: string, language: 'go' | 'python'): Promise<number[]> {
  const r = await analyze(code, file, language);
  return [...new Set((r.taint.flows ?? []).filter((f) => f.sink_type === 'sql_injection').map((f) => f.sink_line))].sort((a, b) => a - b);
}

const sinkLine = (code: string, marker: string) => code.split('\n').findIndex((l) => l.includes(marker)) + 1;

const pyApp = (header: string) => `import sqlite3
from flask import Flask, request
app = Flask(__name__)
${header}
    return v.strip()
@app.route("/a")
def by_id():
    uid = sanitize(request.args.get("id"))
    db = sqlite3.connect("d.db")
    db.execute("SELECT * FROM t WHERE id='" + uid + "'")
    return "ok"
`;

const goApp = (header: string) => `package main

import (
	"database/sql"
	"net/http"
	"strings"
)

${header}
	return strings.TrimSpace(v)
}

func byID(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	uid := sanitize(r.URL.Query().Get("id"))
	db.Query("SELECT * FROM t WHERE id='" + uid + "'")
}
`;

describe('cognium-dev#1305 R2 no-op helper header regexes are linear', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('python: a long gap before an annotation outside the class analyzes quickly', async () => {
    const code = `def tidy(v) ->${GAP}'str':\n    return v\n`;
    expect(await timed(code, 'gap.py', 'python')).toBeLessThan(3000);
  }, 60_000);

  it('go: a long gap before a result type outside the class analyzes quickly', async () => {
    const code = `package main\n\nfunc tidy(v string)${GAP}<-chan string {\n\treturn nil\n}\n`;
    expect(await timed(code, 'gap.go', 'go')).toBeLessThan(3000);
  }, 60_000);

  describe('spaced headers are still read (the helper is a no-op, so the sink reports)', () => {
    for (const header of [
      'def sanitize(v) -> str :',
      `def sanitize(v)  ->  Optional[str]${' '.repeat(40)}:`,
      'def sanitize(v) :',
    ]) {
      it(`python: ${JSON.stringify(header.replace(/ {2,}/g, ' … '))}`, async () => {
        const code = pyApp(header);
        expect(await sqlLines(code, 'lookup.py', 'python')).toEqual([sinkLine(code, 'db.execute')]);
      });
    }

    for (const header of [
      'func sanitize(v string) ( string ) {',
      `func sanitize(v string)${' '.repeat(40)}string${' '.repeat(40)}{`,
      'func sanitize(v string) (out string) {',
    ]) {
      it(`go: ${JSON.stringify(header.replace(/ {2,}/g, ' … '))}`, async () => {
        const code = goApp(header);
        expect(await sqlLines(code, 'lookup.go', 'go')).toEqual([sinkLine(code, 'db.Query')]);
      });
    }
  });
});
