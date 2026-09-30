/**
 * #343 remainder — a `bufio.Scanner` / `bufio.Reader` wrapping the HTTP
 * request body. `sc := bufio.NewScanner(r.Body); … sc.Text()` had a sink but
 * no source. Each `sc.Text()` / `sc.Bytes()` / `br.ReadString(…)` read in the
 * wrapper's own block is now an http_body source; wrappers over os.Stdin, a
 * file, or a fetched `resp.Body` stay silent.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const hdr = ['package main', 'import ("bufio";"database/sql";"net/http";"os";"os/exec")', ''];
const run = async (...body: string[]) => {
  const r = await analyze([...hdr, ...body].join('\n'), 'h.go', 'go');
  return {
    body: r.taint.sources.filter((s) => /HTTP request body/.test(s.location ?? '')),
    flows: (r.taint.flows ?? []).filter((f) => f.sink_type !== 'external_taint_escape').map((f) => f.sink_type),
  };
};

describe('#343 — bufio wrappers over the Go request body', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('sc := bufio.NewScanner(r.Body); line := sc.Text() flows to exec', async () => {
    const { body, flows } = await run('func h(w http.ResponseWriter, r *http.Request) {', '  sc := bufio.NewScanner(r.Body)', '  for sc.Scan() {', '    line := sc.Text()', '    exec.Command("sh", "-c", line).Run()', '  }', '}');
    expect(body.map((s) => [s.type, s.variable])).toEqual([['http_body', 'line']]);
    expect(flows).toContain('command_injection');
  });

  it('an inline sc.Text() inside a SQL string flows to the query on the same line', async () => {
    const { body, flows } = await run('func h(w http.ResponseWriter, r *http.Request, db *sql.DB) {', '  scanner := bufio.NewScanner(r.Body)', '  for scanner.Scan() {', '    db.Query("SELECT * FROM t WHERE x = \'" + scanner.Text() + "\'")', '  }', '}');
    expect(body.map((s) => s.type)).toEqual(['http_body']);
    expect(flows).toContain('sql_injection');
  });

  it('sc.Bytes() is a source too', async () => {
    const { body } = await run('func h(w http.ResponseWriter, r *http.Request) {', '  sc := bufio.NewScanner(r.Body)', '  for sc.Scan() {', '    b := sc.Bytes()', '    _ = b', '  }', '}');
    expect(body.map((s) => s.variable)).toEqual(['b']);
  });

  it('br := bufio.NewReader(r.Body); s, _ := br.ReadString(...) flows to exec', async () => {
    const { body, flows } = await run('func h(w http.ResponseWriter, r *http.Request) {', '  br := bufio.NewReader(r.Body)', "  s, _ := br.ReadString('\\n')", '  exec.Command(s).Run()', '}');
    expect(body.map((s) => [s.type, s.variable])).toEqual([['http_body', 's']]);
    expect(flows).toContain('command_injection');
  });

  it('a size-limited body (http.MaxBytesReader) is still the request body', async () => {
    const { body } = await run('func h(w http.ResponseWriter, r *http.Request) {', '  sc := bufio.NewScanner(http.MaxBytesReader(w, r.Body, 1<<20))', '  for sc.Scan() {', '    t := sc.Text()', '    _ = t', '  }', '}');
    expect(body.map((s) => s.variable)).toEqual(['t']);
  });

  it('does NOT seed a scanner over os.Stdin', async () => {
    const { body } = await run('func h(w http.ResponseWriter, r *http.Request) {', '  sc := bufio.NewScanner(os.Stdin)', '  for sc.Scan() {', '    t := sc.Text()', '    exec.Command(t).Run()', '  }', '}');
    expect(body).toEqual([]);
  });

  it('does NOT seed a scanner over a fetched response body', async () => {
    const { body } = await run('func h(w http.ResponseWriter, r *http.Request) {', '  resp, _ := http.Get("https://x")', '  sc := bufio.NewScanner(resp.Body)', '  for sc.Scan() {', '    t := sc.Text()', '    _ = t', '  }', '}');
    expect(body).toEqual([]);
  });

  it('does NOT leak into a same-named scanner over a file in another function', async () => {
    const { body } = await run(
      'func h(w http.ResponseWriter, r *http.Request) {', '  sc := bufio.NewScanner(r.Body)', '  for sc.Scan() {', '    a := sc.Text()', '    _ = a', '  }', '}',
      'func other(f *os.File) {', '  sc := bufio.NewScanner(f)', '  for sc.Scan() {', '    b := sc.Text()', '    exec.Command(b).Run()', '  }', '}',
    );
    expect(body.map((s) => s.variable)).toEqual(['a']);
  });

  it('stops at a re-binding of the wrapper to a non-request reader', async () => {
    const { body } = await run('func h(w http.ResponseWriter, r *http.Request, f *os.File) {', '  sc := bufio.NewScanner(r.Body)', '  sc = bufio.NewScanner(f)', '  for sc.Scan() {', '    t := sc.Text()', '    _ = t', '  }', '}');
    expect(body).toEqual([]);
  });
});

describe('#343 — inline bufio read does not taint the next line', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('log.Println(sc.Text()) followed by a constant x does not flow to exec(x)', async () => {
    const r = await analyze([
      'package main', 'import ("bufio";"log";"net/http";"os/exec")',
      'func h(w http.ResponseWriter, r *http.Request) {', '  sc := bufio.NewScanner(r.Body)', '  for sc.Scan() {',
      '    log.Println(sc.Text())', '    x := "fixed"', '    exec.Command(x).Run()', '  }', '}',
    ].join('\n'), 'adj.go', 'go');
    expect((r.taint.flows ?? []).filter((f) => f.sink_type === 'command_injection')).toEqual([]);
  });
});
