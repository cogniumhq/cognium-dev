/**
 * #456 — Go `fmt.Fprint*(w, …)` is xss when, and only when, `w` is the
 * enclosing handler's http.ResponseWriter.
 *
 * Before: the xss sink covered only arg[1] (the format string), so the common
 * reflected-XSS shape `Fprintf(w, "%s", q)` produced no xss finding, while
 * `Fprintf(os.Stderr, tainted)` did. Now the varargs count and the writer is
 * checked against the function signature.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const go = (sig: string, ...body: string[]) =>
  ['package main', 'import ("fmt"; "net/http"; "os"; "bytes")', '', sig, '  q := r.URL.Query().Get("q")', ...body.map((l) => '  ' + l), '}'].join('\n');
const HANDLER = 'func h(w http.ResponseWriter, r *http.Request) {';

const flows = async (code: string) => {
  const r = await analyze(code, 'h.go', 'go');
  return (r.taint.flows ?? []).map((f) => f.sink_type);
};

describe('#456 — Go Fprint* to a ResponseWriter', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it.each([
    ['Fprintf varargs', 'fmt.Fprintf(w, "hello %s", q)'],
    ['Fprintf tainted format', 'fmt.Fprintf(w, q)'],
    ['Fprint', 'fmt.Fprint(w, q)'],
    ['Fprintln', 'fmt.Fprintln(w, "got:", q)'],
  ])('%s to the handler writer is xss', async (_n, line) => {
    expect(await flows(go(HANDLER, line))).toContain('xss');
  });

  it('recognises a differently named writer and a wrapped signature', async () => {
    const code = go('func h(\n  rw http.ResponseWriter,\n  r *http.Request,\n) {', 'fmt.Fprintf(rw, "%s", q)');
    expect(await flows(code)).toContain('xss');
  });

  it.each([
    ['stderr', 'fmt.Fprintf(os.Stderr, "%s", q)'],
    ['a buffer', 'var b bytes.Buffer', 'fmt.Fprintf(&b, "%s", q)', '_ = b'],
    ['a buffer variable', 'b := &bytes.Buffer{}', 'fmt.Fprintf(b, "%s", q)', '_ = b'],
  ])('to %s is not xss', async (_n, ...body) => {
    const f = await flows(go(HANDLER, ...body));
    expect(f).not.toContain('xss');
  });

  it('keeps the CWE-134 format_string sink on a non-writer with a tainted format', async () => {
    expect(await flows(go(HANDLER, 'fmt.Fprintf(os.Stderr, q)'))).toContain('format_string');
  });

  it('recognises the writer of an inline closure handler (httprouter/chi shape)', async () => {
    const code = ['package main', 'import ("fmt"; "net/http")', '',
      'func setup() {', '  router.GET("/", func(w http.ResponseWriter, r *http.Request) {',
      '    host := r.Header.Get("Origin")', '    fmt.Fprintf(w, "<a href=%s>x</a>", host)', '  })', '}'].join('\n');
    const r = await analyze(code, 'h.go', 'go');
    expect((r.taint.flows ?? []).map((f) => f.sink_type)).toContain('xss');
  });

  it('is silent when the writer is a plain parameter that is not a ResponseWriter', async () => {
    const code = ['package main', 'import ("fmt"; "io"; "net/http")', '',
      'func render(out io.Writer, r *http.Request) {', '  q := r.URL.Query().Get("q")', '  fmt.Fprintf(out, "%s", q)', '}'].join('\n');
    expect(await flows(code)).not.toContain('xss');
  });
});
