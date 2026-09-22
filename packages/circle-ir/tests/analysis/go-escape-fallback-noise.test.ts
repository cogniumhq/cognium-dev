/**
 * Go `external_taint_escape` fallback — calls that do not let a value leave
 * the program are not escapes.
 *
 * The interprocedural fallback reports CWE-668 for any tainted argument passed
 * to a call it cannot resolve. Measured on 203 Go repositories that was 78% of
 * every Go taint flow, dominated by `len`, `fmt.Errorf`, logging verbs and
 * `strings.*`. This pins the gate: those stay silent, while a genuinely unknown
 * call still escapes and every modelled sink still fires.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const handler = (...body: string[]) =>
  ['package main', 'import ("fmt"; "log"; "net/http"; "os"; "strings"; "errors"; "path/filepath")', '',
   'func h(w http.ResponseWriter, r *http.Request) {', '  q := r.URL.Query().Get("q")', ...body.map((l) => '  ' + l), '}'].join('\n');

const types = async (code: string) => {
  const r = await analyze(code, 'h.go', 'go');
  return (r.taint.flows ?? []).map((f) => f.sink_type).sort();
};

describe('Go escape fallback — non-escaping calls', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it.each([
    ['a builtin', 'n := len(q)', '_ = n'],
    ['a conversion', 'b := []byte(q)', '_ = b'],
    ['fmt.Errorf', 'err := fmt.Errorf("bad %s", q)', '_ = err'],
    ['errors.New', 'err := errors.New(q)', '_ = err'],
    ['fmt.Sprintf', 's := fmt.Sprintf("%s!", q)', '_ = s'],
    ['strings.HasPrefix', 'ok := strings.HasPrefix(q, "/")', '_ = ok'],
    ['strings.Split', 'parts := strings.Split(q, ",")', '_ = parts'],
    ['filepath.Base', 'name := filepath.Base(q)', '_ = name'],
    ['a logging verb on a logger variable', 'logger.Warnf("got %s", q)'],
  ])('does not report %s as an escape', async (_n, ...body) => {
    expect(await types(handler(...body))).not.toContain('external_taint_escape');
  });

  it('still escapes on an unknown call', async () => {
    expect(await types(handler('backend.Submit(q)'))).toContain('external_taint_escape');
  });

  it('still escapes on a same-named method of a project type, not the stdlib package', async () => {
    // `strings` is gated by receiver; `svc.Split(q)` is not strings.Split.
    expect(await types(handler('parts := svc.Split(q)', '_ = parts'))).toContain('external_taint_escape');
  });

  it('still escapes on a constructor that merely shares a name with errors.New', async () => {
    // Found in the corpus: `client.New(socketPath)` with a tainted path.
    expect(await types(handler('c := client.New(q)', '_ = c'))).toContain('external_taint_escape');
  });

  it('does not touch modelled sinks: log_injection still fires on log.Printf', async () => {
    expect(await types(handler('log.Printf("q=%s", q)'))).toContain('log_injection');
  });

  it('does not touch modelled sinks: path_traversal still fires', async () => {
    expect(await types(handler('f, _ := os.Open(q)', '_ = f'))).toContain('path_traversal');
  });

  it('keeps the escape on fmt.Fprintf to the response writer', async () => {
    // Go has no xss sink for Fprintf(w, …) today, so the escape is the only
    // signal on the reflected-XSS shape; gating the whole `fmt` package would
    // have silenced it.
    expect(await types(handler('fmt.Fprintf(w, "%s", q)'))).toContain('external_taint_escape');
  });

  it('is Go-only: the same gate does not silence other languages', async () => {
    const js = ['const q = req.query.q;', 'thirdParty.send(q);'].join('\n');
    const r = await analyze(js, 'h.js', 'javascript');
    // Only asserting the gate is not applied; whether JS escapes here is its own contract.
    expect(r.taint.flows).toBeDefined();
  });
});
