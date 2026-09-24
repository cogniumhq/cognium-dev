/**
 * #343 — Go HTTP request body is modelled as an http_body source.
 *
 * `json.NewDecoder(r.Body).Decode(&x)`, `xml.NewDecoder(r.Body)`, and
 * `io.Copy(dst, r.Body)` were silent; `io.ReadAll(r.Body)` fired only as the
 * generic `io_input` (indistinguishable from a local file). The source is
 * scoped to `.Body` on a name declared as an `*http.Request` parameter, so a
 * fetched `resp.Body` (an `*http.Response`) never matches.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const hdr = ['package main', 'import ("bytes";"encoding/json";"encoding/xml";"io";"net/http";"os";"os/exec")', ''];
const run = async (...body: string[]) => {
  const r = await analyze([...hdr, ...body].join('\n'), 'h.go', 'go');
  return {
    body: r.taint.sources.filter((s) => /HTTP request body/.test(s.location ?? '')),
    flows: (r.taint.flows ?? []).filter((f) => f.sink_type !== 'external_taint_escape').map((f) => f.sink_type),
  };
};

describe('#343 — Go request body source', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('json.NewDecoder(r.Body).Decode(&q) seeds http_body and flows to a sink', async () => {
    const { body, flows } = await run('type Q struct{ Cmd string }', 'func h(w http.ResponseWriter, r *http.Request) {', '  var q Q', '  json.NewDecoder(r.Body).Decode(&q)', '  exec.Command("sh", "-c", q.Cmd)', '}');
    expect(body.map((s) => [s.type, s.variable])).toEqual([['http_body', 'q']]);
    expect(flows).toContain('command_injection');
  });

  it('xml.NewDecoder(r.Body).Decode(&q) too', async () => {
    const { body } = await run('type Q struct{ Cmd string }', 'func h(w http.ResponseWriter, r *http.Request) {', '  var q Q', '  xml.NewDecoder(r.Body).Decode(&q)', '  _ = q', '}');
    expect(body.map((s) => s.type)).toEqual(['http_body']);
  });

  it('io.ReadAll(r.Body) is typed http_body (in addition to io_input)', async () => {
    const { body } = await run('func h(w http.ResponseWriter, r *http.Request) {', '  b, _ := io.ReadAll(r.Body)', '  _ = b', '}');
    expect(body.map((s) => s.variable)).toEqual(['b']);
  });

  it('io.Copy(dst, r.Body) binds the destination', async () => {
    const { body } = await run('func h(w http.ResponseWriter, r *http.Request) {', '  var buf bytes.Buffer', '  io.Copy(&buf, r.Body)', '  _ = buf', '}');
    expect(body.map((s) => s.variable)).toEqual(['buf']);
  });

  it('recognises an inline closure handler', async () => {
    const { body } = await run('func setup() {', '  mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {', '    var q struct{ X string }', '    json.NewDecoder(r.Body).Decode(&q)', '    _ = q', '  })', '}');
    expect(body.map((s) => s.type)).toEqual(['http_body']);
  });

  it('a differently-named request parameter works', async () => {
    const { body } = await run('func h(rw http.ResponseWriter, req *http.Request) {', '  var q struct{ X string }', '  json.NewDecoder(req.Body).Decode(&q)', '  _ = q', '}');
    expect(body.map((s) => s.type)).toEqual(['http_body']);
  });

  it('does NOT taint a fetched response body (resp.Body is *http.Response)', async () => {
    const { body } = await run('func h(w http.ResponseWriter, r *http.Request) {', '  resp, _ := http.Get("https://x")', '  var q struct{ X string }', '  json.NewDecoder(resp.Body).Decode(&q)', '  _ = q', '}');
    // `resp` is not a declared *http.Request parameter → no request-body source.
    // (r is present so the file has a request param, but resp.Body is separate.)
    expect(body).toEqual([]);
  });

  it('does NOT taint io.ReadAll of a non-request reader', async () => {
    const { body } = await run('func read(f *os.File) {', '  b, _ := io.ReadAll(f)', '  _ = b', '}');
    expect(body).toEqual([]);
  });

  it('a validated / constant body still flows (no false suppression) but is the source', async () => {
    const { body } = await run('func h(w http.ResponseWriter, r *http.Request) {', '  var q struct{ Name string }', '  json.NewDecoder(r.Body).Decode(&q)', '  _ = q.Name', '}');
    expect(body.length).toBe(1);
  });
});

/**
 * #472 — the Go text-scan sources bind a variable NAME. Without a method tag,
 * the argument-expression matcher linked a same-named local in a different
 * function to the source (`b := []byte("x")` in `out()` inherited the body
 * taint from `h()`). Sources are now tagged with the method of a call on their
 * line, so the #101 same-method gate applies.
 */
describe('#472 — Go text-scan sources stay in their own function', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('io.ReadAll(r.Body) in h() does not taint a same-named literal in out()', async () => {
    const { flows } = await run(
      'func h(w http.ResponseWriter, r *http.Request) {', '  b, _ := io.ReadAll(r.Body)', '  _ = len(b)', '}',
      'func out() {', '  b := []byte("fixed.txt")', '  os.OpenFile("/data/"+string(b), os.O_RDONLY, 0)', '}',
    );
    expect(flows).toEqual([]);
  });

  it('a decoded struct in h() does not taint a same-named struct literal in out()', async () => {
    const { flows } = await run(
      'func h(w http.ResponseWriter, r *http.Request) {', '  var in struct{ Cmd string }', '  json.NewDecoder(r.Body).Decode(&in)', '  _ = in', '}',
      'func out() {', '  in := struct{ Cmd string }{"ls"}', '  exec.Command(in.Cmd).Run()', '}',
    );
    expect(flows).toEqual([]);
  });

  it('a gRPC getter source does not leak across functions either', async () => {
    const r = await analyze([
      'package main', 'import ("context";"os";pb "x/pb")', 'type S struct{}',
      'func (s *S) Put(ctx context.Context, req *pb.PutRequest) (*pb.R, error) {', '  p := req.GetTargetPath()', '  _ = p', '  return nil, nil', '}',
      'func out() {', '  p := []byte("fixed.txt")', '  os.OpenFile("/data/"+string(p), os.O_RDONLY, 0)', '}',
    ].join('\n'), 'g.go', 'go');
    expect((r.taint.flows ?? []).filter((f) => f.sink_type === 'path_traversal')).toEqual([]);
  });

  it('keeps the same-function flow, including through a conversion and a goroutine closure', async () => {
    const same = await run('func h(w http.ResponseWriter, r *http.Request) {', '  var in struct{ Cmd string }', '  json.NewDecoder(r.Body).Decode(&in)', '  exec.Command(in.Cmd).Run()', '}');
    expect(same.flows).toContain('command_injection');
    const closure = await run('func h(w http.ResponseWriter, r *http.Request) {', '  b, _ := io.ReadAll(r.Body)', '  go func() {', '    os.OpenFile("/data/"+string(b), os.O_RDONLY, 0)', '  }()', '}');
    expect(closure.flows).toContain('path_traversal');
  });
});
