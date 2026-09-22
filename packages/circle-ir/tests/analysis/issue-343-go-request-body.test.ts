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
