/**
 * cognium-dev #492 — Go `r.PostForm` / `r.Form` / `r.MultipartForm.Value`
 * after ParseForm are the same request data as `r.FormValue`, and were silent.
 *
 * `.Get` is a call; the extractor rewrites it to a synthetic class so a
 * plain `url.Values.Get` does not match. The index form is not a call and
 * is seeded from the LHS.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const hdr = ['package main', 'import ("net/http"; "net/url"; "os/exec")', ''];
const run = async (...body: string[]) => {
  const r = await analyze([...hdr, ...body].join('\n'), 'h.go', 'go');
  return (r.taint.flows ?? [])
    .filter((f) => f.sink_type === 'command_injection' && !f.sanitized)
    .map((f) => f.sink_type);
};

describe('#492 — Go request form map reads are sources', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('r.PostForm.Get flows to exec.Command', async () => {
    const flows = await run(
      'func h(w http.ResponseWriter, r *http.Request) {',
      '  r.ParseForm()',
      '  cmd := r.PostForm.Get("cmd")',
      '  exec.Command(cmd).Run()',
      '}',
    );
    expect(flows).toContain('command_injection');
  });

  it('r.Form.Get flows to exec.Command', async () => {
    const flows = await run(
      'func h(w http.ResponseWriter, r *http.Request) {',
      '  cmd := r.Form.Get("cmd")',
      '  exec.Command(cmd).Run()',
      '}',
    );
    expect(flows).toContain('command_injection');
  });

  it('r.Form[k][0] flows to exec.Command', async () => {
    const flows = await run(
      'func h(w http.ResponseWriter, r *http.Request) {',
      '  c2 := r.Form["c"][0]',
      '  exec.Command(c2).Run()',
      '}',
    );
    expect(flows).toContain('command_injection');
  });

  it('r.MultipartForm.Value[k][0] flows to exec.Command', async () => {
    const flows = await run(
      'func h(w http.ResponseWriter, r *http.Request) {',
      '  v := r.MultipartForm.Value["k"][0]',
      '  exec.Command(v).Run()',
      '}',
    );
    expect(flows).toContain('command_injection');
  });

  it('a literal command stays clean', async () => {
    const flows = await run(
      'func h(w http.ResponseWriter, r *http.Request) {',
      '  cmd := "ls"',
      '  exec.Command(cmd).Run()',
      '}',
    );
    expect(flows).toHaveLength(0);
  });

  it('url.Values.Get is not a request source', async () => {
    const flows = await run(
      'func f(v url.Values) {',
      '  cmd := v.Get("cmd")',
      '  exec.Command(cmd).Run()',
      '}',
    );
    expect(flows).toHaveLength(0);
  });
});
