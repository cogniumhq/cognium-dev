/**
 * cognium-dev#374 — Go CWE-22 recall. The sink half of this issue (adding
 * `os.Create` / `os.OpenFile` / `os.Remove` / `ioutil.{Read,Write}File` as
 * path_traversal sinks) landed first and moved the corpus number by ZERO,
 * which is what sent me looking here.
 *
 * On `vulnerability-goapp/pkg/image/imageUploader.go` the picture was:
 *
 *   77:  file, handler, err := r.FormFile("uploadfile")
 *   83:  f, err := os.OpenFile("./assets/img/"+handler.Filename, os.O_WRONLY|os.O_CREATE, 0666)
 *
 * After the sink fix, line 83 registered as a path_traversal sink — and still
 * produced no finding, because NOTHING bound `handler` as a source. Sink
 * present, source absent, `flows: 0`. Adding sinks alone cannot raise recall
 * when the corresponding source shape is unmodelled; that is the lesson this
 * test pins.
 *
 * `handler.Filename` is attacker-controlled by construction: it is the
 * client's multipart Content-Disposition filename, and the Go stdlib
 * explicitly does not sanitise it.
 *
 * The source is emitted on the FormFile line bound to the SECOND return
 * value, because the tainted value is read as `handler.Filename` INLINE in
 * the sink argument — there is no intermediate assignment to bind instead.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';
import { generateFindings } from '../../src/analysis/findings.js';

const findings = (r: any, file: string, code: string) =>
  generateFindings(
    r.taint.sources, r.taint.sinks, r.dfg, file, code, 'go',
    r.taint.sanitizers, r.types, r.taint.flows,
  );

describe('#374 — Go multipart upload filename as a CWE-22 source', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('flags the inline handler.Filename concatenated into os.OpenFile', async () => {
    const code = [
      'package main',
      'import (',
      '\t"net/http"',
      '\t"os"',
      ')',
      'func upload(w http.ResponseWriter, r *http.Request) {',
      '\tfile, handler, err := r.FormFile("uploadfile")',
      '\tif err != nil { return }',
      '\tdefer file.Close()',
      '\tf, err := os.OpenFile("./assets/img/"+handler.Filename, os.O_WRONLY|os.O_CREATE, 0666)',
      '\tif err != nil { return }',
      '\tdefer f.Close()',
      '}',
    ].join('\n');
    const r = await analyze(code, 'upload.go', 'go');
    expect(r.taint.sources.some((s: any) => s.variable === 'handler')).toBe(true);
    const pt = findings(r, 'upload.go', code).filter((f: any) => f.type === 'path_traversal');
    expect(pt.length).toBeGreaterThan(0);
  });

  it('binds a local assigned from handler.Filename', async () => {
    const code = [
      'package main',
      'import (',
      '\t"net/http"',
      '\t"os"',
      ')',
      'func upload(w http.ResponseWriter, r *http.Request) {',
      '\t_, handler, _ := r.FormFile("f")',
      '\tname := handler.Filename',
      '\tf, _ := os.Create("/tmp/" + name)',
      '\tdefer f.Close()',
      '}',
    ].join('\n');
    const r = await analyze(code, 'u2.go', 'go');
    expect(r.taint.sources.some((s: any) => s.variable === 'name')).toBe(true);
    const pt = findings(r, 'u2.go', code).filter((f: any) => f.type === 'path_traversal');
    expect(pt.length).toBeGreaterThan(0);
  });

  it('does not fire on a file that never touches multipart', async () => {
    const code = [
      'package main',
      'import "os"',
      'func main() {',
      '\tf, _ := os.Create("/tmp/fixed.log")',
      '\tdefer f.Close()',
      '}',
    ].join('\n');
    const r = await analyze(code, 'plain.go', 'go');
    expect(r.taint.sources.filter((s: any) => /Filename/.test(s.location ?? ''))).toHaveLength(0);
    expect(findings(r, 'plain.go', code).filter((f: any) => f.type === 'path_traversal')).toHaveLength(0);
  });

  it('skips a discarded FileHeader (`_`)', async () => {
    const code = [
      'package main',
      'import "net/http"',
      'func h(w http.ResponseWriter, r *http.Request) {',
      '\tfile, _, err := r.FormFile("f")',
      '\t_ = file',
      '\t_ = err',
      '}',
    ].join('\n');
    const r = await analyze(code, 'skip.go', 'go');
    expect(r.taint.sources.filter((s: any) => /FormFile/.test(s.location ?? ''))).toHaveLength(0);
  });
});
