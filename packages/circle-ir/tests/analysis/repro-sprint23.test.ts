/**
 * Repro for cognium-dev Sprint 23 — bundled "S" complexity closure
 * (#53, #102, #107, #108).
 *
 * Single sprint that lands four orthogonal small fixes:
 *
 *   - **#53** Go string-concat taint loss. Sources emitted from method-call
 *     shapes (`r.URL.Query().Get(...)`) landed without a `variable` field,
 *     so `detectExpressionScanFlows` could not match the bound identifier
 *     when it reappeared in concatenated sink arguments
 *     (`exec.Command("sh","-c","ping "+host)`). Compounded by
 *     `exec.Command`'s sink config declaring `argPositions:[0]` — the
 *     SinkFilterPass clean-variable filter then dropped the whole sink
 *     when arg[0] was a literal (`"sh"`).
 *     Fix: widen `exec.Command`/`CommandContext` `argPositions` to `[]`
 *     (no position filter) **and** recover the Go LHS identifier from
 *     `:=` / `var x =` / `x =` lines in `taint-matcher.ts`.
 *
 *   - **#102** Bash realpath + case prefix-guard false positive. The
 *     idiomatic shape `resolved=$(realpath "$f"); case "$resolved" in
 *     "$ROOT"/*) ... ;; *) exit 1 ;; esac` was reported as
 *     `path_traversal`.
 *     Fix: `findBashRealpathPrefixGuardSanitizers` in
 *     `language-sources-pass.ts` emits a per-line sanitizer over the
 *     `case…esac` block when (a) at least one prefix arm is present and
 *     (b) the catch-all `*)` arm terminates execution.
 *
 *   - **#107** Go `log_injection` sink type was not registered for the
 *     `log.{Print,Println,Printf,Fatal,Fatalln,Fatalf,Panic,Panicln,
 *     Panicf}` family.
 *     Fix: add CWE-117 entries to `getBuiltinSinks()` in `go.ts` with
 *     `argPositions:[]` so any tainted positional argument fires.
 *
 *   - **#108** Go SSTI/`code_injection` sink type was not registered for
 *     `text/template` and `html/template` `Parse`/`ParseFiles`/
 *     `ParseGlob`/`ParseFS`. The existing `Template.Execute` entry only
 *     models data-injection XSS; parse-time injection of the template
 *     source itself is code execution.
 *     Fix: add CWE-94 entries to `getBuiltinSinks()`.
 *
 * Target release: circle-ir 3.73.0 / cognium-dev 3.73.0.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('cognium-dev Sprint 23 — bundled S closure (#53/#102/#107/#108)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const flowsByType = (
    flows: Array<{ sink_type?: string; sanitized?: boolean }> | undefined,
    sinkType: string,
  ) => (flows ?? []).filter((f) => f.sink_type === sinkType && !f.sanitized);

  // ---------------------------------------------------------------------------
  // #53 — Go string-concat taint preservation across `+`
  // ---------------------------------------------------------------------------

  it('#53 GO.cmd_concat — right concat in exec.Command shell-shape', async () => {
    const code = `package main
import ("net/http"; "os/exec")
func handler(w http.ResponseWriter, r *http.Request) {
  host := r.URL.Query().Get("h")
  exec.Command("sh", "-c", "ping " + host).Output()
}
`;
    const r = await analyze(code, 'cmd.go', 'go');
    expect(flowsByType(r.taint?.flows, 'command_injection').length).toBeGreaterThanOrEqual(1);
  });

  it('#53 GO.path_concat — right concat into os.ReadFile', async () => {
    const code = `package main
import ("net/http"; "os")
func handler(w http.ResponseWriter, r *http.Request) {
  name := r.URL.Query().Get("n")
  os.ReadFile("/var/uploads/" + name)
}
`;
    const r = await analyze(code, 'p.go', 'go');
    expect(flowsByType(r.taint?.flows, 'path_traversal').length).toBeGreaterThanOrEqual(1);
  });

  it('#53 GO.left_concat — tainted on left side of `+`', async () => {
    const code = `package main
import ("net/http"; "os/exec")
func handler(w http.ResponseWriter, r *http.Request) {
  cmd := r.URL.Query().Get("c")
  exec.Command("sh", "-c", cmd + " --verbose").Output()
}
`;
    const r = await analyze(code, 'l.go', 'go');
    expect(flowsByType(r.taint?.flows, 'command_injection').length).toBeGreaterThanOrEqual(1);
  });

  // ---------------------------------------------------------------------------
  // #107 — Go log_injection sink_type
  // ---------------------------------------------------------------------------

  it('#107 GO.log_printf — log.Printf with user-controlled value', async () => {
    const code = `package main
import ("net/http"; "log")
func handler(w http.ResponseWriter, r *http.Request) {
  m := r.URL.Query().Get("m")
  log.Printf("event=%s", m)
}
`;
    const r = await analyze(code, 'log.go', 'go');
    expect(flowsByType(r.taint?.flows, 'log_injection').length).toBeGreaterThanOrEqual(1);
  });

  it('#107 GO.log_println — log.Println with user-controlled value', async () => {
    const code = `package main
import ("net/http"; "log")
func handler(w http.ResponseWriter, r *http.Request) {
  m := r.URL.Query().Get("m")
  log.Println(m)
}
`;
    const r = await analyze(code, 'logln.go', 'go');
    expect(flowsByType(r.taint?.flows, 'log_injection').length).toBeGreaterThanOrEqual(1);
  });

  // ---------------------------------------------------------------------------
  // #108 — Go code_injection / SSTI sink_type for text/template + html/template
  // ---------------------------------------------------------------------------

  it('#108 GO.text_template — text/template.Parse with tainted source', async () => {
    const code = `package main
import ("net/http"; "text/template"; "os")
func handler(w http.ResponseWriter, r *http.Request) {
  t := r.URL.Query().Get("t")
  tmpl, _ := template.New("x").Parse(t)
  tmpl.Execute(os.Stdout, nil)
}
`;
    const r = await analyze(code, 'tt.go', 'go');
    expect(flowsByType(r.taint?.flows, 'code_injection').length).toBeGreaterThanOrEqual(1);
  });

  it('#108 GO.html_template — html/template.Parse with tainted source', async () => {
    const code = `package main
import ("net/http"; "html/template"; "os")
func handler(w http.ResponseWriter, r *http.Request) {
  t := r.URL.Query().Get("t")
  tmpl, _ := template.New("x").Parse(t)
  tmpl.Execute(os.Stdout, nil)
}
`;
    const r = await analyze(code, 'ht.go', 'go');
    expect(flowsByType(r.taint?.flows, 'code_injection').length).toBeGreaterThanOrEqual(1);
  });

  // ---------------------------------------------------------------------------
  // #102 — Bash realpath + case prefix-guard FP suppression
  // ---------------------------------------------------------------------------

  it('#102 BASH.realpath_prefix_safe — realpath + case "$ROOT"/*) emits no path_traversal', async () => {
    const code = `#!/bin/bash
UPLOAD_ROOT=/var/uploads
f="$1"
resolved=$(realpath "$f")
case "$resolved" in
  "$UPLOAD_ROOT"/*) cat "$resolved" ;;
  *) echo denied; exit 1 ;;
esac
`;
    const r = await analyze(code, 'safe.sh', 'bash');
    const unsanitized = (r.taint?.flows ?? []).filter(
      (f) => !f.sanitized && (
        f.sink_type === 'path_traversal' ||
        f.sink_type === 'command_injection'
      ),
    );
    expect(unsanitized.length).toBe(0);
  });

  it('#102 BASH.no_guard_vuln — baseline: cat "$1" with no guard still fires', async () => {
    const code = `#!/bin/bash
f="$1"
cat "$f"
`;
    const r = await analyze(code, 'vuln.sh', 'bash');
    // Either a path_traversal or command_injection flow is acceptable evidence
    // that the engine still recognises the tainted path. The key invariant is
    // that the realpath sanitizer didn't over-suppress.
    const positive =
      flowsByType(r.taint?.flows, 'path_traversal').length +
      flowsByType(r.taint?.flows, 'command_injection').length;
    expect(positive).toBeGreaterThanOrEqual(1);
  });
});
