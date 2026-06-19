/**
 * Repro for cognium-dev Sprint 24 — Go safe-handler false positives (#102).
 *
 * Closes the Go portion of #102 left open after Sprint 23. Sprint 23 shipped
 * the Bash FP-24 fix; Sprint 24 closes five reproducible Go FPs.
 *
 *   - **FP-19a** parameterised SQL (`db.Query("SELECT ... WHERE id = ?", id)`)
 *     no longer triggers `external_taint_escape`. Fix: Go SQL Query/Exec
 *     methods added to `safeUtilityMethods` in interprocedural.ts so the
 *     CWE-668 fallback doesn't fire after the sql_injection sink check has
 *     already cleared the call.
 *
 *   - **FP-19b** `html/template.Execute` no longer triggers
 *     `external_taint_escape`. Fix: `findGoHtmlTemplateImportSanitizers`
 *     in language-sources-pass.ts emits a per-line sanitizer at every
 *     `.Execute(`/`.ExecuteTemplate(` call when `html/template` is
 *     imported (and `text/template` is not — that case retains the
 *     positive code_injection lock from Sprint 23 #108).
 *
 *   - **FP-20** map-allowlist guard (`if !allowedHosts[host] { return }`)
 *     suppresses the downstream ssrf flow. Fix:
 *     `findGoMapAllowlistGuardSanitizers` modelled on Sprint 23's Bash
 *     realpath+prefix-guard detector emits per-line sanitizers from the
 *     guard close-brace through end of file when the map name matches
 *     the allowlist naming heuristic (UPPER_SNAKE or contains
 *     "allowed"/"accepted"/"whitelist"/"permitted"/"valid"/"approved").
 *
 *   - **FP-25** `exec.Command("ping", "-c", "1", host)` no longer fires
 *     command_injection. Fix: `isSafeGoExecCommandCall` in taint-matcher.ts
 *     suppresses the command_injection sink when arg[0] is a literal
 *     non-shell program. Sprint 23 #53 (shell-shape) is preserved:
 *     `exec.Command("sh", "-c", taintedCmd)` still fires because "sh" is
 *     in the SHELL_PROGRAMS set. Variable program preserved too:
 *     `exec.Command(taintedProg, "-c", "x")` still fires because
 *     arg[0].literal is null. `Command`/`CommandContext` also added to
 *     `safeUtilityMethods` so the CWE-668 fallback doesn't re-fire on
 *     the variadic args after the command_injection sink was cleared.
 *
 *   - **FP-27** `html.EscapeString(name)` followed by `fmt.Fprintf` no
 *     longer fires `external_taint_escape`. Fix: register the
 *     `html.EscapeString` / `template.HTMLEscapeString` sanitizers
 *     directly in DEFAULT_SANITIZERS (the per-language configs/sinks/
 *     golang.json is not loaded at runtime). Add a two-tier uniform
 *     line-keyed sanitizer filter in TaintPropagationPass and
 *     InterproceduralPass: external_taint_escape suppression is
 *     line-range based (sanitizer anywhere from source to sink line);
 *     configured sinks require the sanitizer to be at the sink_line
 *     itself.
 *
 * Target release: circle-ir 3.74.0 / cognium-dev 3.74.0.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('cognium-dev Sprint 24 — Go safe-handler FPs (#102)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const flowsByType = (
    flows: Array<{ sink_type?: string; sanitized?: boolean }> | undefined,
    sinkType: string,
  ) => (flows ?? []).filter((f) => f.sink_type === sinkType && !f.sanitized);

  const allFlows = (flows: Array<{ sanitized?: boolean }> | undefined) =>
    (flows ?? []).filter((f) => !f.sanitized);

  // ---------------------------------------------------------------------------
  // FP-19a — parameterised SQL Query / Exec
  // ---------------------------------------------------------------------------

  it('FP-19a GO.param_sql_query — db.Query with placeholder is safe', async () => {
    const code = `package main
import ("database/sql"; "net/http")
func handler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
  id := r.URL.Query().Get("id")
  _, _ = db.Query("SELECT name FROM users WHERE id = ?", id)
}
`;
    const r = await analyze(code, 'q.go', 'go');
    expect(allFlows(r.taint?.flows).length).toBe(0);
  });

  // ---------------------------------------------------------------------------
  // FP-19b — html/template.Execute auto-escape
  // ---------------------------------------------------------------------------

  it('FP-19b GO.html_template_execute — html/template auto-escape is safe', async () => {
    const code = `package main
import ("html/template"; "net/http")
func handler(w http.ResponseWriter, r *http.Request) {
  name := r.URL.Query().Get("name")
  t, _ := template.New("p").Parse("<p>Hello {{.}}</p>")
  _ = t.Execute(w, name)
}
`;
    const r = await analyze(code, 'h.go', 'go');
    expect(allFlows(r.taint?.flows).length).toBe(0);
  });

  // ---------------------------------------------------------------------------
  // FP-20 — map-allowlist guard
  // ---------------------------------------------------------------------------

  it('FP-20 GO.host_allowlist_map — map-allowlist guard suppresses ssrf', async () => {
    const code = `package main
import ("net/http")
var allowedHosts = map[string]bool{"a.com": true, "b.com": true}
func handler(w http.ResponseWriter, r *http.Request) {
  host := r.URL.Query().Get("host")
  if !allowedHosts[host] {
    http.Error(w, "forbidden", 403)
    return
  }
  _, _ = http.Get("https://" + host)
}
`;
    const r = await analyze(code, 'a.go', 'go');
    expect(allFlows(r.taint?.flows).length).toBe(0);
  });

  // ---------------------------------------------------------------------------
  // FP-25 — exec.Command with fixed program literal + variadic args
  // ---------------------------------------------------------------------------

  it('FP-25 GO.exec_fixed_argv — exec.Command("ping",...) is safe', async () => {
    const code = `package main
import ("net/http"; "os/exec")
func handler(w http.ResponseWriter, r *http.Request) {
  host := r.URL.Query().Get("h")
  _, _ = exec.Command("ping", "-c", "1", host).Output()
}
`;
    const r = await analyze(code, 'p.go', 'go');
    expect(allFlows(r.taint?.flows).length).toBe(0);
  });

  // ---------------------------------------------------------------------------
  // FP-26 — filepath.Clean + HasPrefix regression lock
  // ---------------------------------------------------------------------------

  it('FP-26 GO.filepath_clean_prefix — Clean + HasPrefix guard is safe', async () => {
    const code = `package main
import ("net/http"; "path/filepath"; "strings"; "os")
func handler(w http.ResponseWriter, r *http.Request) {
  name := r.URL.Query().Get("n")
  p := filepath.Clean("/var/uploads/" + name)
  if !strings.HasPrefix(p, "/var/uploads/") { return }
  _, _ = os.ReadFile(p)
}
`;
    const r = await analyze(code, 'c.go', 'go');
    expect(allFlows(r.taint?.flows).length).toBe(0);
  });

  // ---------------------------------------------------------------------------
  // FP-27 — html.EscapeString → fmt.Fprintf
  // ---------------------------------------------------------------------------

  it('FP-27 GO.html_escape_fprintf — html.EscapeString sanitizes Fprintf', async () => {
    const code = `package main
import ("fmt"; "html"; "net/http")
func handler(w http.ResponseWriter, r *http.Request) {
  name := r.URL.Query().Get("name")
  safe := html.EscapeString(name)
  _, _ = fmt.Fprintf(w, "<p>Hello, %s</p>", safe)
}
`;
    const r = await analyze(code, 'e.go', 'go');
    expect(allFlows(r.taint?.flows).length).toBe(0);
  });

  // ---------------------------------------------------------------------------
  // Positive recall locks — these MUST continue to fire
  // ---------------------------------------------------------------------------

  it('POS GO.ssrf_no_guard — http.Get on raw tainted URL fires ssrf', async () => {
    const code = `package main
import ("net/http")
func handler(w http.ResponseWriter, r *http.Request) {
  url := r.URL.Query().Get("u")
  _, _ = http.Get(url)
}
`;
    const r = await analyze(code, 's.go', 'go');
    expect(flowsByType(r.taint?.flows, 'ssrf').length).toBeGreaterThanOrEqual(1);
  });

  it('POS GO.exec_shell_shape — exec.Command("sh","-c",cmd) fires (Sprint 23 #53 lock)', async () => {
    const code = `package main
import ("net/http"; "os/exec")
func handler(w http.ResponseWriter, r *http.Request) {
  cmd := r.URL.Query().Get("c")
  _, _ = exec.Command("sh", "-c", cmd).Output()
}
`;
    const r = await analyze(code, 'sh.go', 'go');
    expect(flowsByType(r.taint?.flows, 'command_injection').length).toBeGreaterThanOrEqual(1);
  });

  it('POS GO.path_no_guard — os.ReadFile on raw concat fires path_traversal', async () => {
    const code = `package main
import ("net/http"; "os")
func handler(w http.ResponseWriter, r *http.Request) {
  name := r.URL.Query().Get("n")
  _, _ = os.ReadFile("/var/uploads/" + name)
}
`;
    const r = await analyze(code, 'p.go', 'go');
    expect(flowsByType(r.taint?.flows, 'path_traversal').length).toBeGreaterThanOrEqual(1);
  });

  it('POS GO.tainted_prog — exec.Command(taintedProg,...) fires (arg[0] taint)', async () => {
    const code = `package main
import ("net/http"; "os/exec")
func handler(w http.ResponseWriter, r *http.Request) {
  prog := r.URL.Query().Get("p")
  _, _ = exec.Command(prog, "-c", "x").Output()
}
`;
    const r = await analyze(code, 'tp.go', 'go');
    expect(flowsByType(r.taint?.flows, 'command_injection').length).toBeGreaterThanOrEqual(1);
  });

  it('POS GO.text_template_execute — text/template Execute fires (no html auto-escape)', async () => {
    // text/template does NOT auto-escape; distinguishes from FP-19b html/template case.
    // Either xss or external_taint_escape acceptable (no html.EscapeString upstream).
    const code = `package main
import ("text/template"; "net/http")
func handler(w http.ResponseWriter, r *http.Request) {
  name := r.URL.Query().Get("name")
  t, _ := template.New("p").Parse("<p>Hello {{.}}</p>")
  _ = t.Execute(w, name)
}
`;
    const r = await analyze(code, 'tt.go', 'go');
    // Allow xss or external_taint_escape — both legitimate findings for text/template
    // since there's no auto-escape and no sanitizer in scope.
    const flows = allFlows(r.taint?.flows);
    expect(flows.length).toBeGreaterThanOrEqual(1);
  });
});
