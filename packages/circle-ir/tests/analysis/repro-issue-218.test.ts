/**
 * Regression lock for cognium-dev #218 — Go `exec.Command` package-manager
 * install/exec subcommand FN (CVE-2026-33634 shape).
 *
 * Baseline `isSafeGoExecCommandCall` (Sprint 23 / #102 FP-25) treated
 * `exec.Command("go", "install", tainted)` as safe-by-shape because `"go"`
 * is not in `SHELL_PROGRAMS`. Fix: extend the safe-shape gate with a
 * `PACKAGE_MANAGER_EXEC_SUBCOMMANDS` map so `go install/run/get`,
 * `npm install/exec/i`, `npx *`, `pip install`, `gem install`,
 * `cargo install/run`, `yarn add/exec/dlx`, `pnpm add/exec/dlx` all
 * fire when a later argv slot is tainted.
 *
 * Recall guards keep `exec.Command("git", "clone", tainted)` and
 * `exec.Command("go", "version")` safe (git/clone is checkout, not
 * install; `go version` has no argv[2]).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('#218 — Go exec.Command package-manager install FN', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // ── TP: package-manager install/exec subcommands + tainted argv ─────

  it('TP-1: exec.Command("go", "install", url+"@latest") fires command_injection', async () => {
    const code = `package main

import (
  "net/http"
  "os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
  url := r.URL.Query().Get("pkg")
  exec.Command("go", "install", url+"@latest").Run()
}
`;
    const result = await analyze(code, 'main.go', 'go');
    const sinks = result.taint.sinks.filter(s => s.type === 'command_injection');
    expect(sinks.length).toBeGreaterThan(0);
    const flows = result.taint.flows.filter(f => f.sink_type === 'command_injection');
    expect(flows.length).toBeGreaterThan(0);
  });

  it('TP-2: exec.Command("npm", "install", tainted) fires', async () => {
    const code = `package main

import (
  "net/http"
  "os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
  pkg := r.URL.Query().Get("p")
  exec.Command("npm", "install", pkg).Run()
}
`;
    const result = await analyze(code, 'main.go', 'go');
    const sinks = result.taint.sinks.filter(s => s.type === 'command_injection');
    expect(sinks.length).toBeGreaterThan(0);
  });

  it('TP-3: exec.Command("pip", "install", tainted) fires', async () => {
    const code = `package main

import (
  "net/http"
  "os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
  pkg := r.URL.Query().Get("p")
  exec.Command("pip", "install", pkg).Run()
}
`;
    const result = await analyze(code, 'main.go', 'go');
    const sinks = result.taint.sinks.filter(s => s.type === 'command_injection');
    expect(sinks.length).toBeGreaterThan(0);
  });

  it('TP-4: npx wildcard subcommand fires', async () => {
    const code = `package main

import (
  "net/http"
  "os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
  pkg := r.URL.Query().Get("p")
  exec.Command("npx", pkg).Run()
}
`;
    const result = await analyze(code, 'main.go', 'go');
    const sinks = result.taint.sinks.filter(s => s.type === 'command_injection');
    expect(sinks.length).toBeGreaterThan(0);
  });

  it('TP-5: exec.CommandContext("go", "get", tainted) fires (ctx shift)', async () => {
    const code = `package main

import (
  "context"
  "net/http"
  "os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
  ctx := context.Background()
  url := r.URL.Query().Get("pkg")
  exec.CommandContext(ctx, "go", "get", url).Run()
}
`;
    const result = await analyze(code, 'main.go', 'go');
    const sinks = result.taint.sinks.filter(s => s.type === 'command_injection');
    expect(sinks.length).toBeGreaterThan(0);
  });

  // ── TN: safe-shape recall guards ───────────────────────────────────

  it('TN-1: literal-only exec.Command("go", "install", "example.com/pkg@v1") stays safe', async () => {
    const code = `package main

import "os/exec"

func main() {
  exec.Command("go", "install", "example.com/pkg@v1.0.0").Run()
}
`;
    const result = await analyze(code, 'main.go', 'go');
    const sinks = result.taint.sinks.filter(s => s.type === 'command_injection');
    expect(sinks.length).toBe(0);
  });

  it('TN-2: exec.Command("git", "clone", tainted) stays safe (git is not a package manager)', async () => {
    const code = `package main

import (
  "net/http"
  "os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
  url := r.URL.Query().Get("u")
  exec.Command("git", "clone", url).Run()
}
`;
    const result = await analyze(code, 'main.go', 'go');
    const sinks = result.taint.sinks.filter(s => s.type === 'command_injection');
    expect(sinks.length).toBe(0);
  });

  it('TN-3: exec.Command("go", "version") stays safe (no code-executing subcommand)', async () => {
    const code = `package main

import "os/exec"

func main() {
  exec.Command("go", "version").Run()
}
`;
    const result = await analyze(code, 'main.go', 'go');
    const sinks = result.taint.sinks.filter(s => s.type === 'command_injection');
    expect(sinks.length).toBe(0);
  });

  it('TN-4: exec.Command("npm", "run", "test") stays safe (run is not in npm exec-subcommands)', async () => {
    const code = `package main

import "os/exec"

func main() {
  exec.Command("npm", "run", "test").Run()
}
`;
    const result = await analyze(code, 'main.go', 'go');
    const sinks = result.taint.sinks.filter(s => s.type === 'command_injection');
    expect(sinks.length).toBe(0);
  });

  // ── Recall: pre-existing shapes unaffected ─────────────────────────

  it('recall-1: exec.Command("sh", "-c", tainted) still fires (shell-in-string)', async () => {
    const code = `package main

import (
  "net/http"
  "os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
  cmd := r.URL.Query().Get("cmd")
  exec.Command("sh", "-c", cmd).Run()
}
`;
    const result = await analyze(code, 'main.go', 'go');
    const sinks = result.taint.sinks.filter(s => s.type === 'command_injection');
    expect(sinks.length).toBeGreaterThan(0);
  });

  it('recall-2: exec.Command(taintedProg) still fires (argv[0] tainted)', async () => {
    const code = `package main

import (
  "net/http"
  "os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
  bin := r.URL.Query().Get("bin")
  exec.Command(bin).Run()
}
`;
    const result = await analyze(code, 'main.go', 'go');
    const sinks = result.taint.sinks.filter(s => s.type === 'command_injection');
    expect(sinks.length).toBeGreaterThan(0);
  });
});
