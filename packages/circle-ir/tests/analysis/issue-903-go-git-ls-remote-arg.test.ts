import { beforeAll, describe, expect, it } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

beforeAll(async () => {
  await initAnalyzer();
});

function cmdInjectionFlows(code: string, file = 'semaphore_git_arg_tp.go') {
  return analyze(code, file, 'go').then((r) =>
    (r.taint.flows ?? []).filter(
      (f) => !f.sanitized && (f.sink_type === 'command_injection' || f.cwe === 'CWE-78'),
    ),
  );
}

describe('issue #903 go git ls-remote argv injection', () => {
  it('flags tainted ref without end-of-options separator', async () => {
    const code = `
package intake

import (
  "net/http"
  "os/exec"
)

func handle(w http.ResponseWriter, r *http.Request) {
  gitURL := r.FormValue("url")
  _ = exec.Command("git", "ls-remote", gitURL, "master")
}
`;
    const flows = await cmdInjectionFlows(code);
    expect(flows.length).toBeGreaterThan(0);
  });

  it('stays clean when -- separates options from tainted ref', async () => {
    const code = `
package intake

import (
  "net/http"
  "os/exec"
)

func handle(w http.ResponseWriter, r *http.Request) {
  gitURL := r.FormValue("url")
  _ = exec.Command("git", "ls-remote", "--", gitURL, "master")
}
`;
    expect(await cmdInjectionFlows(code, 'semaphore_git_arg_safe.go')).toHaveLength(0);
  });

  it('flags cve-daily CVE-2026-24061 git ls-remote shape', async () => {
    const code = `
package main

import (
  "net/http"
  "os/exec"
)

func run(w http.ResponseWriter, r *http.Request) {
  gitURL := r.FormValue("git_url")
  exec.Command("git", "ls-remote", gitURL, "master").Run()
}
`;
    const flows = await cmdInjectionFlows(code, 'cve_2026_24061_tp.go');
    expect(flows.length).toBeGreaterThan(0);
  });

  it('flags cve-daily CVE-2026-86060 git ls-remote shape', async () => {
    const code = `
package main

import (
  "net/http"
  "os/exec"
)

func run(w http.ResponseWriter, r *http.Request) {
  gitURL := r.FormValue("git_url")
  exec.Command("git", "ls-remote", gitURL, "master").Run()
}
`;
    const flows = await cmdInjectionFlows(code, 'cve_2026_86060_tp.go');
    expect(flows.length).toBeGreaterThan(0);
  });
});
