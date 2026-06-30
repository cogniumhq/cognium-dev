/**
 * Sprint 77a — #216 Pattern X (mixed in-corpus FPs): 3 FPs
 *
 * Closes 3 of 5 remaining scorecard FPs from #216:
 *   - java SafeInteropShellInString.java: argv-form
 *     `Runtime.getRuntime().exec(new String[]{"echo", "--", arg})` — fixed
 *     program, no shell interpolation, no command injection possible.
 *   - rust benign_exec_argv.rs: argv-form
 *     `Command::new("grep").arg(p).arg("/var/log/app.log").status()` —
 *     fixed program string, taint flows only into argv slots.
 *   - python benign_autoescape_template.py: Jinja2 environment with
 *     `autoescape=select_autoescape(["html"])` — html-context output is
 *     auto-escaped, no XSS.
 *
 * 2 TS Pattern A interop FPs remain on #216 after Sprint 77a — those are
 * corpus-blocked (fixtures not yet committed to typescript-vuln-demo) and
 * deferred to Sprint 77b.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

describe('#216 Sprint 77a — mixed in-corpus sanitizer recognition', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('TN-1 — SafeInteropShellInString.java: Runtime.exec(String[]) argv form sanitizes command_injection + ETE', async () => {
    const code = [
      'package com.demo.interop;',
      '',
      '/** SAFE mirror -- fixed argv, no shell interpolation. */',
      'public class SafeInteropShellInString {',
      '    public void run(String arg) throws Exception {',
      '        Runtime.getRuntime().exec(new String[]{"echo", "--", arg});',
      '    }',
      '}',
      '',
    ].join('\n');
    const r: any = await analyze(
      code,
      'SafeInteropShellInString.java',
      'java',
    );
    const ci = (r.taint?.flows ?? []).filter(
      (f: any) => f.sink_type === 'command_injection',
    );
    const ete = (r.taint?.flows ?? []).filter(
      (f: any) => f.sink_type === 'external_taint_escape',
    );
    expect(ci.length).toBe(0);
    expect(ete.length).toBe(0);
  });

  it('TN-2 — benign_exec_argv.rs: Command::new(literal).arg(...).arg(...) argv form sanitizes command_injection + ETE', async () => {
    const code = [
      'use std::process::Command;',
      'pub fn grep(p: &str) { let _ = Command::new("grep").arg(p).arg("/var/log/app.log").status(); }',
      '',
    ].join('\n');
    const r: any = await analyze(code, 'benign_exec_argv.rs', 'rust');
    const ci = (r.taint?.flows ?? []).filter(
      (f: any) => f.sink_type === 'command_injection',
    );
    const ete = (r.taint?.flows ?? []).filter(
      (f: any) => f.sink_type === 'external_taint_escape',
    );
    expect(ci.length).toBe(0);
    expect(ete.length).toBe(0);
  });

  it('TN-3 — benign_autoescape_template.py: Jinja2 autoescape sanitizes xss + ETE', async () => {
    const code = [
      '"""TN -- Jinja2 autoescape enabled."""',
      'from jinja2 import Environment, PackageLoader, select_autoescape',
      '',
      'env = Environment(loader=PackageLoader("app", "templates"), autoescape=select_autoescape(["html"]))',
      'def render(name: str) -> str:',
      '    return env.get_template("hello.html").render(name=name)',
      '',
    ].join('\n');
    const r: any = await analyze(
      code,
      'benign_autoescape_template.py',
      'python',
    );
    const xss = (r.taint?.flows ?? []).filter(
      (f: any) => f.sink_type === 'xss',
    );
    const ete = (r.taint?.flows ?? []).filter(
      (f: any) => f.sink_type === 'external_taint_escape',
    );
    expect(xss.length).toBe(0);
    expect(ete.length).toBe(0);
  });

  it('TP-1 — Runtime.exec(String) shell-form concatenation does NOT get sanitized', async () => {
    // String-form exec runs through /bin/sh -c (depending on JVM) -- the
    // argv-form sanitizer must NOT over-suppress concat-into-single-string
    // command injection.
    const code = [
      'package com.demo.tp;',
      '',
      'public class UnsafeShellConcat {',
      '    public void run(String arg) throws Exception {',
      '        Runtime.getRuntime().exec("echo -- " + arg);',
      '    }',
      '}',
      '',
    ].join('\n');
    const r: any = await analyze(code, 'UnsafeShellConcat.java', 'java');
    const ci = (r.taint?.flows ?? []).filter(
      (f: any) => f.sink_type === 'command_injection',
    );
    expect(ci.length).toBeGreaterThan(0);
  });

  it('TP-2 — Command::new(tainted_program) does NOT get sanitized', async () => {
    // Tainted program-name slot is command_injection -- the argv-form
    // sanitizer must only recognize literal program names.
    const code = [
      'use std::process::Command;',
      'pub fn run(prog: &str) { let _ = Command::new(prog).arg("/var/log/app.log").status(); }',
      '',
    ].join('\n');
    const r: any = await analyze(code, 'unsafe_exec_prog.rs', 'rust');
    const ci = (r.taint?.flows ?? []).filter(
      (f: any) => f.sink_type === 'command_injection',
    );
    expect(ci.length).toBeGreaterThan(0);
  });

  it('TP-3 — Jinja2 Environment(autoescape=False) does NOT get sanitized', async () => {
    // Autoescape disabled -- xss must still fire on tainted .render() input.
    const code = [
      'from jinja2 import Environment, PackageLoader',
      '',
      'env = Environment(loader=PackageLoader("app", "templates"), autoescape=False)',
      'def render(name: str) -> str:',
      '    return env.get_template("hello.html").render(name=name)',
      '',
    ].join('\n');
    const r: any = await analyze(code, 'unsafe_noautoescape.py', 'python');
    const xss = (r.taint?.flows ?? []).filter(
      (f: any) => f.sink_type === 'xss',
    );
    expect(xss.length).toBeGreaterThan(0);
  });
});
