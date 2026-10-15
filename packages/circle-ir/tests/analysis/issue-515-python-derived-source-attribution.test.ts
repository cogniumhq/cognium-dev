/**
 * #515 (slice, Python only) — a variable derived by `buildPythonTaintedVars`
 * was given a synthetic source that copied the EARLIEST real source in the
 * file, not the source its right-hand side references. A decoy read that never
 * reaches the sink got the credit. The derived variable now anchors to the real
 * source (following the chain through earlier derived variables) that its
 * right-hand side names; the earliest-source anchor remains the fallback.
 * Only `source_line` / `source_type` move; the flow set is unchanged.
 *
 * Review follow-ups: trailing `#…` comments (outside strings only) and
 * f-string `{…}` names are handled on the RHS scan; format specs / conversion
 * flags are cut so they cannot drop later names or become scanned identifiers;
 * a later assignment of a real-source name is resolved before falling back to
 * that real source; the direct-argument case pins the source line. `!=` inside
 * an f-string is an operator, not a conversion, so names after it are kept.
 * Nested `{…}` fields inside a format spec (after `:` or after `!conversion:`)
 * are kept; literal format-spec text stays dropped. Inside a format-spec tail,
 * `{` always opens a nested field (Python 3.12+), so `{{fmt}}` is a set
 * expression whose names are credited; the top-level `{{` / `}}` skip in
 * `braceExprs` still keeps a literal `f"{{fmt}}"` from crediting `fmt`.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const flowsOf = async (code: string) => {
  const ir = await analyze(code, 'f.py', 'python');
  return (ir.taint.flows ?? []).map(f => [f.source_line, f.sink_line, f.sink_type] as const);
};

describe('#515 Python derived-variable source attribution', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('credits the read the derivation references, not the earliest read in the file', async () => {
    const code = `from flask import request
import subprocess

def export_report():
    note = request.args.get("note")
    fmt = request.form.get("fmt")
    cmdline = "pandoc -t " + fmt
    subprocess.check_output(cmdline, shell=True)
`;
    expect(await flowsOf(code)).toEqual([[6, 8, 'command_injection']]);
  });

  it('ignores a trailing comment that names an earlier decoy source', async () => {
    const code = `from flask import request
import subprocess

def export_report():
    note = request.args.get("note")
    fmt = request.form.get("fmt")
    cmdline = "pandoc -t " + fmt  # note
    subprocess.check_output(cmdline, shell=True)
`;
    expect(await flowsOf(code)).toEqual([[6, 8, 'command_injection']]);
  });

  it('keeps f-string interpolations so the braced name is credited', async () => {
    const code = `from flask import request
import subprocess

def export_report():
    note = request.args.get("note")
    fmt = request.form.get("fmt")
    cmdline = f"pandoc -t {fmt}"
    subprocess.check_output(cmdline, shell=True)
`;
    expect(await flowsOf(code)).toEqual([[6, 8, 'command_injection']]);
  });

  it('does not treat a format-spec # as a comment that drops later names', async () => {
    const code = `from flask import request
import subprocess

def export_report():
    note = request.args.get("note")
    fmt = request.form.get("fmt")
    cmdline = f"{width:#04x}" + fmt
    subprocess.check_output(cmdline, shell=True)
`;
    expect(await flowsOf(code)).toEqual([[6, 8, 'command_injection']]);
  });

  it('does not treat an f-string conversion flag as a source name', async () => {
    const code = `from flask import request
import subprocess

def export_report():
    s = request.args.get("s")
    fmt = request.form.get("fmt")
    cmdline = f"pandoc -t {fmt!s}"
    subprocess.check_output(cmdline, shell=True)
`;
    expect(await flowsOf(code)).toEqual([[6, 8, 'command_injection']]);
  });

  it('still drops a conversion flag followed by a format spec', async () => {
    const code = `from flask import request
import subprocess

def export_report():
    s = request.args.get("s")
    fmt = request.form.get("fmt")
    cmdline = f"pandoc -t {fmt!s:10}"
    subprocess.check_output(cmdline, shell=True)
`;
    expect(await flowsOf(code)).toEqual([[6, 8, 'command_injection']]);
  });

  it('keeps a nested format-spec field so the braced name is credited', async () => {
    const code = `from flask import request
import subprocess

def export_report():
    note = request.args.get("note")
    fmt = request.form.get("fmt")
    cmdline = f"{label:{fmt}}"
    subprocess.check_output(cmdline, shell=True)
`;
    expect(await flowsOf(code)).toEqual([[6, 8, 'command_injection']]);
  });

  it('keeps a set-literal nested format-spec field ({{fmt}} is not a brace escape)', async () => {
    const code = `from flask import request
import subprocess

def export_report():
    note = request.args.get("note")
    fmt = request.form.get("fmt")
    cmdline = f"{label:{{fmt}}}"
    subprocess.check_output(cmdline, shell=True)
`;
    expect(await flowsOf(code)).toEqual([[6, 8, 'command_injection']]);
  });

  it('keeps a nested format-spec field after a conversion flag', async () => {
    const code = `from flask import request
import subprocess

def export_report():
    note = request.args.get("note")
    fmt = request.form.get("fmt")
    cmdline = f"{label!s:{fmt}}"
    subprocess.check_output(cmdline, shell=True)
`;
    expect(await flowsOf(code)).toEqual([[6, 8, 'command_injection']]);
  });

  it('keeps a nested format-spec field when the f-string is the sink argument', async () => {
    const code = `from flask import request
import subprocess

def export_report():
    note = request.args.get("note")
    fmt = request.form.get("fmt")
    subprocess.check_output(f"{label:{fmt}}", shell=True)
`;
    expect(await flowsOf(code)).toEqual([[6, 7, 'command_injection']]);
  });

  it('keeps a set-literal nested format-spec field when the f-string is the sink argument', async () => {
    const code = `from flask import request
import subprocess

def export_report():
    note = request.args.get("note")
    fmt = request.form.get("fmt")
    subprocess.check_output(f"{label:{{fmt}}}", shell=True)
`;
    expect(await flowsOf(code)).toEqual([[6, 7, 'command_injection']]);
  });

  it('still does not credit a name inside a top-level literal brace escape', async () => {
    const code = `from flask import request
import subprocess

def export_report():
    note = request.args.get("note")
    fmt = request.form.get("fmt")
    cmdline = f"{{fmt}}" + note
    subprocess.check_output(cmdline, shell=True)
`;
    expect(await flowsOf(code)).toEqual([[5, 8, 'command_injection']]);
  });

  it('does not cut an f-string != comparison as if it were a conversion', async () => {
    const code = `from flask import request
import subprocess

def export_report():
    note = request.args.get("note")
    fmt = request.form.get("fmt")
    cmdline = f"{label != fmt}"
    subprocess.check_output(cmdline, shell=True)
`;
    expect(await flowsOf(code)).toEqual([[6, 8, 'command_injection']]);
  });

  it('does not cut an unspaced != comparison inside an f-string', async () => {
    const code = `from flask import request
import subprocess

def export_report():
    note = request.args.get("note")
    fmt = request.form.get("fmt")
    cmdline = f"{other!=fmt}"
    subprocess.check_output(cmdline, shell=True)
`;
    expect(await flowsOf(code)).toEqual([[6, 8, 'command_injection']]);
  });

  it('keeps the name after != when the f-string is the sink argument', async () => {
    const code = `from flask import request
import subprocess

def export_report():
    note = request.args.get("note")
    fmt = request.form.get("fmt")
    subprocess.check_output(f"{label != fmt}", shell=True)
`;
    expect(await flowsOf(code)).toEqual([[6, 7, 'command_injection']]);
  });

  it('follows a reassignment of a real-source name to the value that flows', async () => {
    const code = `from flask import request
import subprocess

def export_report():
    other = request.args.get("o")
    fmt = request.form.get("fmt")
    fmt = other
    cmdline = "pandoc -t " + fmt
    subprocess.check_output(cmdline, shell=True)
`;
    expect(await flowsOf(code)).toEqual([[5, 9, 'command_injection']]);
  });

  it('follows a chain of derivations back to the referenced read', async () => {
    const code = `from flask import request
import subprocess

def export_report():
    note = request.args.get("note")
    fmt = request.form.get("fmt")
    base = "pandoc -t " + fmt
    cmdline = base + " -o out.pdf"
    subprocess.check_output(cmdline, shell=True)
`;
    expect(await flowsOf(code)).toEqual([[6, 9, 'command_injection']]);
  });

  it('is rename-proof (different names, decoy placed after the real read)', async () => {
    const code = `from flask import request
import subprocess

def go():
    zeta = request.form.get("z")
    alpha = request.args.get("a")
    line = "tool " + zeta
    subprocess.check_output(line, shell=True)
`;
    expect(await flowsOf(code)).toEqual([[5, 8, 'command_injection']]);
  });

  it('keeps a decoy-only file at no flow', async () => {
    const code = `from flask import request
import subprocess

def export_report():
    note = request.args.get("note")
    cmdline = "pandoc -t html"
    subprocess.check_output(cmdline, shell=True)
`;
    expect(await flowsOf(code)).toEqual([]);
  });

  it('keeps a single-read file at 5 -> 7', async () => {
    const code = `from flask import request
import subprocess

def export_report():
    fmt = request.form.get("fmt")
    cmdline = "pandoc -t " + fmt
    subprocess.check_output(cmdline, shell=True)
`;
    expect(await flowsOf(code)).toEqual([[5, 7, 'command_injection']]);
  });

  it('leaves the direct-argument shape unchanged and pins the source line', async () => {
    const code = `from flask import request
import subprocess

def export_report():
    note = request.args.get("note")
    fmt = request.form.get("fmt")
    subprocess.check_output("echo " + fmt, shell=True)
`;
    expect(await flowsOf(code)).toEqual([[6, 7, 'command_injection']]);
  });
});
