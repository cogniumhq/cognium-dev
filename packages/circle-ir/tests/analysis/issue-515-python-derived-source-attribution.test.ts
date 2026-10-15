/**
 * #515 (slice, Python only) — a variable derived by `buildPythonTaintedVars`
 * was given a synthetic source that copied the EARLIEST real source in the
 * file, not the source its right-hand side references. A decoy read that never
 * reaches the sink got the credit. The derived variable now anchors to the real
 * source (following the chain through earlier derived variables) that its
 * right-hand side names; the earliest-source anchor remains the fallback.
 * Only `source_line` / `source_type` move; the flow set is unchanged.
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

  it('leaves the direct-argument shape unchanged', async () => {
    const code = `from flask import request
import subprocess

def export_report():
    note = request.args.get("note")
    fmt = request.form.get("fmt")
    subprocess.check_output("echo " + fmt, shell=True)
`;
    const flows = await flowsOf(code);
    expect(flows.length).toBe(1);
    expect(flows[0][2]).toBe('command_injection');
  });
});
