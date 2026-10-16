/**
 * cognium-dev#750 (slice 1, follow-up of #594): C# — the constant shell program of a
 * `ProcessStartInfo` may be written by its constructor's single argument
 * (`new ProcessStartInfo("/bin/sh")`) or by a `FileName = "…"` entry of its object
 * initializer, on the statement that creates the variable. It counts as the one
 * `FileName` write, so the existing rules (a shell program, a command flag, no
 * second write) still decide whether `ArgumentList.Add(<tainted>)` reaches `Start`.
 *
 * SAST regression fixtures — the controllers are deliberately vulnerable.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const wrap = (body: string, params = 'string name') => `using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
public class ScriptListController : Controller
{
    [HttpGet("m/{name}")]
    public string Run(${params})
    {
${body}
        return "";
    }
}
`;

/** Lines of the `Start` call, and the command_injection sink lines reported. */
async function run(body: string, file = 'ScriptListController.cs', params?: string) {
  const code = wrap(body, params);
  const startLine = code.split('\n').findIndex((l) => /\bStart\s*\(/.test(l)) + 1;
  const r = await analyze(code, file, 'csharp');
  const lines = [...new Set((r.taint.flows ?? []).filter((f) => f.sink_type === 'command_injection').map((f) => f.sink_line))].sort((a, b) => a - b);
  return { startLine, lines };
}

const reports = async (body: string, file?: string, params?: string) => {
  const { startLine, lines } = await run(body, file, params);
  expect(lines).toEqual([startLine]);
};
const clean = async (body: string, file?: string, params?: string) => {
  expect((await run(body, file, params)).lines).toEqual([]);
};

const tail = `        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add(name);
        Process.Start(psi);`;

describe('cognium-dev#750 — constant program from the ProcessStartInfo constructor / initializer', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  describe('reports', () => {
    it('constructor argument', async () => {
      await reports(`        var psi = new ProcessStartInfo("/bin/sh");\n${tail}`);
    });

    it('object initializer', async () => {
      await reports(`        var psi = new ProcessStartInfo { FileName = "/bin/sh" };\n${tail}`);
    });

    it('object initializer with an empty constructor list and other members', async () => {
      await reports(`        ProcessStartInfo psi = new ProcessStartInfo() { FileName = "/bin/sh", UseShellExecute = false };\n${tail}`);
    });

    it('a multi-line object initializer', async () => {
      await reports(`        var psi = new ProcessStartInfo
        {
            UseShellExecute = false,
            FileName = "/bin/sh"
        };\n${tail}`);
    });

    it('a trailing comment after the creating statement', async () => {
      await reports(`        var psi = new ProcessStartInfo("/bin/sh"); // shell\n${tail}`);
    });

    it('is not keyed on names: renamed variable, parameter and shell', async () => {
      await reports(`        var launcher = new ProcessStartInfo("bash");
        launcher.ArgumentList.Add("-c");
        launcher.ArgumentList.Add(script);
        Process.Start(launcher);`, 'Runner.cs', 'string script');
    });

    it('the process object form: proc.StartInfo = new ProcessStartInfo("…")', async () => {
      await reports(`        Process proc = new Process();
        proc.StartInfo = new ProcessStartInfo("/bin/sh");
        proc.StartInfo.ArgumentList.Add("-c");
        proc.StartInfo.ArgumentList.Add(name);
        proc.Start();`);
    });

    it('an unrelated ProcessStartInfo with a non-constant program does not hide it', async () => {
      await reports(`        var psi = new ProcessStartInfo("/bin/sh");
        var other = new ProcessStartInfo(name);\n${tail}`);
    });

    it('an explicit FileName write keeps deciding as before (same constant twice)', async () => {
      await reports(`        var psi = new ProcessStartInfo("/bin/sh");
        psi.FileName = "/bin/sh";\n${tail}`);
    });
  });

  describe('stays clean', () => {
    it('a constant non-shell program in the constructor (argv)', async () => {
      await clean(`        var psi = new ProcessStartInfo("/usr/bin/tar");\n${tail}`);
    });

    it('a constant non-shell program in the initializer', async () => {
      await clean(`        var psi = new ProcessStartInfo { FileName = "/usr/bin/tar" };\n${tail}`);
    });

    it('a shell with no command flag', async () => {
      await clean(`        var psi = new ProcessStartInfo("/bin/sh");
        psi.ArgumentList.Add(name);
        Process.Start(psi);`);
    });

    it('a constructor argument that is a variable holding a constant', async () => {
      await clean(`        string prog = "/bin/sh";
        var psi = new ProcessStartInfo(prog);\n${tail}`);
    });

    it('a two-argument constructor (the second is the argument string)', async () => {
      await clean(`        var psi = new ProcessStartInfo("/bin/sh", "-c ls");\n${tail}`);
    });

    it('an initializer that also sets Arguments', async () => {
      await clean(`        var psi = new ProcessStartInfo { FileName = "/bin/sh", Arguments = "-c ls" };\n${tail}`);
    });

    it('a constructor program and an initializer program together', async () => {
      await clean(`        var psi = new ProcessStartInfo("/bin/sh") { FileName = "/bin/sh" };\n${tail}`);
    });

    it('the variable is created twice', async () => {
      await clean(`        var psi = new ProcessStartInfo("/bin/sh");
        psi = new ProcessStartInfo("/bin/sh");\n${tail}`);
    });

    it('a later explicit non-shell FileName write replaces the constructor program', async () => {
      await clean(`        var psi = new ProcessStartInfo("/bin/sh");
        psi.FileName = "/usr/bin/ls";\n${tail}`);
    });

    it('ArgumentList.Clear() after the flag', async () => {
      await clean(`        var psi = new ProcessStartInfo("/bin/sh");
        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Clear();
        psi.ArgumentList.Add(name);
        Process.Start(psi);`);
    });

    it('the added value is overwritten with a literal', async () => {
      await clean(`        var psi = new ProcessStartInfo("/bin/sh");
        var cmd = name;
        cmd = "uptime";
        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add(cmd);
        Process.Start(psi);`);
    });

    it('a value converted to a number', async () => {
      await clean(`        var psi = new ProcessStartInfo("/bin/sh");
        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add("sleep " + int.Parse(name));
        Process.Start(psi);`);
    });

    it('the program is constant but a different variable carries the tainted list', async () => {
      await clean(`        var psi = new ProcessStartInfo("/bin/sh");
        var tool = new ProcessStartInfo("/usr/bin/tar");
        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add("uptime");
        tool.ArgumentList.Add("-c");
        tool.ArgumentList.Add(name);
        Process.Start(tool);`);
    });

    it('a constructor in another method does not count', async () => {
      const code = `using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
public class ScriptListController : Controller
{
    private ProcessStartInfo Make() { var psi = new ProcessStartInfo("/bin/sh"); return psi; }
    [HttpGet("m/{name}")]
    public string Run(string name)
    {
        var psi = Make();
        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add(name);
        Process.Start(psi);
        return "";
    }
}
`;
      const r = await analyze(code, 'ScriptListController.cs', 'csharp');
      expect((r.taint.flows ?? []).filter((f) => f.sink_type === 'command_injection')).toEqual([]);
    });
  });
});
