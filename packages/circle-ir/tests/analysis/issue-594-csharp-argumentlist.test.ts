/**
 * cognium-dev#594 (slice): C# — `X.StartInfo.ArgumentList.Add(<tainted>)` (or
 * `psi.ArgumentList.Add(<tainted>)` on a local `ProcessStartInfo`) behind a
 * constant shell program that is told to run a command string (`-c`, `/c`, …)
 * links source to sink. argv for a constant non-shell program, a shell without a
 * command flag, a non-constant program and a literal-overwritten value stay clean.
 *
 * SAST regression fixtures — the controllers are deliberately vulnerable.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

async function cmdi(code: string, file = 'ScriptListController.cs'): Promise<number[]> {
  const r = await analyze(code, file, 'csharp');
  return [...new Set((r.taint.flows ?? []).filter((f) => f.sink_type === 'command_injection').map((f) => f.sink_line))].sort((a, b) => a - b);
}

const wrap = (methods: string) => `using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
public class ScriptListController : Controller
{
${methods}
}
`;

/** One method; the `Start` call is the last line of `body`. */
const method = (params: string, body: string) => `    [HttpGet("m/{name}")]
    public string Run(${params})
    {
${body}
        return "";
    }
`;

describe('cognium-dev#594 — ArgumentList.Add behind a shell command flag', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('reports a tainted Add behind cmd.exe /c (process object)', async () => {
    const code = wrap(method('string name', `        Process proc = new Process();
        proc.StartInfo.FileName = "cmd.exe";
        proc.StartInfo.ArgumentList.Add("/c");
        proc.StartInfo.ArgumentList.Add("echo " + name);
        proc.Start();`));
    expect(await cmdi(code)).toEqual([12]);
  });

  it('reports a tainted Add behind /bin/sh -c on a local ProcessStartInfo', async () => {
    const code = wrap(method('string name', `        var psi = new ProcessStartInfo();
        psi.FileName = "/bin/sh";
        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add(name);
        Process.Start(psi);`));
    expect(await cmdi(code)).toEqual([12]);
  });

  it('reports with spaces before the parens and a renamed receiver', async () => {
    const code = wrap(method('string target', `        Process worker = new Process();
        worker.StartInfo.FileName = "bash";
        worker.StartInfo.ArgumentList.Add ( "-c" ) ;
        worker.StartInfo.ArgumentList.Add ( "echo " + target ) ;
        worker.Start();`));
    expect(await cmdi(code)).toEqual([12]);
  });

  it('reports a tainted local copy', async () => {
    const code = wrap(method('string name', `        var line = name;
        var psi = new ProcessStartInfo();
        psi.FileName = "powershell";
        psi.ArgumentList.Add("-Command");
        psi.ArgumentList.Add(line);
        Process.Start(psi);`));
    expect(await cmdi(code)).toEqual([13]);
  });

  describe('stays clean', () => {
    it('a constant non-shell program (argv): git log <branch>', async () => {
      const code = wrap(method('string branch', `        Process proc = new Process();
        proc.StartInfo.FileName = "git";
        proc.StartInfo.ArgumentList.Add("log");
        proc.StartInfo.ArgumentList.Add(branch);
        proc.StartInfo.UseShellExecute = false;
        proc.Start();`));
      expect(await cmdi(code)).toEqual([]);
    });

    it('a non-shell program even when a command-style flag is added', async () => {
      const code = wrap(method('string branch', `        var psi = new ProcessStartInfo();
        psi.FileName = "git";
        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add(branch);
        Process.Start(psi);`));
      expect(await cmdi(code)).toEqual([]);
    });

    it('a shell without a command flag', async () => {
      const code = wrap(method('string name', `        Process proc = new Process();
        proc.StartInfo.FileName = "cmd.exe";
        proc.StartInfo.ArgumentList.Add(name);
        proc.Start();`));
      expect(await cmdi(code)).toEqual([]);
    });

    it('a program held in a local rather than a literal', async () => {
      const code = wrap(method('string name', `        string prog = "sh";
        Process proc = new Process();
        proc.StartInfo.FileName = prog;
        proc.StartInfo.ArgumentList.Add("-c");
        proc.StartInfo.ArgumentList.Add(name);
        proc.Start();`));
      expect(await cmdi(code)).toEqual([]);
    });

    it('two FileName writes', async () => {
      const code = wrap(method('string name', `        Process proc = new Process();
        proc.StartInfo.FileName = "sh";
        proc.StartInfo.FileName = "git";
        proc.StartInfo.ArgumentList.Add("-c");
        proc.StartInfo.ArgumentList.Add(name);
        proc.Start();`));
      expect(await cmdi(code)).toEqual([]);
    });

    it('a value converted to a number', async () => {
      const code = wrap(method('string name', `        Process proc = new Process();
        proc.StartInfo.FileName = "bash";
        proc.StartInfo.ArgumentList.Add("-c");
        proc.StartInfo.ArgumentList.Add("sleep " + int.Parse(name));
        proc.Start();`));
      expect(await cmdi(code)).toEqual([]);
    });

    it('a tainted parameter that never reaches the process', async () => {
      const code = wrap(method('string name', `        Process proc = new Process();
        proc.StartInfo.FileName = "bash";
        proc.StartInfo.ArgumentList.Add("-c");
        proc.StartInfo.ArgumentList.Add("uptime");
        proc.Start();
        return name;`));
      expect(await cmdi(code)).toEqual([]);
    });

    it('the list is cleared before the process starts', async () => {
      const code = wrap(method('string name', `        Process proc = new Process();
        proc.StartInfo.FileName = "bash";
        proc.StartInfo.ArgumentList.Add("-c");
        proc.StartInfo.ArgumentList.Add(name);
        proc.StartInfo.ArgumentList.Clear();
        proc.StartInfo.ArgumentList.Add("uptime");
        proc.Start();`));
      expect(await cmdi(code)).toEqual([]);
    });

    it('the value is overwritten with a literal before the Add', async () => {
      const code = wrap(method('string name', `        var cmd = name;
        cmd = "uptime";
        var psi = new ProcessStartInfo();
        psi.FileName = "sh";
        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add(cmd);
        Process.Start(psi);`));
      expect(await cmdi(code)).toEqual([]);
    });

    it('the parameter is overwritten with a literal before the Add', async () => {
      const code = wrap(method('string name', `        name = "uptime";
        Process proc = new Process();
        proc.StartInfo.FileName = "bash";
        proc.StartInfo.ArgumentList.Add("-c");
        proc.StartInfo.ArgumentList.Add("echo " + name);
        proc.Start();`));
      expect(await cmdi(code)).toEqual([]);
    });

    it('an unrelated type with an ArgumentList member', async () => {
      const code = wrap(method('string name', `        var job = new JobSpec();
        job.FileName = "sh";
        job.ArgumentList.Add("-c");
        job.ArgumentList.Add(name);
        job.Run();`));
      expect(await cmdi(code)).toEqual([]);
    });

    it('a sibling method with the same local names stays isolated', async () => {
      const code = wrap(`${method('string name', `        Process proc = new Process();
        proc.StartInfo.FileName = "bash";
        proc.StartInfo.ArgumentList.Add("-c");
        proc.StartInfo.ArgumentList.Add("echo " + name);
        proc.Start();`)}
    [HttpGet("n")]
    public string Safe(string name)
    {
        Process proc = new Process();
        proc.StartInfo.FileName = "bash";
        proc.StartInfo.ArgumentList.Add("-c");
        proc.StartInfo.ArgumentList.Add("uptime");
        proc.Start();
        return name;
    }
`);
      expect(await cmdi(code)).toEqual([12]);
    });
  });

  it('keeps the #276 control: Process.Start(file, args) with a tainted concat', async () => {
    const code = wrap(method('string name', `        Process.Start("cmd.exe", "/c echo " + name);`));
    expect((await cmdi(code)).length).toBeGreaterThanOrEqual(1);
  });
});
