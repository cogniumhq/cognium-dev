/**
 * cognium-dev#594 (minimal slice) — C#: `X.StartInfo.Arguments = <tainted>;`
 * followed by the zero-argument `X.Start();` links source to sink when the
 * program is a shell (or is not a constant). A constant non-shell program with
 * argv is the #272 / #328 safe shape and stays clean.
 *
 * SAST regression fixtures — the controllers are deliberately vulnerable.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const scriptHost = `using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

public class ScriptHostController : Controller
{
    [HttpGet("script/{name}")]
    public string Run(string name)
    {
        Process proc = new Process();
        proc.StartInfo.FileName = "cmd.exe";
        proc.StartInfo.Arguments = "/c " + name;
        proc.Start();
        return proc.StandardOutput.ReadToEnd();
    }
}
`;

const history = `using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

public class HistoryController : Controller
{
    [HttpGet("history/{branch}")]
    public string Log(string branch)
    {
        Process proc = new Process();
        proc.StartInfo.FileName = "git";
        proc.StartInfo.Arguments = "log " + branch;
        proc.StartInfo.UseShellExecute = false;
        proc.Start();
        return proc.StandardOutput.ReadToEnd();
    }
}
`;

async function cmdiSinkLines(code: string, file = 'Controller.cs'): Promise<number[]> {
  const r = await analyze(code, file, 'csharp');
  return [...new Set((r.taint.flows ?? []).filter((f) => f.sink_type === 'command_injection').map((f) => f.sink_line))].sort((a, b) => a - b);
}

describe('#594: C# StartInfo.Arguments carries taint to Process.Start() when the program is a shell', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('a constant shell FileName with a tainted Arguments reports command_injection at Start() (line 12)', async () => {
    expect(await cmdiSinkLines(scriptHost, 'ScriptHostController.cs')).toEqual([12]);
  });

  it('a constant non-shell program with tainted argv and UseShellExecute=false stays clean', async () => {
    expect(await cmdiSinkLines(history, 'HistoryController.cs')).toEqual([]);
  });

  it('is not keyed on identifiers: renamed process, parameter and shell still fire', async () => {
    const code = scriptHost
      .replace(/\bproc\b/g, 'child')
      .replace(/\bname\b/g, 'script')
      .replace('"cmd.exe"', '"/bin/sh"')
      .replace('"/c "', '"-c "');
    expect(await cmdiSinkLines(code)).toEqual([12]);
  });

  it('a non-constant FileName with a tainted Arguments reports command_injection', async () => {
    const code = scriptHost.replace('"cmd.exe"', 'Config.Shell');
    expect(await cmdiSinkLines(code)).toEqual([12]);
  });

  it('a constant shell with a constant Arguments beside an unrelated tainted parameter stays clean', async () => {
    const code = `using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

public class CleanupController : Controller
{
    [HttpGet("clean")]
    public string Clean(string label)
    {
        Process proc = new Process();
        proc.StartInfo.FileName = "cmd.exe";
        proc.StartInfo.Arguments = "/c dir";
        proc.Start();
        return label + proc.StandardOutput.ReadToEnd();
    }
}
`;
    expect(await cmdiSinkLines(code)).toEqual([]);
  });

  it('a comparison against Arguments is not an assignment', async () => {
    const code = `using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

public class CompareController : Controller
{
    [HttpGet("c")]
    public string Compare(string name)
    {
        Process proc = new Process();
        proc.StartInfo.FileName = "cmd.exe";
        proc.StartInfo.Arguments = "/c dir";
        if (proc.StartInfo.Arguments == name)
        {
            proc.StartInfo.RedirectStandardOutput = true;
        }
        proc.Start();
        return proc.StandardOutput.ReadToEnd();
    }
}
`;
    expect(await cmdiSinkLines(code)).toEqual([]);
  });

  it('#701 control: a tainted FileName still fires', async () => {
    const code = `using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

public class ToolRunnerController : Controller
{
    [HttpGet("run/{tool}")]
    public string Run(string tool)
    {
        Process proc = new Process();
        proc.StartInfo.FileName = tool;
        proc.Start();
        return proc.StandardOutput.ReadToEnd();
    }
}
`;
    expect(await cmdiSinkLines(code)).toEqual([11]);
  });

  it('#276 control: Process.Start("cmd.exe", "/c echo " + name) still fires', async () => {
    const code = `using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

public class EchoController : ControllerBase
{
    public void Echo([FromQuery] string name)
    {
        Process.Start("cmd.exe", "/c echo " + name);
    }
}
`;
    expect(await cmdiSinkLines(code)).toEqual([8]);
  });
});
