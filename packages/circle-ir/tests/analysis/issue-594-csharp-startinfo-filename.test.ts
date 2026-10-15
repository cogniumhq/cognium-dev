/**
 * cognium-dev#594 (minimal slice) — C#: `X.StartInfo.FileName = <tainted>;`
 * followed by the zero-argument `X.Start();` links source to sink.
 *
 * SAST regression fixtures — the controller is deliberately vulnerable.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const runner = `using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

public class ToolRunnerController : Controller
{
    [HttpGet("run/{tool}")]
    public string Run(string tool)
    {
        Process proc = new Process();
        proc.StartInfo.FileName = tool;
        proc.StartInfo.RedirectStandardOutput = true;
        proc.Start();
        return proc.StandardOutput.ReadToEnd();
    }

    [HttpGet("fixed")]
    public string Fixed(string label)
    {
        Process proc = new Process();
        proc.StartInfo.FileName = "/usr/bin/uptime";
        proc.StartInfo.RedirectStandardOutput = true;
        proc.Start();
        return label + proc.StandardOutput.ReadToEnd();
    }
}
`;

async function cmdiSinkLines(code: string): Promise<number[]> {
  const r = await analyze(code, 'ToolRunnerController.cs', 'csharp');
  return [...new Set((r.taint.flows ?? []).filter((f) => f.sink_type === 'command_injection').map((f) => f.sink_line))].sort((a, b) => a - b);
}

describe('#594: C# StartInfo.FileName carries taint to Process.Start()', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('a tainted FileName reports command_injection at Start() (line 12); the constant FileName method (line 22) stays clean', async () => {
    expect(await cmdiSinkLines(runner)).toEqual([12]);
  });

  it('is not keyed on identifiers: renamed process and parameter still fire', async () => {
    const code = runner.replace(/\bproc\b/g, 'child').replace(/\btool\b/g, 'binary');
    expect(await cmdiSinkLines(code)).toEqual([12]);
  });

  it('a tainted parameter that never reaches StartInfo does not seed the process', async () => {
    const code = `using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

public class UptimeController : Controller
{
    [HttpGet("up")]
    public string Up(string label)
    {
        var p = new Process();
        p.StartInfo.FileName = "/usr/bin/uptime";
        p.Start();
        return label;
    }
}
`;
    expect(await cmdiSinkLines(code)).toEqual([]);
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

  it('#272 / #328 control: constant non-shell exe with tainted argv stays clean', async () => {
    const code = `using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

public class GrepController : ControllerBase
{
    public void Find([FromQuery] string pattern)
    {
        Process.Start(new ProcessStartInfo("grep", pattern) { UseShellExecute = false });
    }
}
`;
    expect(await cmdiSinkLines(code)).toEqual([]);
  });
});
