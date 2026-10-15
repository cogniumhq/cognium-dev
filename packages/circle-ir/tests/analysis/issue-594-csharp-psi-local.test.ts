/**
 * cognium-dev#594 (slice): C# — a local `ProcessStartInfo psi` whose `FileName`
 * is tainted (or whose `Arguments` are tainted behind a shell / a non-constant
 * program), passed to `Process.Start(psi)`, links source to sink. A constant
 * non-shell program with argv (the #272 / #328 shape) and an unrelated type with
 * a `FileName` property stay clean.
 *
 * SAST regression fixtures — the controllers are deliberately vulnerable.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

async function cmdi(code: string, file = 'ToolController.cs'): Promise<number[]> {
  const r = await analyze(code, file, 'csharp');
  return [...new Set((r.taint.flows ?? []).filter((f) => f.sink_type === 'command_injection').map((f) => f.sink_line))].sort((a, b) => a - b);
}

const HEAD = `using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
public class ToolController : Controller
{
`;

const tool = `${HEAD}    [HttpGet("a/{tool}")]
    public string RunTool(string tool)
    {
        var psi = new ProcessStartInfo();
        psi.FileName = tool;
        Process.Start(psi);
        return "";
    }

    [HttpGet("b/{step}")]
    public string RunStep(string step)
    {
        var psi = new ProcessStartInfo();
        psi.FileName = "cmd.exe";
        psi.Arguments = "/c " + step;
        Process.Start(psi);
        return "";
    }

    [HttpGet("c/{branch}")]
    public string History(string branch)
    {
        var psi = new ProcessStartInfo();
        psi.FileName = "git";
        psi.Arguments = "log " + branch;
        psi.UseShellExecute = false;
        Process.Start(psi);
        return "";
    }
}
`;

describe('cognium-dev#594 ProcessStartInfo local passed to Process.Start', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('a tainted FileName and a tainted Arguments behind cmd.exe report; constant git argv stays clean', async () => {
    // Process.Start(psi) at 10 (FileName), 20 (cmd.exe + Arguments), 32 (git: clean)
    expect(await cmdi(tool)).toEqual([10, 20]);
  });

  it('Arguments with no FileName write in the method seeds nothing', async () => {
    const code = `${HEAD}    public string Run(string name, ProcessStartInfo psi)
    {
        psi.Arguments = "/c " + name;
        Process.Start(psi);
        return "";
    }
}
`;
    expect(await cmdi(code)).toEqual([]);
  });

  it('a non-constant program lets tainted Arguments choose what runs', async () => {
    const code = `${HEAD}    public string Run(string prog, string name)
    {
        var psi = new ProcessStartInfo();
        psi.FileName = prog;
        psi.Arguments = name;
        Process.Start(psi);
        return "";
    }
}
`;
    expect(await cmdi(code)).toEqual([10]);
  });

  it('a FileName property on an unrelated type is not a process', async () => {
    const code = `${HEAD}    public string Run(string name)
    {
        var doc = new Attachment();
        doc.FileName = name;
        Process.Start("cmd.exe", "/c echo hi");
        return doc.FileName;
    }
}
class Attachment { public string FileName { get; set; } }
`;
    expect(await cmdi(code)).toEqual([]);
  });

  it('a tainted FileName overwritten by a literal before Start is clean', async () => {
    const code = `${HEAD}    public string Run(string tool)
    {
        ProcessStartInfo psi = new ProcessStartInfo();
        psi.FileName = tool;
        psi.FileName = "git";
        psi.UseShellExecute = false;
        Process.Start(psi);
        return "";
    }
}
`;
    expect(await cmdi(code)).toEqual([]);
  });

  it('the #276 control Process.Start("cmd.exe", "/c echo " + name) keeps reporting', async () => {
    const code = `${HEAD}    public string Run(string name)
    {
        Process.Start("cmd.exe", "/c echo " + name);
        return "";
    }
}
`;
    expect(await cmdi(code)).toEqual([7]);
  });

  it('two methods reusing the local name seed per method', async () => {
    const code = `${HEAD}    public string A(string tool)
    {
        var psi = new ProcessStartInfo();
        psi.FileName = tool;
        Process.Start(psi);
        return "";
    }
    public string B(string tool)
    {
        var psi = new ProcessStartInfo();
        psi.FileName = "ls";
        Process.Start(psi);
        return "";
    }
}
`;
    expect(await cmdi(code)).toEqual([9]);
  });

  it('a numeric conversion in Arguments does not carry text; a raw operand beside it still reports', async () => {
    const clean = `${HEAD}    public string Run(string t)
    {
        var psi = new ProcessStartInfo();
        psi.FileName = "cmd.exe";
        psi.Arguments = "/c " + int.Parse(t);
        Process.Start(psi);
        return "";
    }
}
`;
    expect(await cmdi(clean)).toEqual([]);
    const mixed = clean.replace('int.Parse(t)', 'int.Parse(t) + t');
    expect(await cmdi(mixed)).toEqual([10]);
  });

  it('a tainted write guarded by a null check on the same line still reports', async () => {
    const code = `${HEAD}    public string Run(string t)
    {
        var psi = new ProcessStartInfo();
        if (t != null) { psi.FileName = t; }
        Process.Start (psi);
        return "";
    }
}
`;
    expect(await cmdi(code)).toEqual([9]);
  });
});
