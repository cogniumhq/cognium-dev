/**
 * cognium-dev#750 (slice 2): C# — `FileName` assigned from a same-file `const string`
 * field counts as that constant program for ArgumentList shell-reachability.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const wrap = (body: string, members = '', params = 'string script') => `using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
public class TaskRunnerController : Controller
{
${members}
    [HttpGet("t/{script}")]
    public string Run(${params})
    {
${body}
        return "";
    }
}
`;

async function run(body: string, members = '', params?: string, file = 'TaskRunnerController.cs') {
  const code = wrap(body, members, params);
  const startLine = code.split('\n').findIndex((l) => /\bStart\s*\(/.test(l)) + 1;
  const r = await analyze(code, file, 'csharp');
  const lines = [...new Set((r.taint.flows ?? []).filter((f) => f.sink_type === 'command_injection').map((f) => f.sink_line))].sort((a, b) => a - b);
  return { startLine, lines };
}

const reports = async (body: string, members = '', params?: string) => {
  const { startLine, lines } = await run(body, members, params);
  expect(lines).toEqual([startLine]);
};
const clean = async (body: string, members = '', params?: string) => {
  expect((await run(body, members, params)).lines).toEqual([]);
};

const jobTail = `        job.ArgumentList.Add("-c");
        job.ArgumentList.Add(script);
        Process.Start(job);`;

describe('cognium-dev#750 — const string field as FileName program', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  describe('reports', () => {
    it('class-level const string field', async () => {
      await reports(
        `        var job = new ProcessStartInfo();
        job.FileName = Interpreter;
${jobTail}`,
        '    private const string Interpreter = "/bin/bash";',
      );
    });

    it('issue spelling Shell = /bin/sh', async () => {
      await reports(
        `        var psi = new ProcessStartInfo();
        psi.FileName = Shell;
        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add(script);
        Process.Start(psi);`,
        '    public const string Shell = "/bin/sh";',
      );
    });
  });

  describe('stays clean', () => {
    it('constant non-shell program', async () => {
      await clean(
        `        var job = new ProcessStartInfo();
        job.FileName = Tool;
${jobTail}`,
        '    private const string Tool = "/usr/bin/ls";',
      );
    });

    it('static non-const field', async () => {
      await clean(
        `        var job = new ProcessStartInfo();
        job.FileName = Interpreter;
${jobTail}`,
        '    private static string Interpreter = "/bin/bash";',
      );
    });

    it('local variable, not a const string field', async () => {
      await clean(
        `        var launcherPath = "/usr/bin/ls";
        var job = new ProcessStartInfo();
        job.FileName = launcherPath;
${jobTail}`,
      );
    });

    it('const initialised from an expression', async () => {
      await clean(
        `        var job = new ProcessStartInfo();
        job.FileName = Interpreter;
${jobTail}`,
        `    private const string Prefix = "/bin/";
    private const string Interpreter = Prefix + "bash";`,
      );
    });

    it('second FileName write after the const one', async () => {
      await clean(
        `        var job = new ProcessStartInfo();
        job.FileName = Interpreter;
        job.FileName = "/usr/bin/ls";
${jobTail}`,
        '    private const string Interpreter = "/bin/bash";',
      );
    });

    it('no command flag', async () => {
      await clean(
        `        var job = new ProcessStartInfo();
        job.FileName = Interpreter;
        job.ArgumentList.Add(script);
        Process.Start(job);`,
        '    private const string Interpreter = "/bin/bash";',
      );
    });
  });
});
