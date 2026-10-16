/**
 * cognium-dev#638 step 1 — constant-caller gate accepts literal-only local arrays.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';
import { isConstantArg, isLiteralArrayLocal } from '../../src/analysis/constant-caller-gate.js';
import type { CallInfo } from '../../src/types/index.js';

const feeder = `using System.Web;
public class Feeder
{
    public void Nightly()
    {
        string[] slots = new string[2];
        slots[0] = "localhost";
        slots[1] = "backup";
        Executor.RunSlot(slots);
    }
    public void FromRequest(HttpRequest req)
    {
        string[] args = new string[2];
        args[0] = "localhost";
        args[1] = req.QueryString["host"];
        Executor.RunArgs(args);
    }
}
`;

const executor = `using System.Diagnostics;
public class Executor
{
    public static void RunSlot(string[] slots)
    {
        string target = slots[0];
        Process.Start("cmd.exe", "/c ping " + target);
    }
    public static void RunArgs(string[] args)
    {
        string target = args[1];
        Process.Start("cmd.exe", "/c ping " + target);
    }
}
`;

const lineOf = (code: string, needle: string, nth = 0) => {
  let seen = -1;
  const lines = code.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes(needle) && ++seen === nth) return i + 1;
  }
  return -1;
};

const callAt = (ir: { calls: CallInfo[] }, fileLine: number, methodName: string) =>
  ir.calls.find(c => c.location.line === fileLine && c.method_name === methodName);

describe('#638 step 1: isLiteralArrayLocal / isConstantArg for arrays', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('constant-only array at Nightly call; tainted array at FromRequest call', async () => {
    const pa = await analyzeProject(
      [
        { filePath: 'Feeder.cs', code: feeder, language: 'csharp' },
        { filePath: 'Executor.cs', code: executor, language: 'csharp' },
      ],
      {},
    );
    const feederIr = pa.files.find(f => f.file === 'Feeder.cs')!.analysis;
    const lines = feeder.split('\n');
    const runSlotLine = lineOf(feeder, 'Executor.RunSlot');
    const runArgsLine = lineOf(feeder, 'Executor.RunArgs');
    const runSlot = callAt(feederIr, runSlotLine, 'RunSlot');
    const runArgs = callAt(feederIr, runArgsLine, 'RunArgs');
    expect(runSlot).toBeDefined();
    expect(runArgs).toBeDefined();

    expect(isLiteralArrayLocal(feederIr, lines, runSlot!, 'slots')).toBe(true);
    expect(isConstantArg(feederIr, lines, runSlot!, 0)).toBe(true);
    expect(isLiteralArrayLocal(feederIr, lines, runArgs!, 'args')).toBe(false);
    expect(isConstantArg(feederIr, lines, runArgs!, 0)).toBe(false);
  });

  it('analyzeProject flows unchanged (string[] params not seeded yet)', async () => {
    const snap = async () => {
      const pa = await analyzeProject(
        [
          { filePath: 'Feeder.cs', code: feeder, language: 'csharp' },
          { filePath: 'Executor.cs', code: executor, language: 'csharp' },
        ],
        {},
      );
      return JSON.stringify(
        pa.files.map(f => ({
          file: f.file,
          flows: (f.analysis.taint.flows ?? []).map(fl => ({
            sink_type: fl.sink_type,
            sink_line: fl.sink_line,
            source_type: fl.source_type,
          })),
        })),
      );
    };
    expect(await snap()).toBe(await snap());
  });

  const mustStayFalse = [
    {
      label: 'reassigned from parameter',
      code: `public class X {
  public void Go(string[] other) {
    string[] slots = new string[1];
    slots[0] = "a";
    slots = other;
    Worker.Run(slots);
  }
}`,
      callNeedle: 'Worker.Run',
    },
    {
      label: 'passed to another call first',
      code: `public class X {
  public void Go() {
    string[] slots = new string[1];
    slots[0] = "a";
    Log.Dump(slots);
    Worker.Run(slots);
  }
}`,
      callNeedle: 'Worker.Run',
    },
    {
      label: 'literal local later reassigned before element write',
      code: `using System.Web;
public class X {
  public void Go(HttpRequest req) {
    string[] slots = new string[1];
    string host = "localhost";
    host = req.QueryString["h"];
    slots[0] = host;
    Worker.Run(slots);
  }
}`,
      callNeedle: 'Worker.Run',
    },
    {
      label: 'array is caller parameter',
      code: `public class X {
  public void Go(string[] slots) {
    Worker.Run(slots);
  }
}`,
      callNeedle: 'Worker.Run',
    },
  ];

  it.each(mustStayFalse)('$label: isConstantArg stays false', async ({ code, callNeedle }) => {
    const pa = await analyzeProject([{ filePath: 'X.cs', code, language: 'csharp' }], {});
    const ir = pa.files[0].analysis;
    const lines = code.split('\n');
    const line = lineOf(code, callNeedle);
    const call = callAt(ir, line, 'Run');
    expect(call).toBeDefined();
    expect(isConstantArg(ir, lines, call!, 0)).toBe(false);
  });
});
