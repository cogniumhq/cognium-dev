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

  it('step 2: cross-file array carrier reaches tainted sink; constant path stays clean', async () => {
    const pa = await analyzeProject(
      [
        { filePath: 'Feeder.cs', code: feeder, language: 'csharp' },
        { filePath: 'Executor.cs', code: executor, language: 'csharp' },
      ],
      {},
    );
    const runArgsSink = lineOf(executor, 'Process.Start', 1);
    const runSlotSink = lineOf(executor, 'Process.Start', 0);
    expect(
      pa.taint_paths.some(
        p =>
          p.sink.file === 'Executor.cs' &&
          p.sink.line === runArgsSink &&
          p.sink.type === 'command_injection' &&
          p.source.file === 'Feeder.cs',
      ),
    ).toBe(true);
    expect(
      pa.taint_paths.some(p => p.sink.file === 'Executor.cs' && p.sink.line === runSlotSink),
    ).toBe(false);
    const execIr = pa.files.find(f => f.file === 'Executor.cs')!.analysis;
    expect(
      execIr.taint.sources?.some(
        s => s.type === 'interprocedural_param' && s.variable === 'args' && s.in_method === 'RunArgs',
      ),
    ).toBe(true);
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

const boxFeeder = `using System.Web;
public class Pod { public string payload; }
public class Feeder
{
    public void Holder(HttpRequest req)
    {
        Pod pod = new Pod();
        pod.payload = req.QueryString["host"];
        Executor.BoxSink(pod);
    }
    public void LiteralOnly()
    {
        Pod pod = new Pod();
        pod.payload = "localhost";
        Executor.BoxSink(pod);
    }
}
`;

const boxExecutor = `using System.Diagnostics;
public class Executor
{
    public static void BoxSink(Pod pod)
    {
        string target = pod.payload;
        Process.Start("cmd.exe", "/c ping " + target);
    }
}
`;

const staticFeeder = `using System.Web;
public class A {
    public static string stored;
    public void Field(HttpRequest req) {
        stored = req.QueryString["name"];
        new B().FieldSink();
    }
}`;

const staticExecutor = `using System.Diagnostics;
public class B {
    public void FieldSink() {
        string data = A.stored;
        Process.Start("cmd.exe /c dir " + data);
    }
}`;

describe('#638 step 4: static field cross-file carrier', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('cross-file path when a static field is tainted; literal write stays clean', async () => {
    const pa = await analyzeProject(
      [
        { filePath: 'A.cs', code: staticFeeder, language: 'csharp' },
        { filePath: 'B.cs', code: staticExecutor, language: 'csharp' },
      ],
      {},
    );
    const taintedSink = lineOf(staticExecutor, 'Process.Start', 0);
    expect(
      pa.taint_paths.some(
        p =>
          p.sink.file === 'B.cs' &&
          p.sink.line === taintedSink &&
          p.sink.type === 'command_injection' &&
          p.source.file === 'A.cs',
      ),
    ).toBe(true);

    const literalFeeder = `using System.Web;
public class A {
    public static string stored;
    public void LiteralOnly() {
        stored = "localhost";
        new B().FieldSink();
    }
}
`;
    const literalPa = await analyzeProject(
      [
        { filePath: 'A.cs', code: literalFeeder, language: 'csharp' },
        { filePath: 'B.cs', code: staticExecutor, language: 'csharp' },
      ],
      {},
    );
    expect(
      literalPa.taint_paths.some(
        p => p.sink.file === 'B.cs' && p.sink.line === taintedSink,
      ),
    ).toBe(false);
  });
});

describe('#638 step 3: container field cross-file carrier', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('cross-file path when container field is tainted; literal-only path stays clean', async () => {
    const pa = await analyzeProject(
      [
        { filePath: 'Feeder.cs', code: boxFeeder, language: 'csharp' },
        { filePath: 'Executor.cs', code: boxExecutor, language: 'csharp' },
      ],
      {},
    );
    const taintedSink = lineOf(boxExecutor, 'Process.Start', 0);
    expect(
      pa.taint_paths.some(
        p =>
          p.sink.file === 'Executor.cs' &&
          p.sink.line === taintedSink &&
          p.sink.type === 'command_injection' &&
          p.source.file === 'Feeder.cs',
      ),
    ).toBe(true);
    const literalFeeder = `using System.Web;
public class Pod { public string payload; }
public class Feeder
{
    public void LiteralOnly()
    {
        Pod pod = new Pod();
        pod.payload = "localhost";
        Executor.BoxSink(pod);
    }
}
`;
    const literalPa2 = await analyzeProject(
      [
        { filePath: 'Feeder.cs', code: literalFeeder, language: 'csharp' },
        { filePath: 'Executor.cs', code: boxExecutor, language: 'csharp' },
      ],
      {},
    );
    expect(
      literalPa2.taint_paths.some(
        p => p.sink.file === 'Executor.cs' && p.sink.line === taintedSink,
      ),
    ).toBe(false);
  });
});
