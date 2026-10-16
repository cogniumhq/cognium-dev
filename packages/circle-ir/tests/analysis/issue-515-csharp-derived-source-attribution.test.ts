/**
 * #515 (C# slice) — derived alias source attribution must follow the RHS,
 * not the earliest unused read in the same method.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const flowsOf = async (code: string, file: string) => {
  const ir = await analyze(code, file, 'csharp');
  return (ir.taint.flows ?? []).map(f => [f.source_line, f.sink_line, f.sink_type] as const);
};

const EXPORT = `using System;
using System.Diagnostics;

public class ArchiveExportController
{
    public void Export()
    {
        string note = Console.ReadLine();
        string fmt = Environment.GetEnvironmentVariable("X-Format");
        string cmdline = "tar --format " + fmt;
        Process.Start(cmdline);
    }
}
`;

const DECOY = `using System;
using System.Diagnostics;

public class ArchiveDecoyController
{
    public void Export()
    {
        string note = Console.ReadLine();
        string cmdline = "tar --format zip";
        Process.Start(cmdline);
    }
}
`;

describe('#515 C# derived-variable source attribution', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('credits the read the derivation references, not an earlier decoy read', async () => {
    const flows = await flowsOf(EXPORT, 'ArchiveExportController.cs');
    expect(flows).toEqual([[9, 11, 'command_injection']]);
  });

  it('keeps a literal-only command with no flow', async () => {
    expect(await flowsOf(DECOY, 'ArchiveDecoyController.cs')).toEqual([]);
  });
});
