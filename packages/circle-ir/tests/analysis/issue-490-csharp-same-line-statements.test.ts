/**
 * cognium-dev #490 (C# slice) — one-line multi-statement bodies must not
 * co-taint a literal neighbour or mis-bind reads across statements.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const HEADER = 'using System;\nusing System.Diagnostics;';

const wrap = (className: string, body: string) =>
  [
    HEADER,
    `public class ${className} {`,
    '  public static void Run() {',
    `    ${body}`,
    '  }',
    '}',
  ].join('\n');

const cmdi = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === 'command_injection' && !f.sanitized);

const BODY_LINE = 5;

beforeAll(async () => {
  await initAnalyzer();
});

describe('#490 C# same-line statements', () => {
  it('OneLineRunner: literal neighbour is not reported', async () => {
    const r = await analyze(
      wrap('OneLineRunner', 'string q = Console.ReadLine(); string x = "fixed"; Process.Start(x);'),
      'OneLineRunner.cs',
      'csharp',
    );
    expect(cmdi(r)).toEqual([]);
  });

  it('TwoDeclsRunner: read on second decl does not taint first literal', async () => {
    const r = await analyze(
      wrap('TwoDeclsRunner', 'string x = "fixed"; string y = Console.ReadLine(); Process.Start(x);'),
      'TwoDeclsRunner.cs',
      'csharp',
    );
    expect(cmdi(r)).toEqual([]);
  });

  it('DiscardedReadRunner: discarded read does not taint earlier literal', async () => {
    const r = await analyze(
      wrap('DiscardedReadRunner', 'string x = "fixed"; Console.ReadLine(); Process.Start(x);'),
      'DiscardedReadRunner.cs',
      'csharp',
    );
    expect(cmdi(r)).toEqual([]);
  });

  it('SameLineTp: direct use of read still reports', async () => {
    const r = await analyze(
      wrap('SameLineTp', 'string q = Console.ReadLine(); Process.Start(q);'),
      'SameLineTp.cs',
      'csharp',
    );
    const flows = cmdi(r);
    expect(flows).toHaveLength(1);
    expect(flows[0].sink_line).toBe(BODY_LINE);
  });

  it('TwoDeclsTp: sink uses the read binding, not the literal', async () => {
    const r = await analyze(
      wrap('TwoDeclsTp', 'string x = "fixed"; string y = Console.ReadLine(); Process.Start(y);'),
      'TwoDeclsTp.cs',
      'csharp',
    );
    const flows = cmdi(r);
    expect(flows).toHaveLength(1);
    expect(flows[0].sink_line).toBe(BODY_LINE);
  });

  it('ChainedTp: derived value from read still reports', async () => {
    const r = await analyze(
      wrap('ChainedTp', 'string q = Console.ReadLine(); string x = "ls " + q; Process.Start(x);'),
      'ChainedTp.cs',
      'csharp',
    );
    const flows = cmdi(r);
    expect(flows).toHaveLength(1);
    expect(flows[0].sink_line).toBe(BODY_LINE);
  });

  it('NestedReadTp: inline read inside sink argument still reports', async () => {
    const r = await analyze(
      wrap('NestedReadTp', 'string x = "fixed"; Process.Start(Console.ReadLine());'),
      'NestedReadTp.cs',
      'csharp',
    );
    const flows = cmdi(r);
    expect(flows).toHaveLength(1);
    expect(flows[0].sink_line).toBe(BODY_LINE);
  });
});
