/**
 * cognium-dev #614 — Juliet flow variant 52 (three-class relay): project-level
 * constant-caller gate must drop goodG2B sinks while bad() keeps reporting.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';

type F = { filePath: string; code: string };

const project = async (files: F[]) => {
  const pa = await analyzeProject(files.map(f => ({ ...f, language: 'java' as const })), {});
  const out = new Map<string, Array<{ sink_type: string; sink_line: number }>>();
  for (const fa of pa.files) {
    out.set(
      fa.file,
      (fa.analysis.taint.flows ?? []).map(f => ({ sink_type: f.sink_type, sink_line: f.sink_line })),
    );
  }
  return out;
};

const pathAt = (
  flows: Map<string, Array<{ sink_type: string; sink_line: number }>>,
  file: string,
  line: number,
) => (flows.get(file) ?? []).some(f => f.sink_type === 'path_traversal' && f.sink_line === line);

const entry = `package relay;

public class PathEntry {
    public void bad() throws Throwable {
        String data = System.getenv("ADD");
        PathRelay.badSink(data);
    }

    public void good() throws Throwable {
        goodG2B();
    }

    private void goodG2B() throws Throwable {
        String data = "foo";
        PathRelay.goodG2BSink(data);
    }
}
`;

const relay = `package relay;

public class PathRelay {
    public static void badSink(String data) throws Throwable {
        PathSink.badSink(data);
    }

    public static void goodG2BSink(String data) throws Throwable {
        PathSink.goodG2BSink(data);
    }
}
`;

const sink = `package relay;

import java.io.*;

public class PathSink {
    public static void badSink(String data) throws Throwable {
        String root = "/home/user/uploads/";
        if (data != null) {
            File file = new File(root + data);
            if (file.exists() && file.isFile()) {
                new FileInputStream(file);
            }
        }
    }

    public static void goodG2BSink(String data) throws Throwable {
        String root = "/home/user/uploads/";
        if (data != null) {
            File file = new File(root + data);
            if (file.exists() && file.isFile()) {
                new FileInputStream(file);
            }
        }
    }
}
`;

const lineOf = (code: string, needle: string, nth = 0) => {
  let seen = -1;
  const lines = code.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (lines[i]!.includes(needle) && ++seen === nth) return i + 1;
  }
  return -1;
};

describe('#614 Java Juliet-52 relay (project gate)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('reports badSink only; goodG2BSink is dropped when callers pass constants', async () => {
    const flows = await project([
      { filePath: 'relay/PathEntry.java', code: entry },
      { filePath: 'relay/PathRelay.java', code: relay },
      { filePath: 'relay/PathSink.java', code: sink },
    ]);
    const sinkFile = 'relay/PathSink.java';
    expect(pathAt(flows, sinkFile, lineOf(sink, 'new FileInputStream', 0))).toBe(true);
    expect(pathAt(flows, sinkFile, lineOf(sink, 'new FileInputStream', 1))).toBe(false);
  });
});
