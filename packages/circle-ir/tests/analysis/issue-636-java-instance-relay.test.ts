/**
 * cognium-dev#636 — Juliet flow variant 52 uses `new Relay().sink(data)` instance
 * dispatch; the Java constant-caller gate must resolve those calls project-wide.
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
  return { pa, flows: out };
};

const lineOf = (code: string, needle: string, nth = 0) => {
  let seen = -1;
  const lines = code.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (lines[i]!.includes(needle) && ++seen === nth) return i + 1;
  }
  return -1;
};

const entryGood = `package relay;
public class PathEntry {
    public void goodG2B() throws Throwable {
        String data = "foo";
        new PathRelay().goodG2BSink(data);
    }
}
`;

const entryBad = `package relay;
public class PathEntry {
    public void bad(javax.servlet.http.HttpServletRequest req) throws Throwable {
        String data = req.getParameter("item");
        new PathRelay().badSink(data);
    }
}
`;

const relay = `package relay;
public class PathRelay {
    public void badSink(String data) throws Throwable {
        PathSink.badSink(data);
    }
    public void goodG2BSink(String data) throws Throwable {
        PathSink.goodG2BSink(data);
    }
}
`;

const sink = `package relay;
import java.io.*;
public class PathSink {
    public static void badSink(String data) throws Throwable {
        String root = "/home/user/uploads/";
        File file = new File(root + data);
        if (file.exists()) new FileInputStream(file);
    }
    public static void goodG2BSink(String data) throws Throwable {
        String root = "/home/user/uploads/";
        File file = new File(root + data);
        if (file.exists()) new FileInputStream(file);
    }
}
`;

const pathAt = (
  flows: Map<string, Array<{ sink_type: string; sink_line: number }>>,
  file: string,
  line: number,
) => (flows.get(file) ?? []).some(f => f.sink_type === 'path_traversal' && f.sink_line === line);

describe('#636 Java instance relay (Juliet-52 shape)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('drops goodG2BSink when constants reach it through new Relay().method()', async () => {
    const { flows } = await project([
      { filePath: 'relay/PathEntry.java', code: entryGood },
      { filePath: 'relay/PathRelay.java', code: relay },
      { filePath: 'relay/PathSink.java', code: sink },
    ]);
    const sinkFile = 'relay/PathSink.java';
    expect(pathAt(flows, sinkFile, lineOf(sink, 'new FileInputStream', 1))).toBe(false);
  });

  it('still reports badSink reached via new PathRelay().badSink(tainted)', async () => {
    const { flows } = await project([
      { filePath: 'relay/PathEntry.java', code: entryBad },
      { filePath: 'relay/PathRelay.java', code: relay },
      { filePath: 'relay/PathSink.java', code: sink },
    ]);
    const sinkFile = 'relay/PathSink.java';
    expect(pathAt(flows, sinkFile, lineOf(sink, 'new FileInputStream', 0))).toBe(true);
  });
});
