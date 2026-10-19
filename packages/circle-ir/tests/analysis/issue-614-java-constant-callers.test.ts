/**
 * Java project gate: drop parameter-seeded sink flows when every in-project caller
 * passes a constant (#614, mirrors cognium-dev#636 C# relay shape).
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
    if (lines[i].includes(needle) && ++seen === nth) return i + 1;
  }
  return -1;
};

const dispatcher = `import java.io.File;
public class Dispatcher {
  public void handle(javax.servlet.http.HttpServletRequest req) throws Exception {
    String item = req.getParameter("item");
    Worker.runWithInput(item);
  }
  public void nightly() throws Exception {
    String label = "nightly-report";
    Worker.runWithLabel(label);
  }
}
`;

const worker = `import java.io.File;
public class Worker {
  public static void runWithInput(String arg) throws Exception {
    new File(arg);
  }
  public static void runWithLabel(String arg) throws Exception {
    new File(arg);
  }
}
`;

const pathAt = (
  flows: Map<string, Array<{ sink_type: string; sink_line: number }>>,
  file: string,
  line: number,
) => (flows.get(file) ?? []).some(f => f.sink_type === 'path_traversal' && f.sink_line === line);

describe('Java constant-only callers (#614)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('reports the tainted-caller sink and drops the constant-caller sink', async () => {
    const { flows } = await project([
      { filePath: 'Dispatcher.java', code: dispatcher },
      { filePath: 'Worker.java', code: worker },
    ]);
    expect(pathAt(flows, 'Worker.java', lineOf(worker, 'new File', 0))).toBe(true);
    expect(pathAt(flows, 'Worker.java', lineOf(worker, 'new File', 1))).toBe(false);
  });
});
