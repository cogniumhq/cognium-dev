/**
 * Repro for issue #124 — Java sink-type mis-categorization.
 *
 * Five `JAVA_SINK_RULES` entries in `src/analysis/config-loader.ts` matched
 * methods whose runtime semantics do NOT match the declared sink type. The
 * fix in 3.83.0 deletes the offending entries:
 *
 *   1. Pattern.compile(...)            tagged code_injection (CWE-94)
 *      Regex compilation does not execute code. Real risk is ReDoS,
 *      already covered by a separate `Pattern.compile -> redos` rule.
 *
 *   2. Process.waitFor()               tagged command_injection (CWE-78)
 *      Blocks on an already-spawned process; takes no args, no command
 *      string flows into it.
 *
 *   3. ProcessBuilder.inheritIO()      tagged command_injection (CWE-78)
 *      Takes no args.
 *
 *   4. ProcessBuilder.redirectOutput(File)  tagged command_injection
 *      File destination, not a command. If anything, path-traversal —
 *      but the threat model is marginal.
 *
 *   5. ProcessBuilder.redirectInput(File)   tagged command_injection
 *      File source, not a command.
 *
 * These shapes must NOT emit `command_injection` / `code_injection`.
 * The real Java command-exec sinks (Runtime.exec, ProcessBuilder.start /
 * .command / constructor) must STILL fire — recall locks below verify it.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';
import type { CircleIR } from '../../src/types/index.js';

const flowsByType = (ir: CircleIR, t: string) =>
  (ir.taint?.flows ?? []).filter((f) => f.sink_type === t);

describe('Issue #124 — Java sink-type mis-categorization (negative locks)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('Pattern.compile does NOT emit code_injection on tainted regex string', async () => {
    const code = `
import java.util.regex.Pattern;
import javax.servlet.http.HttpServletRequest;
public class A {
  public void doGet(HttpServletRequest req) {
    String r = req.getParameter("r");
    Pattern p = Pattern.compile(r);
  }
}
`;
    const ir = await analyze(code, 'PatternCompile.java', 'java');
    expect(flowsByType(ir, 'code_injection')).toHaveLength(0);
  });

  it('Process.waitFor does NOT emit command_injection', async () => {
    const code = `
import javax.servlet.http.HttpServletRequest;
public class A {
  public void doGet(HttpServletRequest req) throws Exception {
    String cmd = req.getParameter("cmd");
    Process p = Runtime.getRuntime().exec("ls");
    p.waitFor();
  }
}
`;
    const ir = await analyze(code, 'WaitFor.java', 'java');
    // waitFor() itself must not be the sink. (Runtime.exec("ls") with a
    // constant arg also should not fire because cmd is unrelated.)
    const flows = flowsByType(ir, 'command_injection');
    for (const f of flows) {
      expect((f.sink as { method?: string } | undefined)?.method ?? '').not.toBe('waitFor');
    }
  });

  it('ProcessBuilder.inheritIO does NOT emit command_injection', async () => {
    const code = `
import javax.servlet.http.HttpServletRequest;
public class A {
  public void doGet(HttpServletRequest req) throws Exception {
    String s = req.getParameter("s");
    ProcessBuilder pb = new ProcessBuilder("ls");
    pb.inheritIO();
  }
}
`;
    const ir = await analyze(code, 'InheritIO.java', 'java');
    const flows = flowsByType(ir, 'command_injection');
    for (const f of flows) {
      expect((f.sink as { method?: string } | undefined)?.method ?? '').not.toBe('inheritIO');
    }
  });

  it('ProcessBuilder.redirectOutput(File) does NOT emit command_injection', async () => {
    const code = `
import java.io.File;
import javax.servlet.http.HttpServletRequest;
public class A {
  public void doGet(HttpServletRequest req) throws Exception {
    String path = req.getParameter("p");
    File out = new File(path);
    ProcessBuilder pb = new ProcessBuilder("ls");
    pb.redirectOutput(out);
  }
}
`;
    const ir = await analyze(code, 'RedirectOutput.java', 'java');
    const flows = flowsByType(ir, 'command_injection');
    for (const f of flows) {
      expect((f.sink as { method?: string } | undefined)?.method ?? '').not.toBe('redirectOutput');
    }
  });

  it('ProcessBuilder.redirectInput(File) does NOT emit command_injection', async () => {
    const code = `
import java.io.File;
import javax.servlet.http.HttpServletRequest;
public class A {
  public void doGet(HttpServletRequest req) throws Exception {
    String path = req.getParameter("p");
    File in = new File(path);
    ProcessBuilder pb = new ProcessBuilder("ls");
    pb.redirectInput(in);
  }
}
`;
    const ir = await analyze(code, 'RedirectInput.java', 'java');
    const flows = flowsByType(ir, 'command_injection');
    for (const f of flows) {
      expect((f.sink as { method?: string } | undefined)?.method ?? '').not.toBe('redirectInput');
    }
  });
});

describe('Issue #124 — recall locks (real command-exec sinks still fire)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('Runtime.exec with tainted arg still emits command_injection', async () => {
    const code = `
import javax.servlet.http.HttpServletRequest;
public class A {
  public void doGet(HttpServletRequest req) throws Exception {
    String cmd = req.getParameter("cmd");
    Runtime.getRuntime().exec(cmd);
  }
}
`;
    const ir = await analyze(code, 'RuntimeExec.java', 'java');
    expect(flowsByType(ir, 'command_injection').length).toBeGreaterThan(0);
  });

  it('ProcessBuilder constructor with tainted arg still emits command_injection', async () => {
    const code = `
import javax.servlet.http.HttpServletRequest;
public class A {
  public void doGet(HttpServletRequest req) throws Exception {
    String cmd = req.getParameter("cmd");
    new ProcessBuilder(cmd).start();
  }
}
`;
    const ir = await analyze(code, 'PbCtor.java', 'java');
    expect(flowsByType(ir, 'command_injection').length).toBeGreaterThan(0);
  });
});
