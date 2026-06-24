/**
 * Tests for cognium-dev #179 Sink 1 — Java `command_injection`
 * (CWE-78) Stage 11 FP suppression on argv-form ProcessBuilder.
 *
 * Sprint 44 adds Stage 11 to `sink-filter-pass.ts`, scoped to
 * `language === 'java'` AND `sink.type === 'command_injection'` AND
 * `sink.method === 'ProcessBuilder'` AND `sink.class === 'constructor'`.
 *
 * Reality: `ProcessBuilder(List<String>)` and `ProcessBuilder(String...)`
 * overloads pass argv directly to fork(2). Each argv slot is a literal
 * argument — no shell, no metacharacter expansion. Suppress these shapes.
 *
 * Recall lock: real `new ProcessBuilder(userCmd)` (single bare variable)
 * and `Runtime.getRuntime().exec(userInput)` continue to fire.
 * Defense-in-depth: a file with BOTH argv-form ProcessBuilder AND
 * `Runtime.exec(userInput)` keeps the Runtime sink.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const countCmdSinks = (
  sinks: Array<{ type?: string }> | undefined,
) => (sinks ?? []).filter((s) => s.type === 'command_injection').length;

describe('cognium-dev #179 Sink 1 — Java ProcessBuilder argv-form Stage 11 FP suppression', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // -------------------------------------------------------------------------
  // FP #179 Sink 1 — argv-form shapes that must NOT fire
  // -------------------------------------------------------------------------

  it('FP #179 — new ProcessBuilder(Arrays.asList(...)): no command_injection sink', async () => {
    const code = `import java.util.Arrays;

public class GitWrapper {
  public Process show(String ref) throws Exception {
    return new ProcessBuilder(Arrays.asList("git", "log", "--oneline", ref)).start();
  }
}
`;
    const r = await analyze(code, 'GitWrapper.java', 'java');
    expect(countCmdSinks(r.taint?.sinks)).toBe(0);
  });

  it('FP #179 — new ProcessBuilder(List.of(...)): no command_injection sink', async () => {
    const code = `import java.util.List;

public class GitWrapper {
  public Process show(String ref) throws Exception {
    return new ProcessBuilder(List.of("git", "log", ref)).start();
  }
}
`;
    const r = await analyze(code, 'GitWrapper.java', 'java');
    expect(countCmdSinks(r.taint?.sinks)).toBe(0);
  });

  it('FP #179 — new ProcessBuilder("git", "log", ref) varargs ≥2: no command_injection sink', async () => {
    const code = `public class GitWrapper {
  public Process show(String ref) throws Exception {
    return new ProcessBuilder("git", "log", ref).start();
  }
}
`;
    const r = await analyze(code, 'GitWrapper.java', 'java');
    expect(countCmdSinks(r.taint?.sinks)).toBe(0);
  });

  it('FP #179 — new ProcessBuilder(new String[]{...}) array literal: no command_injection sink', async () => {
    const code = `public class GitWrapper {
  public Process show(String ref) throws Exception {
    return new ProcessBuilder(new String[]{ "git", "log", ref }).start();
  }
}
`;
    const r = await analyze(code, 'GitWrapper.java', 'java');
    expect(countCmdSinks(r.taint?.sinks)).toBe(0);
  });

  it('FP #179 — new ProcessBuilder(Collections.singletonList(...)): no command_injection sink', async () => {
    const code = `import java.util.Collections;

public class CmdWrapper {
  public Process run(String cmd) throws Exception {
    return new ProcessBuilder(Collections.singletonList(cmd)).start();
  }
}
`;
    const r = await analyze(code, 'CmdWrapper.java', 'java');
    expect(countCmdSinks(r.taint?.sinks)).toBe(0);
  });

  // -------------------------------------------------------------------------
  // Recall locks — real OS-exec shapes that must continue to fire
  // -------------------------------------------------------------------------

  it('Recall — new ProcessBuilder(userCmd) single bare variable: command_injection sink fires', async () => {
    const code = `public class Shell {
  public Process run(String userCmd) throws Exception {
    return new ProcessBuilder(userCmd).start();
  }
}
`;
    const r = await analyze(code, 'Shell.java', 'java');
    expect(countCmdSinks(r.taint?.sinks)).toBeGreaterThanOrEqual(1);
  });

  it('Recall — Runtime.getRuntime().exec(userCmd): command_injection sink fires', async () => {
    const code = `public class Shell {
  public Process run(String userCmd) throws Exception {
    return Runtime.getRuntime().exec(userCmd);
  }
}
`;
    const r = await analyze(code, 'Shell.java', 'java');
    expect(countCmdSinks(r.taint?.sinks)).toBeGreaterThanOrEqual(1);
  });

  // -------------------------------------------------------------------------
  // Defense-in-depth — argv-form AND Runtime.exec in same file
  // -------------------------------------------------------------------------

  it('Defense-in-depth — argv-form PB AND Runtime.exec(userCmd) in same file: Runtime sink still fires', async () => {
    const code = `import java.util.Arrays;

public class Mixed {
  public Process safe(String ref) throws Exception {
    return new ProcessBuilder(Arrays.asList("git", "log", ref)).start();
  }
  public Process unsafe(String userCmd) throws Exception {
    return Runtime.getRuntime().exec(userCmd);
  }
}
`;
    const r = await analyze(code, 'Mixed.java', 'java');
    expect(countCmdSinks(r.taint?.sinks)).toBeGreaterThanOrEqual(1);
  });
});
