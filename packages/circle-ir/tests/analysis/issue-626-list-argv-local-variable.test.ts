/**
 * cognium-dev#626 — shell argv stored in a local `List<String>` before the
 * wrapper call must keep the ProcessBuilder sink (same-file local resolution).
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const servletHead = `import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
`;

const taskLauncher = `${servletHead}
public class TaskLauncherServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String job = request.getParameter("job");
        List<String> argv = Arrays.asList("/bin/sh", "-c", "run " + job);
        spawn(argv);
    }

    private Process spawn(List<String> cmd) throws IOException {
        return new ProcessBuilder(cmd).start();
    }
}
`;

const taskLauncherSafe = `${servletHead}
public class TaskLauncherSafe extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String job = request.getParameter("job");
        List<String> argv = Arrays.asList("git", "log", job);
        spawn(argv);
    }

    private Process spawn(List<String> cmd) throws IOException {
        return new ProcessBuilder(cmd).start();
    }
}
`;

async function cmdiAt(code: string, file: string, line: number): Promise<boolean> {
  const r = await analyze(code, file, 'java');
  return (r.taint.flows ?? []).some((f) => f.sink_type === 'command_injection' && f.sink_line === line);
}

describe('#626 List argv local variable before wrapper call', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('reports command_injection at the wrapper when argv is stored locally', async () => {
    const wrapperLine = taskLauncher.split('\n').findIndex((l) => l.includes('new ProcessBuilder(cmd)')) + 1;
    expect(await cmdiAt(taskLauncher, 'TaskLauncherServlet.java', wrapperLine)).toBe(true);
  });

  it('stays clean when the local list is a non-shell argv', async () => {
    const wrapperLine = taskLauncherSafe.split('\n').findIndex((l) => l.includes('new ProcessBuilder(cmd)')) + 1;
    expect(await cmdiAt(taskLauncherSafe, 'TaskLauncherSafe.java', wrapperLine)).toBe(false);
  });
});
