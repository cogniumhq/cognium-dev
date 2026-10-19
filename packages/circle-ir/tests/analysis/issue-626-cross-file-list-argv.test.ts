/**
 * cognium-dev#626 — cross-file `List<String>` argv wrapper: shell argv built in the
 * caller file must keep the ProcessBuilder sink in the callee.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';

const servletHead = `import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
`;

const callerShell = `${servletHead}
public class JobServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String job = request.getParameter("job");
        List<String> argv = Arrays.asList("/bin/sh", "-c", "run " + job);
        ShellRunner.launch(argv);
    }
}
`;

const callerSafe = `${servletHead}
public class JobServletSafe extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String job = request.getParameter("job");
        List<String> argv = Arrays.asList("git", "log", job);
        ShellRunner.launch(argv);
    }
}
`;

const runner = `import java.io.IOException;
import java.util.List;

public class ShellRunner {
    public static Process launch(List<String> cmd) throws IOException {
        return new ProcessBuilder(cmd).start();
    }
}
`;

describe('#626 cross-file List argv wrapper', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const wrapperLine = runner.split('\n').findIndex(l => l.includes('new ProcessBuilder(cmd)')) + 1;

  it('reports command_injection at the callee when the caller passes a shell argv local', async () => {
    const pa = await analyzeProject([
      { filePath: 'JobServlet.java', code: callerShell, language: 'java' },
      { filePath: 'ShellRunner.java', code: runner, language: 'java' },
    ]);
    const runnerFile = pa.files.find(f => f.file === 'ShellRunner.java');
    const flows = runnerFile?.analysis.taint.flows ?? [];
    expect(flows.some(f => f.sink_type === 'command_injection' && f.sink_line === wrapperLine)).toBe(true);
    expect(pa.taint_paths?.some(p => p.sink.file === 'ShellRunner.java')).toBe(true);
  });

  it('stays clean when the cross-file caller passes a non-shell argv local', async () => {
    const pa = await analyzeProject([
      { filePath: 'JobServletSafe.java', code: callerSafe, language: 'java' },
      { filePath: 'ShellRunner.java', code: runner, language: 'java' },
    ]);
    const runnerFile = pa.files.find(f => f.file === 'ShellRunner.java');
    const flows = runnerFile?.analysis.taint.flows ?? [];
    expect(flows.filter(f => f.sink_type === 'command_injection')).toHaveLength(0);
  });
});
