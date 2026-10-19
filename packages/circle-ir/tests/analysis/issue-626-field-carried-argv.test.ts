/**
 * cognium-dev#626 — field-carried `List<String>` argv: shell argv stored on an instance
 * field via a bean setter, then consumed at `new ProcessBuilder(argv)` in another method.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';

const host = `import java.io.IOException;
import java.util.List;

public class ShellHost {
    private List<String> argv;

    public void setArgv(List<String> argv) {
        this.argv = argv;
    }

    public void runShell() throws IOException {
        new ProcessBuilder(argv).start(); // SINK_LINE
    }
}
`;

const caller = `import java.io.IOException;
import java.util.Arrays;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;

public class CallerServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request) throws IOException {
        String step = request.getParameter("step");
        ShellHost host = new ShellHost();
        host.setArgv(Arrays.asList("/bin/sh", "-c", "make " + step));
        host.runShell();
    }
}
`;

const sameFile = `import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;

public class ShellHostServlet extends HttpServlet {
    private List<String> argv;

    public void setArgv(List<String> argv) {
        this.argv = argv;
    }

    public void runShell() throws IOException {
        new ProcessBuilder(argv).start(); // SINK_LINE
    }

    @Override
    protected void doGet(HttpServletRequest request) throws IOException {
        String step = request.getParameter("step");
        setArgv(Arrays.asList("/bin/sh", "-c", "make " + step));
        runShell();
    }
}
`;

describe('#626 probe field-carried argv', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('same-file setter then sink method reports command_injection', async () => {
    const { initAnalyzer: init, analyze } = await import('../../src/analyzer.js');
    await init();
    const sinkLine = sameFile.split('\n').findIndex(l => l.includes('SINK_LINE')) + 1;
    const r = await analyze(sameFile, 'ShellHostServlet.java', 'java');
    const flows = (r.taint?.flows ?? []).filter(f => f.sink_type === 'command_injection');
    expect(flows.some(f => f.sink_line === sinkLine)).toBe(true);
  });

  it('reports command_injection at ProcessBuilder when argv is set via setter', async () => {
    const pa = await analyzeProject(
      [
        { filePath: 'ShellHost.java', code: host, language: 'java' },
        { filePath: 'CallerServlet.java', code: caller, language: 'java' },
      ],
      {},
    );

    const sinkLine = host.split('\n').findIndex(l => l.includes('SINK_LINE')) + 1;
    const flows =
      pa.files.find(f => f.file === 'ShellHost.java')?.analysis.taint?.flows ?? [];

    expect(
      flows.some(f => f.sink_type === 'command_injection' && f.sink_line === sinkLine),
    ).toBe(true);
  });
});
