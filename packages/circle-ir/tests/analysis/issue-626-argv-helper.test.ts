/**
 * cognium-dev#626 — shell argv built by a helper method (`shellArgv` / `ArgvHelper.shellArgv`)
 * passed to `setArgv` before `new ProcessBuilder(argv)`.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject, analyze } from '../../src/analyzer.js';

describe('#626 argv helper indirection', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('same-file static helper return at setter reports command_injection', async () => {
    const code = `import java.io.IOException;
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
        new ProcessBuilder(argv).start(); // SINK
    }

    private static List<String> shellArgv(String step) {
        return Arrays.asList("/bin/sh", "-c", "make " + step);
    }

    @Override
    protected void doGet(HttpServletRequest request) throws IOException {
        String step = request.getParameter("step");
        setArgv(shellArgv(step));
        runShell();
    }
}
`;
    const sinkLine = code.split('\n').findIndex(l => l.includes('SINK')) + 1;
    const r = await analyze(code, 'ShellHostServlet.java', 'java');
    const flows = (r.taint?.flows ?? []).filter(f => f.sink_type === 'command_injection');
    expect(flows.some(f => f.sink_line === sinkLine)).toBe(true);
  });

  it('cross-file helper at setter reports command_injection', async () => {
    const helper = `import java.util.Arrays;
import java.util.List;

public class ArgvHelper {
    public static List<String> shellArgv(String step) {
        return Arrays.asList("/bin/sh", "-c", "make " + step);
    }
}
`;
    const host = `import java.io.IOException;
import java.util.List;

public class ShellHost {
    private List<String> argv;

    public void setArgv(List<String> argv) {
        this.argv = argv;
    }

    public void runShell() throws IOException {
        new ProcessBuilder(argv).start(); // SINK
    }
}
`;
    const caller = `import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;

public class CallerServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request) throws IOException {
        String step = request.getParameter("step");
        ShellHost host = new ShellHost();
        host.setArgv(ArgvHelper.shellArgv(step));
        host.runShell();
    }
}
`;
    const pa = await analyzeProject(
      [
        { filePath: 'ArgvHelper.java', code: helper, language: 'java' },
        { filePath: 'ShellHost.java', code: host, language: 'java' },
        { filePath: 'CallerServlet.java', code: caller, language: 'java' },
      ],
      {},
    );
    const sinkLine = host.split('\n').findIndex(l => l.includes('SINK')) + 1;
    const flows =
      pa.files.find(f => f.file === 'ShellHost.java')?.analysis.taint?.flows ?? [];
    expect(
      flows.some(f => f.sink_type === 'command_injection' && f.sink_line === sinkLine),
    ).toBe(true);
  });

  it('non-shell helper return stays clean at the wrapper sink', async () => {
    const code = `import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;

public class SafeHostServlet extends HttpServlet {
    private List<String> argv;

    public void setArgv(List<String> argv) {
        this.argv = argv;
    }

    public void runShell() throws IOException {
        new ProcessBuilder(argv).start(); // SINK
    }

    private static List<String> gitArgv(String step) {
        return Arrays.asList("git", "log", step);
    }

    @Override
    protected void doGet(HttpServletRequest request) throws IOException {
        String step = request.getParameter("step");
        setArgv(gitArgv(step));
        runShell();
    }
}
`;
    const sinkLine = code.split('\n').findIndex(l => l.includes('SINK')) + 1;
    const r = await analyze(code, 'SafeHostServlet.java', 'java');
    const flows = (r.taint?.flows ?? []).filter(
      f => f.sink_type === 'command_injection' && f.sink_line === sinkLine,
    );
    expect(flows).toHaveLength(0);
  });
});
