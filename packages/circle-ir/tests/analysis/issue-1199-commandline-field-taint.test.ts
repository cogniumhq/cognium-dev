/**
 * cognium-dev#1199 — field-carried command argv via constructor + addArgument mutators.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';

const taskLine = `import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class TaskLine {
    private String executable;
    private final List<String> arguments = new ArrayList<>();

    public TaskLine(String executable) {
        this.executable = executable;
    }

    public void addArgument(String argument) {
        this.arguments.add(argument);
    }

    public Process execute() throws IOException {
        List<String> argv = new ArrayList<>();
        argv.add(executable);
        argv.addAll(arguments);
        return new ProcessBuilder(argv).start(); // SINK_LINE
    }
}
`;

const taskServlet = `import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;

public class TaskServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request) throws IOException {
        String job = request.getParameter("job");
        TaskLine line = new TaskLine("/bin/sh");
        line.addArgument("-c");
        line.addArgument("run " + job);
        line.execute();
    }
}
`;

const taskServletSafe = `import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;

public class TaskServletSafe extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request) throws IOException {
        String job = request.getParameter("job");
        TaskLine line = new TaskLine("git");
        line.addArgument("log");
        line.addArgument(job);
        line.execute();
    }
}
`;

describe('#1199 Commandline field-carried argv', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('cross-file shell argv reports command_injection at execute sink', async () => {
    const pa = await analyzeProject(
      [
        { filePath: 'TaskLine.java', code: taskLine, language: 'java' },
        { filePath: 'TaskServlet.java', code: taskServlet, language: 'java' },
      ],
      {},
    );
    const sinkLine = taskLine.split('\n').findIndex(l => l.includes('SINK_LINE')) + 1;
    const flows =
      pa.files.find(f => f.file === 'TaskLine.java')?.analysis.taint?.flows ?? [];
    expect(
      flows.some(f => f.sink_type === 'command_injection' && f.sink_line === sinkLine),
    ).toBe(true);
  });

  it('non-shell argv shape stays clean at execute sink', async () => {
    const pa = await analyzeProject(
      [
        { filePath: 'TaskLine.java', code: taskLine, language: 'java' },
        { filePath: 'TaskServletSafe.java', code: taskServletSafe, language: 'java' },
      ],
      {},
    );
    const sinkLine = taskLine.split('\n').findIndex(l => l.includes('SINK_LINE')) + 1;
    const flows =
      pa.files.find(f => f.file === 'TaskLine.java')?.analysis.taint?.flows ?? [];
    expect(
      flows.some(f => f.sink_type === 'command_injection' && f.sink_line === sinkLine),
    ).toBe(false);
  });
});
