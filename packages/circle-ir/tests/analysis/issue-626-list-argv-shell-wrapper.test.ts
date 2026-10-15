/**
 * cognium-dev#626 (minimal slice) — a same-file wrapper `launchCommand(List<String>
 * argv)` that runs `new ProcessBuilder(argv).start()` is command injection when a
 * caller hands it a SHELL argv (`/bin/sh -c <script>`), and stays argv-form (clean,
 * #179) when every caller passes a program argv.
 *
 * SAST regression fixtures — the servlets are deliberately vulnerable.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const head = `import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class BuildRunnerServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String step = request.getParameter("step");
`;
const wrapper = `    }

    private Process launchCommand(List<String> argv) throws IOException {
        return new ProcessBuilder(argv).start();
    }
}
`;

const full = head +
`        launchCommand(Arrays.asList("/bin/sh", "-c", "make " + step));
        launchCommand(Arrays.asList("git", "log", step));
        new ProcessBuilder(Arrays.asList("/bin/sh", "-c", "make " + step)).start();
` + wrapper;

const safeOnly = head +
`        launchCommand(Arrays.asList("git", "log", step));
` + wrapper;

async function cmdiSinkLines(code: string): Promise<number[]> {
  const r = await analyze(code, 'BuildRunnerServlet.java', 'java');
  return [...new Set((r.taint.flows ?? []).filter((f) => f.sink_type === 'command_injection').map((f) => f.sink_line))].sort((a, b) => a - b);
}

describe('#626: List<String> argv wrapper called with a shell argv', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('reports the wrapper line (18) and the inline shell argv (14) while a shell-argv call exists', async () => {
    expect(await cmdiSinkLines(full)).toEqual([14, 18]);
  });

  it('with only a non-shell `git log` caller the wrapper stays clean (#179 precision intact)', async () => {
    expect(await cmdiSinkLines(safeOnly)).toEqual([]);
  });

  it('is not keyed on names: renamed wrapper, parameter and shell (bash) still fire', async () => {
    const code = full.replace(/launchCommand/g, 'spawnJob').replace(/\bargv\b/g, 'tokens').replace('"/bin/sh"', '"bash"');
    expect(await cmdiSinkLines(code)).toContain(18);
  });

  it('the inline non-shell argv ProcessBuilder stays clean', async () => {
    const code = head + `        new ProcessBuilder(Arrays.asList("git", "log", step)).start();\n` + wrapper;
    expect(await cmdiSinkLines(code)).toEqual([]);
  });

  const otherClass = `
class Helper {
    Process launchCommand(List<String> argv) throws IOException {
        return null;
    }
}
`;

  it('a same-named call on a different receiver does not keep the wrapper sink', async () => {
    const code = head +
`        Helper helper = new Helper();
        helper.launchCommand(Arrays.asList("/bin/sh", "-c", "make " + step));
        launchCommand(Arrays.asList("git", "log", step));
` + wrapper + otherClass;
    expect(await cmdiSinkLines(code)).toEqual([]);
  });

  it('a shell argv passed to a different overload (other arity) does not keep the wrapper sink', async () => {
    const code = head +
`        launchCommand(Arrays.asList("/bin/sh", "-c", "make " + step), true);
        launchCommand(Arrays.asList("git", "log", step));
    }

    private void launchCommand(List<String> argv, boolean quiet) {
        System.out.println(argv + " " + quiet);
    }

    private Process launchCommand(List<String> argv) throws IOException {
        return new ProcessBuilder(argv).start();
    }
}
`;
    expect(await cmdiSinkLines(code)).toEqual([]);
  });

  it('a this-qualified call with a shell argv keeps the wrapper sink', async () => {
    const code = head +
`        this.launchCommand(Arrays.asList("/bin/sh", "-c", "make " + step));
` + wrapper;
    expect(await cmdiSinkLines(code)).toEqual([16]);
  });

  it('a shell-argv caller in another class of the file does not keep this class\'s wrapper sink', async () => {
    const code = head +
`        launchCommand(Arrays.asList("git", "log", step));
` + wrapper + `
class Other {
    void run(String step) throws IOException {
        launchCommand(Arrays.asList("/bin/sh", "-c", "make " + step));
    }
    private void launchCommand(List<String> argv) {}
}
`;
    expect(await cmdiSinkLines(code)).toEqual([]);
  });
});
