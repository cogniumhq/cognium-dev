import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/index.js';

/**
 * cognium-dev #220 — Java shell-in-string interop FN.
 *
 * The canonical fixture concatenates a tainted parameter into a shell
 * command string, then invokes it via
 *   Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
 *
 * Before 3.144.3 this produced zero `command_injection` flows:
 *   1. The `interprocedural_param` source for `arg` had no `variable`
 *      field, so the variable-scan flow generator had no seed for the
 *      Java branch and never learned that `cmd` is a derived alias
 *      of the tainted parameter.
 *   2. `findJavaArgvFormExecSanitizers` (Sprint 77a Pattern X, #216)
 *      registered a `java_argv_form_exec` sanitizer for ALL
 *      `exec(String[])` calls, including shell-in-string invocations,
 *      so the Sprint 24 line-keyed sanitizer suppression dropped the
 *      flow even when the source-derived alias was correctly detected.
 *
 * The fix has three parts:
 *   1. Expose `variable: param.name` on `interprocedural_param` sources
 *      **for Java only** in taint-matcher.ts so the flow scan seeds the
 *      Java branch. (Cross-language exposure regressed the Python/Rust
 *      alias-expansion anchor logic.)
 *   2. New `buildJavaTaintedVars` in language-sources-pass.ts iterates
 *      Java declarations and assignments to fixpoint, mirroring
 *      `buildPythonTaintedVars`/`buildRustTaintedVars`.
 *   3. `findJavaArgvFormExecSanitizers` now excludes shell-in-string
 *      shapes (`{"/bin/sh", "-c", ...}`, `{"cmd.exe", "/c", ...}`, etc)
 *      — those DO execute shell code and are NOT sanitized by argv
 *      splitting.
 */
describe('cognium-dev #220 — Java shell-in-string interop', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('canonical fixture — method-param + concat + sh -c array exec fires command_injection', async () => {
    const code = `
package com.demo.interop;

public class InteropShellInString {
    public void run(String arg) throws Exception {
        String cmd = "echo " + arg;
        Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
    }
}
`;
    const ir = await analyze(code, 'InteropShellInString.java', 'java');
    const cmdFlows = (ir.taint.flows ?? []).filter(
      f => f.sink_type === 'command_injection',
    );
    expect(cmdFlows.length).toBeGreaterThan(0);
  });

  it('HTTP source + concat + sh -c array exec fires command_injection', async () => {
    const code = `
package com.demo;
import javax.servlet.http.*;
public class X extends HttpServlet {
    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String arg = req.getParameter("cmd");
        String cmd = "echo " + arg;
        Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
    }
}
`;
    const ir = await analyze(code, 'X.java', 'java');
    const cmdFlows = (ir.taint.flows ?? []).filter(
      f => f.sink_type === 'command_injection',
    );
    expect(cmdFlows.length).toBeGreaterThan(0);
  });

  it('inline concat (no intermediate variable) still fires command_injection', async () => {
    const code = `
package com.demo;
public class X {
    public void run(String arg) throws Exception {
        Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", "echo " + arg});
    }
}
`;
    const ir = await analyze(code, 'X.java', 'java');
    const cmdFlows = (ir.taint.flows ?? []).filter(
      f => f.sink_type === 'command_injection',
    );
    expect(cmdFlows.length).toBeGreaterThan(0);
  });

  it('safe mirror — literal-only shell invocation emits no flow', async () => {
    const code = `
package com.demo;
public class X {
    public void run() throws Exception {
        Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", "echo hello"});
    }
}
`;
    const ir = await analyze(code, 'X.java', 'java');
    const cmdFlows = (ir.taint.flows ?? []).filter(
      f => f.sink_type === 'command_injection',
    );
    expect(cmdFlows.length).toBe(0);
  });

  it('recall guard — non-shell argv exec of tainted program is still sanitized', async () => {
    // exec(new String[]{"ls", "-la", arg}) — first arg is a plain
    // binary (not a shell), so argv splitting DOES sanitize the trailing
    // tainted element. The shell-in-string exclusion must not overreach.
    const code = `
package com.demo;
import javax.servlet.http.*;
public class X extends HttpServlet {
    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String arg = req.getParameter("dir");
        Runtime.getRuntime().exec(new String[]{"ls", "-la", arg});
    }
}
`;
    const ir = await analyze(code, 'X.java', 'java');
    const cmdFlows = (ir.taint.flows ?? []).filter(
      f => f.sink_type === 'command_injection',
    );
    expect(cmdFlows.length).toBe(0);
  });

  it('recall guard — single-string exec(String) form continues to fire', async () => {
    const code = `
package com.demo;
import javax.servlet.http.*;
public class X extends HttpServlet {
    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String arg = req.getParameter("cmd");
        Runtime.getRuntime().exec("echo " + arg);
    }
}
`;
    const ir = await analyze(code, 'X.java', 'java');
    const cmdFlows = (ir.taint.flows ?? []).filter(
      f => f.sink_type === 'command_injection',
    );
    expect(cmdFlows.length).toBeGreaterThan(0);
  });

  it('recall guard — ProcessBuilder(tainted) continues to fire', async () => {
    const code = `
package com.demo;
import javax.servlet.http.*;
public class X extends HttpServlet {
    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        new ProcessBuilder(req.getParameter("cmd")).start();
    }
}
`;
    const ir = await analyze(code, 'X.java', 'java');
    const cmdFlows = (ir.taint.flows ?? []).filter(
      f => f.sink_type === 'command_injection',
    );
    expect(cmdFlows.length).toBeGreaterThan(0);
  });
});
