/**
 * cognium-dev#596 / #597 (minimal slice) — a local tainted inside a nested
 * conditional lost its flow when the sink argument was `<const-local> + <tainted-local>`.
 *
 * SAST regression fixture — the handlers are deliberately vulnerable.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const servlet = (sinkCall: string, init = '""', assign = 'picked[0]', name = 'HostProbeServlet') => `
import java.io.IOException;
import java.util.Map;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ${name} extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Map<String, String[]> fields = request.getParameterMap();
        String target = ${init};
        if (!fields.isEmpty()) {
            String[] picked = fields.get("hostArg");
            if (picked != null) target = ${assign};
        }
        String launcher = "";
        String[] envVars = {"LANG=C"};
        ${sinkCall}
    }
}
`;

const archive = (init: string, assign: string, name: string) => `
import java.io.IOException;
import java.util.Enumeration;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.codec.binary.Base64;

public class ${name} extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String chosen = ${init};
        Enumeration<String> keys = request.getParameterNames();
        while (keys.hasMoreElements()) {
            String key = keys.nextElement();
            String[] vals = request.getParameterValues(key);
            if (vals != null) {
                if (vals[0].equals("pickMe")) chosen = ${assign};
            }
        }
        String archive = new String(Base64.decodeBase64(Base64.encodeBase64(chosen.getBytes())));
        String tool = "";
        Runtime.getRuntime().exec(tool + archive);
    }
}
`;

async function cmdi(code: string, file: string) {
  const r = await analyze(code, file, 'java');
  return (r.taint.flows ?? []).filter((f) => f.sink_type === 'command_injection');
}

describe('cognium-dev#596/#597 — nested-branch taint through <const> + <tainted> concat', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  for (const call of [
    'Runtime.getRuntime().exec(launcher + target, envVars);',
    'Runtime.getRuntime().exec(launcher + target);',
    'Runtime.getRuntime().exec(launcher + target, envVars, null);',
    'Runtime.getRuntime().exec(target, envVars);',
    'Runtime.getRuntime().exec("" + target, envVars);',
  ]) {
    it(`fires on ${call}`, async () => {
      expect((await cmdi(servlet(call), 'HostProbeServlet.java')).length).toBeGreaterThanOrEqual(1);
    });
  }

  it('safe: constants in both branches stay clean', async () => {
    const code = servlet('Runtime.getRuntime().exec(launcher + target, envVars);', '"localhost"', '"127.0.0.1"', 'HostProbeSafe');
    expect(await cmdi(code, 'HostProbeSafe.java')).toHaveLength(0);
  });

  it('#597: parameter-name source through Base64 round-trip fires', async () => {
    expect((await cmdi(archive('""', 'key', 'ArchiveListServlet'), 'ArchiveListServlet.java')).length).toBeGreaterThanOrEqual(1);
  });

  it('#597 safe: constant assignments stay clean', async () => {
    expect(await cmdi(archive('"default.tar"', '"backup.tar"', 'ArchiveListSafe'), 'ArchiveListSafe.java')).toHaveLength(0);
  });
});

describe('cognium-dev#596 — a straight-line reassignment after the block still kills taint', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('target reassigned to a constant after the nested block stays clean', async () => {
    const code = servlet('target = "localhost";\n        Runtime.getRuntime().exec(launcher + target, envVars);', '""', 'picked[0]', 'HostProbeReset');
    expect(await cmdi(code, 'HostProbeReset.java')).toHaveLength(0);
  });
});

const withBlocks = (blocks: string, name: string) => `
import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ${name} extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String target = "";
        ${blocks}
        Runtime.getRuntime().exec(target);
    }
}
`;

describe('cognium-dev#596 — a block that always runs replaces the carried defs', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const nestedTaint = `if (request.getParameter("a") != null) {
            if (request.getParameter("b") != null) target = request.getParameter("host");
        }`;

  it('a bare block that reassigns a constant after the nested branch stays clean', async () => {
    const code = withBlocks(`${nestedTaint}
        { target = "localhost"; }`, 'BareBlockReset');
    expect(await cmdi(code, 'BareBlockReset.java')).toHaveLength(0);
  });

  it('a synchronized block that reassigns a constant after the nested branch stays clean', async () => {
    const code = withBlocks(`${nestedTaint}
        synchronized (this) { target = "localhost"; }`, 'SyncBlockReset');
    expect(await cmdi(code, 'SyncBlockReset.java')).toHaveLength(0);
  });

  it('a bare block that assigns the tainted value still fires', async () => {
    const code = withBlocks('{ target = request.getParameter("host"); }', 'BareBlockTaint');
    expect((await cmdi(code, 'BareBlockTaint.java')).length).toBeGreaterThanOrEqual(1);
  });

  it('a conditional assignment inside a bare block still fires', async () => {
    const code = withBlocks('{ if (request.getParameter("a") != null) target = request.getParameter("host"); }', 'BareBlockBranch');
    expect((await cmdi(code, 'BareBlockBranch.java')).length).toBeGreaterThanOrEqual(1);
  });

  it('a bare block nested in an if body does not kill an earlier tainted branch def', async () => {
    const code = withBlocks(`if (request.getParameter("a") != null) { target = request.getParameter("host"); }
        if (request.getParameter("b") != null) { { target = "localhost"; } }`, 'BareBlockInBranch');
    expect((await cmdi(code, 'BareBlockInBranch.java')).length).toBeGreaterThanOrEqual(1);
  });

  it('an if body that reassigns a constant does not kill the nested tainted def', async () => {
    const code = withBlocks(`${nestedTaint}
        if (request.getParameter("c") != null) { target = "localhost"; }`, 'IfBlockNoKill');
    expect((await cmdi(code, 'IfBlockNoKill.java')).length).toBeGreaterThanOrEqual(1);
  });

  it('DFG: after a bare block that always assigns, only that def reaches the sink use', async () => {
    const code = withBlocks(`${nestedTaint}
        { target = "localhost"; }`, 'BareBlockDfg');
    const r = await analyze(code, 'BareBlockDfg.java', 'java');
    const defs = (r.dfg?.defs ?? []).filter((d) => d.variable === 'target');
    const sinkLine = code.split('\n').findIndex((l) => l.includes('exec(target)')) + 1;
    const reaching = (r.dfg?.uses ?? []).filter((u) => u.variable === 'target' && u.line === sinkLine).map((u) => u.def_id);
    const bareDef = defs[defs.length - 1];
    expect(reaching).toEqual([bareDef.id]);
  });

  it('DFG: after an if body that assigns, the earlier defs still reach the sink use', async () => {
    const code = withBlocks(`${nestedTaint}
        if (request.getParameter("c") != null) { target = "localhost"; }`, 'IfBlockDfg');
    const r = await analyze(code, 'IfBlockDfg.java', 'java');
    const defs = (r.dfg?.defs ?? []).filter((d) => d.variable === 'target');
    const sinkLine = code.split('\n').findIndex((l) => l.includes('exec(target)')) + 1;
    const reaching = new Set((r.dfg?.uses ?? []).filter((u) => u.variable === 'target' && u.line === sinkLine).map((u) => u.def_id));
    expect(reaching.size).toBe(defs.length);
  });
});
