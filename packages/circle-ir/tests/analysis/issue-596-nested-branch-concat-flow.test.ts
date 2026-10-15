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

describe('cognium-dev#596 — a carried def is killed by a later assignment in the block it was carried into', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const innerTaint = `if (request.getParameter("b") != null) {
                target = request.getParameter("host");
            }`;

  it('a straight-line constant assignment after the inner braced if, in the same block, stays clean', async () => {
    const code = withBlocks(`if (request.getParameter("a") != null) {
            ${innerTaint}
            target = "localhost";
        }`, 'OuterBlockReset');
    expect(await cmdi(code, 'OuterBlockReset.java')).toHaveLength(0);
  });

  it('a bare block that assigns a constant after the inner braced if, in the same block, stays clean', async () => {
    const code = withBlocks(`if (request.getParameter("a") != null) {
            ${innerTaint}
            {
                target = "localhost";
            }
        }`, 'OuterBareBlockReset');
    expect(await cmdi(code, 'OuterBareBlockReset.java')).toHaveLength(0);
  });

  it('DFG: a one-line bare block after the inner braced if kills the carried def', async () => {
    const code = withBlocks(`if (request.getParameter("a") != null) {
            ${innerTaint}
            { target = "localhost"; }
        }`, 'OuterBareBlockDfg');
    const r = await analyze(code, 'OuterBareBlockDfg.java', 'java');
    const defs = (r.dfg?.defs ?? []).filter((d) => d.variable === 'target');
    const sinkLine = code.split('\n').findIndex((l) => l.includes('exec(target)')) + 1;
    const reaching = new Set((r.dfg?.uses ?? []).filter((u) => u.variable === 'target' && u.line === sinkLine).map((u) => u.def_id));
    expect(defs).toHaveLength(3);
    expect(reaching).toEqual(new Set([defs[0].id, defs[2].id]));
  });

  it('DFG: only the initialiser and the constant def reach the sink use', async () => {
    const code = withBlocks(`if (request.getParameter("a") != null) {
            ${innerTaint}
            target = "localhost";
        }`, 'OuterBlockDfg');
    const r = await analyze(code, 'OuterBlockDfg.java', 'java');
    const defs = (r.dfg?.defs ?? []).filter((d) => d.variable === 'target');
    const sinkLine = code.split('\n').findIndex((l) => l.includes('exec(target)')) + 1;
    const reaching = new Set((r.dfg?.uses ?? []).filter((u) => u.variable === 'target' && u.line === sinkLine).map((u) => u.def_id));
    expect(defs).toHaveLength(3);
    expect(reaching).toEqual(new Set([defs[0].id, defs[2].id]));
  });

  it('still fires: an inner braced if with no later assignment in the outer block', async () => {
    const code = withBlocks(`if (request.getParameter("a") != null) {
            ${innerTaint}
        }`, 'OuterBlockTaint');
    expect((await cmdi(code, 'OuterBlockTaint.java')).length).toBeGreaterThanOrEqual(1);
  });

  it('still fires: three levels of nesting', async () => {
    const code = withBlocks(`if (request.getParameter("a") != null) {
            if (request.getParameter("b") != null) {
                if (request.getParameter("c") != null) {
                    target = request.getParameter("host");
                }
            }
        }`, 'ThreeLevels');
    expect((await cmdi(code, 'ThreeLevels.java')).length).toBeGreaterThanOrEqual(1);
  });

  it('still fires: a second if with a braced inner if does not kill an earlier branch def', async () => {
    const code = withBlocks(`if (request.getParameter("a") != null) { target = request.getParameter("host"); }
        if (request.getParameter("b") != null) {
            if (request.getParameter("c") != null) { target = "localhost"; }
        }`, 'SecondIfBraced');
    expect((await cmdi(code, 'SecondIfBraced.java')).length).toBeGreaterThanOrEqual(1);
  });

  it('still fires: a tainted def inside a bare block in a switch case reaches a later sink', async () => {
    const code = withBlocks(`switch (request.getParameter("a")) {
            case "1": { target = request.getParameter("host"); break; }
            default: break;
        }`, 'SwitchBlock');
    expect((await cmdi(code, 'SwitchBlock.java')).length).toBeGreaterThanOrEqual(1);
  });

  it('still fires: a nested braced if inside a switch case reaches a later sink', async () => {
    const code = withBlocks(`switch (request.getParameter("a")) {
            case "1":
                if (request.getParameter("b") != null) { target = request.getParameter("host"); }
                break;
            default: break;
        }`, 'SwitchNested');
    expect((await cmdi(code, 'SwitchNested.java')).length).toBeGreaterThanOrEqual(1);
  });

  for (const [label, head] of [
    ['while', 'while (request.getParameter("a") != null)'],
    ['for', 'for (int i = 0; i < 3; i++)'],
    ['enhanced for', 'for (String k : request.getParameterValues("a"))'],
  ] as const) {
    it(`${label} body: a later constant assignment in the same body kills the nested branch def`, async () => {
      const code = withBlocks(`${head} {
            ${innerTaint}
            target = "localhost";
        }`, 'LoopReset');
      expect(await cmdi(code, 'LoopReset.java')).toHaveLength(0);
      const r = await analyze(code, 'LoopReset.java', 'java');
      const defs = (r.dfg?.defs ?? []).filter((d) => d.variable === 'target');
      const sinkLine = code.split('\n').findIndex((l) => l.includes('exec(target)')) + 1;
      const reaching = new Set((r.dfg?.uses ?? []).filter((u) => u.variable === 'target' && u.line === sinkLine).map((u) => u.def_id));
      expect(defs).toHaveLength(3);
      expect(reaching).toEqual(new Set([defs[0].id, defs[2].id]));
    });

    it(`${label} body: a nested branch def with no later assignment still reaches the sink`, async () => {
      const code = withBlocks(`${head} {
            ${innerTaint}
        }`, 'LoopTaint');
      expect((await cmdi(code, 'LoopTaint.java')).length).toBeGreaterThanOrEqual(1);
    });
  }

  describe('a braceless conditional inside an always-run block is not an unconditional assignment', () => {
    const initTainted = (blocks: string, name: string) => `
import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ${name} extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String fallback = "localhost";
        String target = request.getParameter("host");
        ${blocks}
        Runtime.getRuntime().exec(target);
    }
}
`;
    const reaching = async (code: string, file: string) => {
      const r = await analyze(code, file, 'java');
      const defs = (r.dfg?.defs ?? []).filter((d) => d.variable === 'target');
      const sinkLine = code.split('\n').findIndex((l) => l.includes('exec(target)')) + 1;
      const ids = new Set((r.dfg?.uses ?? []).filter((u) => u.variable === 'target' && u.line === sinkLine).map((u) => u.def_id));
      return { defs, ids };
    };

    it('bare block, braceless if: the earlier tainted def still reaches the sink and the finding fires', async () => {
      const code = initTainted(`{\n            if (request.getParameter("a") != null)\n                target = fallback;\n        }`, 'BracelessIf');
      const { defs, ids } = await reaching(code, 'BracelessIf.java');
      expect(defs).toHaveLength(2);
      expect(ids).toEqual(new Set([defs[0].id, defs[1].id]));
      expect((await cmdi(code, 'BracelessIf.java')).length).toBeGreaterThanOrEqual(1);
    });

    // The finding for a braceless loop body is decided elsewhere (constant
    // propagation vetoes it with or without the bare block), so only the DFG is asserted.
    for (const [label, head] of [
      ['while', 'while (request.getParameter("a") != null)'],
      ['for', 'for (int i = 0; i < 3; i++)'],
    ] as const) {
      it(`bare block, braceless ${label}: the earlier tainted def still reaches the sink use`, async () => {
        const code = initTainted(`{\n            ${head}\n                target = fallback;\n        }`, 'BracelessLoop');
        const { defs, ids } = await reaching(code, 'BracelessLoop.java');
        expect(defs).toHaveLength(2);
        expect(ids).toEqual(new Set([defs[0].id, defs[1].id]));
      });
    }

    it('synchronized block, braceless if: the earlier tainted def still reaches the sink and the finding fires', async () => {
      const code = initTainted(`synchronized (this) {\n            if (request.getParameter("a") != null)\n                target = fallback;\n        }`, 'SyncBracelessIf');
      const { defs, ids } = await reaching(code, 'SyncBracelessIf.java');
      expect(ids.has(defs[0].id)).toBe(true);
      expect((await cmdi(code, 'SyncBracelessIf.java')).length).toBeGreaterThanOrEqual(1);
    });

    const initSafe = (blocks: string, name: string) => initTainted(blocks, name).replace('String target = request.getParameter("host");', 'String target = "safe";');

    it('a braced arm followed by a braceless conditional keeps the braced arm def reaching the sink', async () => {
      const code = initSafe(`{\n            if (request.getParameter("a") != null) { target = request.getParameter("host"); }\n            if (request.getParameter("b") != null)\n                target = fallback;\n        }`, 'BracedThenBraceless');
      const { defs, ids } = await reaching(code, 'BracedThenBraceless.java');
      expect(defs).toHaveLength(3);
      expect(ids).toEqual(new Set(defs.map((d) => d.id)));
      expect((await cmdi(code, 'BracedThenBraceless.java')).length).toBeGreaterThanOrEqual(1);
    });

    it('braceless if / else that assign on both arms: both arm defs reach, the initialiser does not', async () => {
      const code = initSafe(`{\n            if (request.getParameter("a") != null)\n                target = request.getParameter("host");\n            else\n                target = fallback;\n        }`, 'BracelessIfElse');
      const { defs, ids } = await reaching(code, 'BracelessIfElse.java');
      expect(defs).toHaveLength(3);
      expect(ids).toEqual(new Set([defs[1].id, defs[2].id]));
      expect((await cmdi(code, 'BracelessIfElse.java')).length).toBeGreaterThanOrEqual(1);
    });

    it('if / else where the else block only assigns under a nested braceless if: the initialiser still reaches', async () => {
      const code = initTainted(`{\n            if (request.getParameter("a") != null)\n                target = "safe";\n            else {\n                if (request.getParameter("b") != null)\n                    target = "safe2";\n            }\n        }`, 'NestedElseBraceless');
      const { defs, ids } = await reaching(code, 'NestedElseBraceless.java');
      expect(defs).toHaveLength(3);
      expect(ids.has(defs[0].id)).toBe(true);
      expect((await cmdi(code, 'NestedElseBraceless.java')).length).toBeGreaterThanOrEqual(1);
    });

    it('if / else where the if block only assigns under a nested braceless if (straight-line else): the initialiser still reaches', async () => {
      const code = initTainted(`{\n            if (request.getParameter("a") != null) {\n                if (request.getParameter("b") != null)\n                    target = "safe";\n            } else\n                target = "safe2";\n        }`, 'NestedIfBraceless');
      const { defs, ids } = await reaching(code, 'NestedIfBraceless.java');
      expect(defs).toHaveLength(3);
      expect(ids.has(defs[0].id)).toBe(true);
      expect((await cmdi(code, 'NestedIfBraceless.java')).length).toBeGreaterThanOrEqual(1);
    });

    for (const [label, head] of [
      ['while', 'while (request.getParameter("b") != null)'],
      ['for', 'for (int i = 0; i < 3; i++)'],
    ] as const) {
      it(`if / else where the else block only assigns in a nested braceless ${label}: the initialiser still reaches`, async () => {
        const code = initTainted(`{\n            if (request.getParameter("a") != null)\n                target = "safe";\n            else {\n                ${head}\n                    target = "safe2";\n            }\n        }`, 'NestedElseLoop');
        const { defs, ids } = await reaching(code, 'NestedElseLoop.java');
        expect(defs).toHaveLength(3);
        expect(ids.has(defs[0].id)).toBe(true);
      });
    }

    it('if / else where both block arms assign directly still replaces the initialiser', async () => {
      const code = initTainted(`{\n            if (request.getParameter("a") != null) {\n                target = "safe";\n            } else {\n                target = "safe2";\n            }\n        }`, 'BracedBoth');
      const { defs, ids } = await reaching(code, 'BracedBoth.java');
      expect(defs).toHaveLength(3);
      expect(ids).toEqual(new Set([defs[1].id, defs[2].id]));
    });

    it('if / else where the else block assigns directly and then again under a nested braceless if: the direct write still replaces the initialiser', async () => {
      const code = initTainted(`{\n            if (request.getParameter("a") != null) {\n                target = "safe";\n            } else {\n                target = "safe2";\n                if (request.getParameter("b") != null)\n                    target = "safe3";\n            }\n        }`, 'DirectThenNested');
      const { defs, ids } = await reaching(code, 'DirectThenNested.java');
      expect(defs).toHaveLength(4);
      expect(ids).toEqual(new Set([defs[1].id, defs[2].id, defs[3].id]));
      expect(ids.has(defs[0].id)).toBe(false);
      // Only the DFG is asserted, as for `BracedBoth`: the finding for a name assigned on both arms is
      // decided by the name-based taint pass and fires on main with or without this change.
    });

    for (const [label, head] of [
      ['while', 'while (request.getParameter("b") != null)'],
      ['for', 'for (int i = 0; i < 3; i++)'],
    ] as const) {
      it(`if / else where the else block assigns directly and then again in a nested braceless ${label}: the direct write still replaces the initialiser`, async () => {
        const code = initTainted(`{\n            if (request.getParameter("a") != null) {\n                target = "safe";\n            } else {\n                target = "safe2";\n                ${head}\n                    target = "safe3";\n            }\n        }`, 'DirectThenNestedLoop');
        const { defs, ids } = await reaching(code, 'DirectThenNestedLoop.java');
        expect(defs).toHaveLength(4);
        expect(ids).toEqual(new Set([defs[1].id, defs[2].id, defs[3].id]));
        expect(ids.has(defs[0].id)).toBe(false);
      });
    }

    it('if / else where the else block writes the tainted value directly and then a constant under a nested braceless if: the tainted def still reaches', async () => {
      const code = initSafe(`{\n            if (request.getParameter("a") != null) {\n                target = "safe1";\n            } else {\n                target = request.getParameter("host");\n                if (request.getParameter("b") != null)\n                    target = fallback;\n            }\n        }`, 'DirectTaintThenNested');
      const { defs, ids } = await reaching(code, 'DirectTaintThenNested.java');
      expect(defs).toHaveLength(4);
      expect(ids).toEqual(new Set([defs[1].id, defs[2].id, defs[3].id]));
      expect((await cmdi(code, 'DirectTaintThenNested.java')).length).toBeGreaterThanOrEqual(1);
    });

    it('nested braceless if / else inside a braced else arm: the tainted write in the nested if still reaches', async () => {
      const code = initSafe(`{\n            if (request.getParameter("a") != null)\n                target = "safe1";\n            else {\n                if (request.getParameter("b") != null)\n                    target = request.getParameter("host");\n                else\n                    target = "safe2";\n            }\n        }`, 'NestedIfElseInElse');
      const { defs, ids } = await reaching(code, 'NestedIfElseInElse.java');
      expect(defs).toHaveLength(4);
      expect(ids).toEqual(new Set([defs[1].id, defs[2].id, defs[3].id]));
      expect((await cmdi(code, 'NestedIfElseInElse.java')).length).toBeGreaterThanOrEqual(1);
    });

    it('two braceless ifs inside a braced else arm: both writes and the initialiser reach', async () => {
      const code = initSafe(`{\n            if (request.getParameter("a") != null)\n                target = "safe1";\n            else {\n                if (request.getParameter("b") != null)\n                    target = request.getParameter("host");\n                if (request.getParameter("c") != null)\n                    target = fallback;\n            }\n        }`, 'TwoBracelessInElse');
      const { defs, ids } = await reaching(code, 'TwoBracelessInElse.java');
      expect(defs).toHaveLength(4);
      expect(ids).toEqual(new Set(defs.map((d) => d.id)));
      expect((await cmdi(code, 'TwoBracelessInElse.java')).length).toBeGreaterThanOrEqual(1);
    });

    it('two braceless ifs inside a braced if arm: the earlier tainted write is not replaced by the later one', async () => {
      const code = initSafe(`{\n            if (request.getParameter("a") != null) {\n                if (request.getParameter("b") != null)\n                    target = request.getParameter("host");\n                if (request.getParameter("c") != null)\n                    target = fallback;\n            } else\n                target = "safe2";\n        }`, 'TwoBracelessInIf');
      const { defs, ids } = await reaching(code, 'TwoBracelessInIf.java');
      expect(defs).toHaveLength(4);
      expect(ids).toEqual(new Set(defs.map((d) => d.id)));
      expect((await cmdi(code, 'TwoBracelessInIf.java')).length).toBeGreaterThanOrEqual(1);
    });

    it('two braceless ifs in one block: both arms and the initialiser reach', async () => {
      const code = initSafe(`{\n            if (request.getParameter("a") != null)\n                target = request.getParameter("host");\n            if (request.getParameter("b") != null)\n                target = fallback;\n        }`, 'TwoBraceless');
      const { defs, ids } = await reaching(code, 'TwoBraceless.java');
      expect(defs).toHaveLength(3);
      expect(ids).toEqual(new Set(defs.map((d) => d.id)));
      expect((await cmdi(code, 'TwoBraceless.java')).length).toBeGreaterThanOrEqual(1);
    });

    it('two straight-line assignments on one line: the later one replaces', async () => {
      const code = initTainted('{\n            target = request.getParameter("x"); target = fallback;\n        }', 'SameLine');
      const { defs, ids } = await reaching(code, 'SameLine.java');
      expect(defs).toHaveLength(3);
      expect(ids).toEqual(new Set([defs[2].id]));
    });

    it('a straight-line assignment in the bare block still replaces the tainted def', async () => {
      const code = initTainted('{\n            target = fallback;\n        }', 'BareStraight');
      const { defs, ids } = await reaching(code, 'BareStraight.java');
      expect(ids).toEqual(new Set([defs[1].id]));
    });

    it('a straight-line assignment before a braceless conditional keeps both as reaching defs', async () => {
      const code = initTainted('{\n            target = fallback;\n            if (request.getParameter("a") != null)\n                target = request.getParameter("host");\n        }', 'StraightThenCond');
      const { defs, ids } = await reaching(code, 'StraightThenCond.java');
      expect(defs).toHaveLength(3);
      expect(ids).toEqual(new Set([defs[1].id, defs[2].id]));
    });

    it('braceless else-if chain where every arm assigns a constant: the initialiser does not reach and nothing fires', async () => {
      const code = initTainted(`{\n            if (request.getParameter("a") != null)\n                target = "safe1";\n            else if (request.getParameter("b") != null)\n                target = "safe2";\n            else\n                target = "safe3";\n        }`, 'ElseIfChainAll');
      const { defs, ids } = await reaching(code, 'ElseIfChainAll.java');
      expect(defs).toHaveLength(4);
      expect(ids).toEqual(new Set([defs[1].id, defs[2].id, defs[3].id]));
      expect(ids.has(defs[0].id)).toBe(false);
      expect(await cmdi(code, 'ElseIfChainAll.java')).toHaveLength(0);
    });

    it('braceless if / else where both arms assign a constant: a source in the if condition does not taint the arm on the next line', async () => {
      const code = initTainted(`{\n            if (request.getParameter("a") != null)\n                target = "safe1";\n            else\n                target = "safe3";\n        }`, 'BracelessIfElseConst');
      const { defs, ids } = await reaching(code, 'BracelessIfElseConst.java');
      expect(ids).toEqual(new Set([defs[1].id, defs[2].id]));
      expect(await cmdi(code, 'BracelessIfElseConst.java')).toHaveLength(0);
    });

    it('braced else-if chain where every arm assigns a constant: the initialiser does not reach and nothing fires', async () => {
      const code = initTainted(`{\n            if (request.getParameter("a") != null) {\n                target = "safe1";\n            } else if (request.getParameter("b") != null) {\n                target = "safe2";\n            } else {\n                target = "safe3";\n            }\n        }`, 'BracedElseIfChainAll');
      const { defs, ids } = await reaching(code, 'BracedElseIfChainAll.java');
      expect(defs).toHaveLength(4);
      expect(ids).toEqual(new Set([defs[1].id, defs[2].id, defs[3].id]));
      expect(await cmdi(code, 'BracedElseIfChainAll.java')).toHaveLength(0);
    });

    it('longer braceless else-if chain where every arm assigns a constant: the initialiser does not reach', async () => {
      const code = initTainted(`{\n            if (request.getParameter("a") != null)\n                target = "safe1";\n            else if (request.getParameter("b") != null)\n                target = "safe2";\n            else if (request.getParameter("c") != null)\n                target = "safe3";\n            else\n                target = "safe4";\n        }`, 'LongElseIfChainAll');
      const { defs, ids } = await reaching(code, 'LongElseIfChainAll.java');
      expect(defs).toHaveLength(5);
      expect(ids).toEqual(new Set([defs[1].id, defs[2].id, defs[3].id, defs[4].id]));
      expect(await cmdi(code, 'LongElseIfChainAll.java')).toHaveLength(0);
    });

    it('else-if chain whose arms assign the tainted value: the tainted arm still reaches and fires', async () => {
      const code = initSafe(`{\n            if (request.getParameter("a") != null)\n                target = "safe1";\n            else if (request.getParameter("b") != null)\n                target = request.getParameter("host");\n            else\n                target = "safe3";\n        }`, 'ElseIfChainTaintedArm');
      const { defs, ids } = await reaching(code, 'ElseIfChainTaintedArm.java');
      expect(defs).toHaveLength(4);
      expect(ids).toEqual(new Set([defs[1].id, defs[2].id, defs[3].id]));
      expect((await cmdi(code, 'ElseIfChainTaintedArm.java')).length).toBeGreaterThanOrEqual(1);
    });

    it('else-if chain with no final else: the initialiser still reaches and the finding fires', async () => {
      const code = initTainted(`{\n            if (request.getParameter("a") != null)\n                target = "safe1";\n            else if (request.getParameter("b") != null)\n                target = "safe2";\n        }`, 'ElseIfChainNoElse');
      const { defs, ids } = await reaching(code, 'ElseIfChainNoElse.java');
      expect(defs).toHaveLength(3);
      expect(ids).toEqual(new Set([defs[0].id, defs[1].id, defs[2].id]));
      expect((await cmdi(code, 'ElseIfChainNoElse.java')).length).toBeGreaterThanOrEqual(1);
    });

    it('braced else-if chain with no final else: the initialiser still reaches and the finding fires', async () => {
      const code = initTainted(`{\n            if (request.getParameter("a") != null) {\n                target = "safe1";\n            } else if (request.getParameter("b") != null) {\n                target = "safe2";\n            }\n        }`, 'BracedElseIfChainNoElse');
      const { defs, ids } = await reaching(code, 'BracedElseIfChainNoElse.java');
      expect(defs).toHaveLength(3);
      expect(ids).toEqual(new Set([defs[0].id, defs[1].id, defs[2].id]));
      expect((await cmdi(code, 'BracedElseIfChainNoElse.java')).length).toBeGreaterThanOrEqual(1);
    });

    it('else-if chain where a middle arm does not assign: the initialiser still reaches and the finding fires', async () => {
      const code = initTainted(`{\n            if (request.getParameter("a") != null)\n                target = "safe1";\n            else if (request.getParameter("b") != null)\n                fallback = "other";\n            else\n                target = "safe3";\n        }`, 'ElseIfChainGap');
      const { defs, ids } = await reaching(code, 'ElseIfChainGap.java');
      expect(defs).toHaveLength(3);
      expect(ids).toEqual(new Set([defs[0].id, defs[1].id, defs[2].id]));
      expect((await cmdi(code, 'ElseIfChainGap.java')).length).toBeGreaterThanOrEqual(1);
    });

    it('else-if chain where the first arm does not assign: the initialiser still reaches and the finding fires', async () => {
      const code = initTainted(`{\n            if (request.getParameter("a") != null)\n                fallback = "other";\n            else if (request.getParameter("b") != null)\n                target = "safe2";\n            else\n                target = "safe3";\n        }`, 'ElseIfChainFirstGap');
      const { defs, ids } = await reaching(code, 'ElseIfChainFirstGap.java');
      expect(defs).toHaveLength(3);
      expect(ids).toEqual(new Set([defs[0].id, defs[1].id, defs[2].id]));
      expect((await cmdi(code, 'ElseIfChainFirstGap.java')).length).toBeGreaterThanOrEqual(1);
    });

    it('else-if chain whose last arm only assigns under a nested braceless if: the initialiser still reaches', async () => {
      const code = initTainted(`{\n            if (request.getParameter("a") != null)\n                target = "safe1";\n            else if (request.getParameter("b") != null)\n                target = "safe2";\n            else {\n                if (request.getParameter("c") != null)\n                    target = "safe3";\n            }\n        }`, 'ElseIfChainNestedLast');
      const { defs, ids } = await reaching(code, 'ElseIfChainNestedLast.java');
      expect(defs).toHaveLength(4);
      expect(ids.has(defs[0].id)).toBe(true);
      expect((await cmdi(code, 'ElseIfChainNestedLast.java')).length).toBeGreaterThanOrEqual(1);
    });

    it('the existing braced conditional in a bare block still fires', async () => {
      const code = withBlocks('{ if (request.getParameter("a") != null) target = request.getParameter("host"); }', 'BareBlockBranch2');
      expect((await cmdi(code, 'BareBlockBranch2.java')).length).toBeGreaterThanOrEqual(1);
    });
  });
});

