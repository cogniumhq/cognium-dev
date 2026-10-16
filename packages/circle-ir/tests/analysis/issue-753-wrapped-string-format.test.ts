/**
 * cognium-dev#753 (slice 1, follow-up of #597) — Java: a statement whose call
 * argument list wraps after a leading string-literal argument
 * (`label = String.format("%s.tar",\n    picked);`) is read like the same statement
 * on one line, so `exec(tool + label)` keeps the flow from `picked`.
 *
 * Before: only the one-line form linked `label` to `picked` on the alias scan;
 * the wrapped form lost the flow, while `exec(label)` alone happened to report.
 *
 * SAST regression fixture — the servlets are deliberately vulnerable.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const servlet = (name: string, body: string) => `import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.codecs.UnixCodec;

public class ${name} extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String picked = request.getParameterNames().nextElement();
        String tool = "/usr/bin/tar ";
        String label = "";
${body}
    }
}
`;

const SINK = '        Runtime.getRuntime().exec(tool + label);';

async function cmdi(code: string, file: string): Promise<number> {
  const r = await analyze(code, file, 'java');
  return (r.taint.flows ?? []).filter((f) => f.sink_type === 'command_injection').length;
}

describe('cognium-dev#753 — wrapped String.format reaches exec(tool + label)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('control: the one-line form reports', async () => {
    const code = servlet('ExportServlet', `        label = String.format("%s.tar", picked);\n${SINK}`);
    expect(await cmdi(code, 'ExportServlet.java')).toBeGreaterThanOrEqual(1);
  });

  for (const [name, assign] of [
    ['an argument after the format string', '        label = String.format("%s.tar",\n                picked);'],
    ['the format string on its own line', '        label = String.format(\n                "%s.tar",\n                picked);'],
    ['a space before the paren and the continuation indented differently', '        label = String.format ("%s.tar",\n      picked );'],
    ['a trailing comment on the first line', '        label = String.format("%s.tar", // name\n                picked);'],
    ['a declaration', '        String other = String.format("%s.tar",\n                picked);\n        label = other;'],
    ['a concatenation after the wrapped call', '        label = String.format("%s.tar",\n                picked) + ".gz";'],
  ] as const) {
    it(`reports for ${name}`, async () => {
      expect(await cmdi(servlet('WrapServlet', `${assign}\n${SINK}`), 'WrapServlet.java')).toBeGreaterThanOrEqual(1);
    });
  }

  it('reports for a wrapped assignment inside an if block', async () => {
    const code = servlet('WrapIf', `        if (picked != null) {\n            label = String.format("%s.tar",\n                    picked);\n        }\n${SINK}`);
    expect(await cmdi(code, 'WrapIf.java')).toBeGreaterThanOrEqual(1);
  });

  it('reports inside a loop body', async () => {
    const code = servlet('WrapLoop', `        for (int i = 0; i < 2; i++) {\n            label = String.format("%s.tar",\n                    picked);\n            Runtime.getRuntime().exec(tool + label);\n        }`);
    expect(await cmdi(code, 'WrapLoop.java')).toBeGreaterThanOrEqual(1);
  });

  it('reports for a try with a catch that resets label to a literal', async () => {
    const code = servlet('TryCatchServlet', `        try {\n            label = String.format("%s.tar", picked);\n        } catch (Exception e) {\n            label = "";\n        }\n${SINK}`);
    const r = await analyze(code, 'TryCatchServlet.java', 'java');
    expect((r.taint.sinks ?? []).length).toBeGreaterThan(0);
    expect(await cmdi(code, 'TryCatchServlet.java')).toBeGreaterThanOrEqual(1);
  });

  it('is not keyed on names: a renamed value, local and parameter', async () => {
    const code = `import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ArchiveServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String chosen = req.getParameterNames().nextElement();
        String program = "/usr/bin/zip ";
        String archive = "";
        archive = String.format("%s.zip",
                chosen);
        Runtime.getRuntime().exec(program + archive);
    }
}
`;
    return cmdi(code, 'ArchiveServlet.java').then((n) => expect(n).toBeGreaterThanOrEqual(1));
  });

  describe('stays clean', () => {
    it('a wrapped format of only constants', async () => {
      const code = servlet('ConstServlet', `        label = String.format("%s.tar",\n                "const");\n${SINK}`);
      expect(await cmdi(code, 'ConstServlet.java')).toBe(0);
    });

    it('a wrapped format of only constants, format string on its own line', async () => {
      const code = servlet('ConstServlet2', `        label = String.format(\n                "%s.tar",\n                "const");\n${SINK}`);
      expect(await cmdi(code, 'ConstServlet2.java')).toBe(0);
    });

    it('a wrapped format that reads another variable', async () => {
      const code = servlet('OtherServlet', `        label = String.format("%s.tar",\n                tool);\n${SINK}`);
      expect(await cmdi(code, 'OtherServlet.java')).toBe(0);
    });

    it('a literal reassignment after the wrapped format', async () => {
      const code = servlet('ResetServlet', `        label = String.format("%s.tar",\n                picked);\n        label = "backup.tar";\n${SINK}`);
      expect(await cmdi(code, 'ResetServlet.java')).toBe(0);
    });

    it('a copy taken before the reset is the tainted one; the reset variable is clean', async () => {
      const code = servlet('CopyServlet', `        label = String.format("%s.tar",\n                picked);\n        String copy = label;\n        label = "backup.tar";\n        Runtime.getRuntime().exec(tool + label);`);
      expect(await cmdi(code, 'CopyServlet.java')).toBe(0);
    });

    it('the wrapped value is parsed as a number', async () => {
      const code = servlet('NumServlet', `        label = Integer.toString(Integer.parseInt(\n                picked));\n${SINK}`);
      expect(await cmdi(code, 'NumServlet.java')).toBe(0);
    });

    it('a wrapped value inside a lambda does not taint the local', async () => {
      const code = servlet('LambdaServlet', `        Runnable job = () -> {\n            String x = String.format("%s",\n                    picked);\n        };\n        label = "x";\n${SINK}`);
      expect(await cmdi(code, 'LambdaServlet.java')).toBe(0);
    });

    it('a covering sanitizer around the wrapped operand still credits it', async () => {
      const code = servlet('SanServlet', `        label = String.format("%s.tar",\n                ESAPI.encoder().encodeForOS(new UnixCodec(), picked));\n${SINK}`);
      expect(await cmdi(code, 'SanServlet.java')).toBe(0);
    });

    it('a raw operand beside a sanitized one still reports', async () => {
      const code = servlet('RawServlet', `        label = String.format("%s.%s",\n                ESAPI.encoder().encodeForOS(new UnixCodec(), picked), picked);\n${SINK}`);
      expect(await cmdi(code, 'RawServlet.java')).toBeGreaterThanOrEqual(1);
    });
  });
});
