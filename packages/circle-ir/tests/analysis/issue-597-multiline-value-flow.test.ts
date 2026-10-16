/**
 * cognium-dev#597 (second blocker) — a Java local whose value wraps over several
 * lines carried no def-use chain from the variables read on the continuation
 * lines, so `exec(<const-local> + <wrapped-local>)` lost its flow. The wrapped
 * Base64 round-trip of the Benchmark `bar = new String(\n decodeBase64(\n ...` is one
 * instance; the mechanism is any value that wraps.
 *
 * SAST regression fixture — the handlers are deliberately vulnerable.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const IMPORTS = `
import java.io.IOException;
import java.util.Enumeration;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.codec.binary.Base64;
`;

const servlet = (name: string, body: string) => `${IMPORTS}
public class ${name} extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
${body}
    }
}
`;

/** Parameter-name pick (nested loops), then `label = <value>` inside an `if`, then the sink. */
const bundle = (name: string, pickAssign: string, value: string, sink: string) =>
  servlet(name, `
        String picked = "";
        boolean searching = true;
        Enumeration<String> keys = request.getParameterNames();
        while (keys.hasMoreElements() && searching) {
            String key = keys.nextElement();
            String[] vals = request.getParameterValues(key);
            if (vals != null) {
                for (int i = 0; i < vals.length && searching; i++) {
                    if (vals[i].equals("pickMe")) {
                        picked = ${pickAssign};
                        searching = false;
                    }
                }
            }
        }

        String label = "";
        if (picked != null) {
            ${value}
        }

        String tool = "";
        if (System.getProperty("os.name").indexOf("Windows") != -1) {
            tool = ToolPaths.lookup("archive");
        }

        ${sink}`);

const roundTrip = `label = new String(
                Base64.decodeBase64(
                    Base64.encodeBase64(
                        picked.getBytes())));`;

async function flows(code: string, file: string, type = 'command_injection') {
  const r = await analyze(code, file, 'java');
  return (r.taint.flows ?? []).filter((f) => f.sink_type === type);
}

describe('cognium-dev#597 — a wrapped value links the variables on its continuation lines', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('wrapped Base64 round-trip of a parameter-name pick reaches exec(tool + label)', async () => {
    const code = bundle('BundleExportServlet', 'key', roundTrip, 'Runtime.getRuntime().exec(tool + label);');
    expect((await flows(code, 'BundleExportServlet.java')).length).toBeGreaterThanOrEqual(1);
  });

  it('safe twin: the loop picks a constant, so nothing reaches the exec', async () => {
    const code = bundle('BundleExportSafe', '"default.tar"', roundTrip, 'Runtime.getRuntime().exec(tool + label);');
    expect(await flows(code, 'BundleExportSafe.java')).toHaveLength(0);
  });

  for (const [name, value] of [
    ['a call argument on its own line', 'label = lookup(\n                picked);'],
    ['a receiver on its own line', 'label = picked\n                .trim();'],
    ['a space before the paren', 'label = new String (\n                picked.getBytes ());'],
    ['an operand after a concat', 'label = "x" +\n                picked;'],
  ] as const) {
    it(`fires for ${name}`, async () => {
      const code = bundle('WrapServlet', 'key', value, 'Runtime.getRuntime().exec(tool + label);');
      expect((await flows(code, 'WrapServlet.java')).length).toBeGreaterThanOrEqual(1);
    });
  }

  it('control: exec(label) alone still fires on the wrapped value', async () => {
    const code = bundle('WrapAlone', 'key', roundTrip, 'Runtime.getRuntime().exec(label);');
    expect((await flows(code, 'WrapAlone.java')).length).toBeGreaterThanOrEqual(1);
  });

  it('a wrapped value built only from constants stays clean', async () => {
    const code = bundle('WrapConst', 'key', 'label = lookup(\n                "a.tar");', 'Runtime.getRuntime().exec(tool + label);');
    expect(await flows(code, 'WrapConst.java')).toHaveLength(0);
  });

  it('a wrapped value that never reads the picked variable stays clean', async () => {
    const code = bundle('WrapOther', 'key', 'label = lookup(\n                tool);', 'Runtime.getRuntime().exec(tool + label);');
    expect(await flows(code, 'WrapOther.java')).toHaveLength(0);
  });

  it('a straight-line reassignment to a constant after the block stays clean', async () => {
    const code = bundle('WrapReset', 'key', roundTrip, 'label = "backup.tar";\n        Runtime.getRuntime().exec(tool + label);');
    expect(await flows(code, 'WrapReset.java')).toHaveLength(0);
  });

  it('a wrapped value inside a lambda does not make the local tainted', async () => {
    const code = bundle('WrapLambda', 'key', 'Runnable job = () -> {\n                lookup(picked);\n            };\n            label = "x";', 'Runtime.getRuntime().exec(tool + label);');
    expect(await flows(code, 'WrapLambda.java')).toHaveLength(0);
  });
});

describe('cognium-dev#597 — a sanitizer call on a continuation line still credits its operand', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const page = (name: string, value: string) => servlet(name, `
        String p = request.getParameter("q");
        String label = "";
        if (p != null) {
            ${value}
        }
        String pre = "<b>";
        response.getWriter().println(pre + label);`);

  it('an encoder wrapped over several lines keeps the output clean', async () => {
    const code = page('EncodedPage', 'label = org.owasp.esapi.ESAPI.encoder()\n                .encodeForHTML(\n                    p);');
    expect(await flows(code, 'EncodedPage.java', 'xss')).toHaveLength(0);
  });

  it('the same wrap without the encoder reports', async () => {
    const code = page('RawPage', 'label = decorate(\n                p);');
    expect((await flows(code, 'RawPage.java', 'xss')).length).toBeGreaterThanOrEqual(1);
  });
});
