/**
 * cognium-dev#597 (second-hop branch-carried def) — a local assigned under a
 * branch from a variable that itself is only reached through a branch-carried
 * alternate must still flow to a sink.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const bundleExport = (pickedAssign: string, className: string) => `
import java.io.IOException;
import java.util.Enumeration;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.codec.binary.Base64;

public class ${className} extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String picked = "";
        boolean searching = true;
        Enumeration<String> keys = request.getParameterNames();
        while (keys.hasMoreElements() && searching) {
            String key = keys.nextElement();
            String[] vals = request.getParameterValues(key);
            if (vals != null) {
                for (int i = 0; i < vals.length && searching; i++) {
                    if (vals[i].equals("pickMe")) {
                        ${pickedAssign}
                        searching = false;
                    }
                }
            }
        }

        String label = "";
        if (picked != null) {
            label = new String(Base64.decodeBase64(Base64.encodeBase64(picked.getBytes())));
        }

        String tool = "";
        if (System.getProperty("os.name").indexOf("Windows") != -1) {
            tool = ToolPaths.lookup("archive");
        }

        Runtime.getRuntime().exec(tool + label);
    }
}
`;

async function cmdi(code: string, file: string) {
  const r = await analyze(code, file, 'java');
  return (r.taint.flows ?? []).filter((f) => f.sink_type === 'command_injection');
}

describe('cognium-dev#597 — second-hop branch-carried def', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('BundleExportServlet reports command_injection at exec', async () => {
    const code = bundleExport('picked = key;', 'BundleExportServlet');
    expect((await cmdi(code, 'BundleExportServlet.java')).length).toBeGreaterThanOrEqual(1);
  });

  it('BundleExportSafe stays clean when picked is always a constant', async () => {
    const code = bundleExport('picked = "default.tar";', 'BundleExportSafe');
    expect(await cmdi(code, 'BundleExportSafe.java')).toHaveLength(0);
  });
});
