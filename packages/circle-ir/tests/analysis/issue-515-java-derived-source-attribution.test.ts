/**
 * #515 (Java slice) — derived alias source attribution must follow the RHS,
 * not the earliest unused read in the same method.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const flowsOf = async (code: string) => {
  const ir = await analyze(code, 'ArchiveExportServlet.java', 'java');
  return (ir.taint.flows ?? []).map(f => [f.source_line, f.sink_line, f.sink_type] as const);
};

const EXPORT = `import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ArchiveExportServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String note = request.getParameter("note");
        String fmt = request.getHeader("X-Format");
        String cmdline = "tar --format " + fmt;
        Runtime.getRuntime().exec(cmdline);
    }
}
`;

const DECOY = `import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ArchiveDecoyServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String note = request.getParameter("note");
        String cmdline = "tar --format zip";
        Runtime.getRuntime().exec(cmdline);
    }
}
`;

describe('#515 Java derived-variable source attribution', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('credits the read the derivation references, not an earlier decoy read', async () => {
    const flows = await flowsOf(EXPORT);
    expect(flows).toEqual([[10, 12, 'command_injection']]);
  });

  it('keeps a literal-only command with no flow', async () => {
    expect(await flowsOf(DECOY)).toEqual([]);
  });
});
