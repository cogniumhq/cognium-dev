/**
 * Repro for cognium-dev#52 — three Java sink/source patterns missed by the
 * matcher:
 *
 *   1. Text4Shell — Apache Commons Text StringSubstitutor.replace() / .replaceIn()
 *      (CVE-2022-42889, CWE-94, code_injection sink)
 *   2. FreeMarker SSTI — `new Template(name, reader, cfg)` and `tpl.process(...)`
 *      (CWE-94, code_injection sink)
 *   3. Zip-Slip — ZipEntry.getName() flowing into File()/FileOutputStream()
 *      (CWE-22, path_traversal sink — entry name was previously modeled as a
 *      sink, which produced 3 findings per vuln; the correct model is SOURCE →
 *      File ctor sink, 1 finding)
 *
 * Root cause: matchesSinkPattern + matchesSourcePattern were ignoring
 * `call.receiver_type` populated by Java/TS plugins, falling back to a
 * receiver-name string heuristic that failed for resolved variable types.
 *
 * NOTE: SAST regression fixtures — every handler below is *deliberately*
 * vulnerable so the detector can be measured. Do not "fix" the fixtures.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('cognium-dev#52 — Text4Shell / FreeMarker / Zip-Slip Java sinks', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // -----------------------------------------------------------------------
  // 1) Text4Shell (CVE-2022-42889) — StringSubstitutor.replace()
  // -----------------------------------------------------------------------

  it('Java Text4Shell: explicit ctor — new StringSubstitutor() + ss.replace(taint) FIRES', async () => {
    const code = `
import javax.servlet.http.*;
import org.apache.commons.text.StringSubstitutor;
public class T4S1 {
  public String t(HttpServletRequest req) {
    String x = req.getParameter("p");
    StringSubstitutor ss = new StringSubstitutor();
    return ss.replace(x);
  }
}
`;
    const r = await analyze(code, 'T4S1.java', 'java');
    const ci = (r.taint.flows ?? []).filter((f) => f.sink_type === 'code_injection');
    expect(ci.length).toBeGreaterThanOrEqual(1);
  });

  it('Java Text4Shell: chained variable — StringSubstitutor.createInterpolator() + interp.replace(taint) FIRES', async () => {
    const code = `
import javax.servlet.http.*;
import org.apache.commons.text.StringSubstitutor;
public class T4S2 {
  public String t(HttpServletRequest req) {
    String x = req.getParameter("p");
    StringSubstitutor interp = StringSubstitutor.createInterpolator();
    return interp.replace(x);
  }
}
`;
    const r = await analyze(code, 'T4S2.java', 'java');
    const ci = (r.taint.flows ?? []).filter((f) => f.sink_type === 'code_injection');
    expect(ci.length).toBeGreaterThanOrEqual(1);
  });

  // -----------------------------------------------------------------------
  // 2) FreeMarker SSTI — new Template(name, reader, cfg)
  // -----------------------------------------------------------------------

  it('Java FreeMarker: new Template(name, new StringReader(taint), cfg) FIRES code_injection', async () => {
    const code = `
import javax.servlet.http.*;
import freemarker.template.*;
public class FmSSTI {
  public void t(HttpServletRequest req, java.io.Writer out) throws Exception {
    String body = req.getParameter("tpl");
    Template tpl = new Template("name", new java.io.StringReader(body), new Configuration());
    tpl.process(new java.util.HashMap(), out);
  }
}
`;
    const r = await analyze(code, 'FmSSTI.java', 'java');
    const ci = (r.taint.flows ?? []).filter((f) => f.sink_type === 'code_injection');
    expect(ci.length).toBeGreaterThanOrEqual(1);
  });

  // -----------------------------------------------------------------------
  // 3) Zip-Slip — ZipEntry.getName() flowing into File() / FileOutputStream()
  // -----------------------------------------------------------------------

  it('Java Zip-Slip: entry.getName() (SOURCE) flowing into new File(dir, name) FIRES path_traversal', async () => {
    const code = `
import java.io.*;
import java.util.zip.*;
public class ZipSlip1 {
  public void unzip(ZipInputStream zis, File destDir) throws Exception {
    ZipEntry entry = zis.getNextEntry();
    File outFile = new File(destDir, entry.getName());
    new FileOutputStream(outFile);
  }
}
`;
    const r = await analyze(code, 'ZipSlip1.java', 'java');
    const pt = (r.taint.flows ?? []).filter((f) => f.sink_type === 'path_traversal');
    expect(pt.length).toBeGreaterThanOrEqual(1);
  });

  it('Java Zip-Slip: Apache Commons ZipArchiveEntry.getName() also tainted', async () => {
    const code = `
import java.io.*;
import org.apache.commons.compress.archivers.zip.*;
public class ZipSlip2 {
  public void unzip(ZipFile zf, ZipArchiveEntry entry, File destDir) throws Exception {
    File outFile = new File(destDir, entry.getName());
    new FileOutputStream(outFile);
  }
}
`;
    const r = await analyze(code, 'ZipSlip2.java', 'java');
    const pt = (r.taint.flows ?? []).filter((f) => f.sink_type === 'path_traversal');
    expect(pt.length).toBeGreaterThanOrEqual(1);
  });

  it('Java Zip-Slip: entry.getName() should NOT itself be reported as a sink (de-dup, was 3 findings)', async () => {
    const code = `
import java.io.*;
import java.util.zip.*;
public class ZipSlipDedup {
  public void unzip(ZipInputStream zis, File destDir) throws Exception {
    ZipEntry entry = zis.getNextEntry();
    File outFile = new File(destDir, entry.getName());
    new FileOutputStream(outFile);
  }
}
`;
    const r = await analyze(code, 'ZipSlipDedup.java', 'java');
    // Sinks should only include File() and FileOutputStream() — not entry.getName()
    const sinkLocs = (r.taint.sinks ?? []).map((s) => s.location ?? '');
    const getNameSinks = sinkLocs.filter((l) => l.includes('getName'));
    expect(getNameSinks.length).toBe(0);
  });
});
