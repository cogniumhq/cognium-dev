/**
 * cognium-dev #914 — a helper that reads a system property only to choose a
 * shell prefix does not return that property.
 *
 * OWASP BenchmarkJava's `Utils.getOSCommandString(append)` shape:
 * `osName = System.getProperty("os.name")` appears only in an `if` condition,
 * and the method returns `"cmd.exe /c " + append` or `append`. The project
 * phase marked the method `returnsSource` (env_input) because a real source
 * sits in its body, so every caller's `exec(...)` got a cross-file
 * command_injection path from the property read (60 safe OWASP cmdi cases).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';

const helper = (body: string) => `package org.example.helpers;

public class Utils {
    public static String shellCommand(String append) {
${body}
    }
}
`;

const BRANCH_ONLY = `        String command = null;
        String osName = System.getProperty("os.name");
        if (osName.indexOf("Windows") != -1) {
            command = "cmd.exe /c " + append + " ";
        } else {
            command = append + " ";
        }
        return command;`;

const caller = (barInit: string) => `package org.example.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Runner extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String param = request.getHeader("h");
        ${barInit}
        String cmd = org.example.helpers.Utils.shellCommand("ls ");
        String[] args = new String[] {"sh", "-c", cmd + bar};
        Runtime r = Runtime.getRuntime();
        Process p = r.exec(args);
    }
}
`;

async function cmdi(helperBody: string, barInit: string) {
  const pa = await analyzeProject([
    { filePath: 'Utils.java', code: helper(helperBody), language: 'java' },
    { filePath: 'Runner.java', code: caller(barInit), language: 'java' },
  ], {});
  const paths = (pa.taint_paths ?? []).filter(p => p.sink.type === 'command_injection');
  const flows = pa.files.flatMap(f => (f.analysis.taint.flows ?? []).filter(x => x.sink_type === 'command_injection'));
  return { paths, flows };
}

describe('#914 branch-only system property in a command helper', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('os.name read only in the if condition: no path from the helper, safe caller is clean', async () => {
    const { paths, flows } = await cmdi(BRANCH_ONLY, 'String bar = "safe";');
    expect(paths.filter(p => p.source.file === 'Utils.java')).toHaveLength(0);
    expect(flows).toHaveLength(0);
  });

  it('a tainted caller argument still fires through the same helper', async () => {
    const { flows, paths } = await cmdi(BRANCH_ONLY, 'String bar = param;');
    expect(flows.length + paths.length).toBeGreaterThan(0);
  });

  it('a property that is returned keeps the cross-file path', async () => {
    const body = `        String extra = System.getProperty("extra.args");
        return append + " " + extra;`;
    const { paths } = await cmdi(body, 'String bar = "safe";');
    expect(paths.filter(p => p.source.file === 'Utils.java').length).toBeGreaterThan(0);
  });

  it('a property used in the condition and in the data keeps the path', async () => {
    const body = `        String shell = System.getProperty("app.shell");
        if (shell != null) {
            return shell + " -c " + append;
        }
        return append;`;
    const { paths } = await cmdi(body, 'String bar = "safe";');
    expect(paths.filter(p => p.source.file === 'Utils.java').length).toBeGreaterThan(0);
  });

  it('a property copied to another local keeps the path', async () => {
    const body = `        String osName = System.getProperty("os.name");
        String prefix = osName;
        if (osName.indexOf("Windows") != -1) {
            return prefix + append;
        }
        return append;`;
    const { paths } = await cmdi(body, 'String bar = "safe";');
    expect(paths.filter(p => p.source.file === 'Utils.java').length).toBeGreaterThan(0);
  });
});
