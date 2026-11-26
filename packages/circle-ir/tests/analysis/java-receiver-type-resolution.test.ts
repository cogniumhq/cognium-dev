/**
 * Java inter-procedural call resolution: a call on a receiver whose declared
 * type is not in this file does not bind to a same-named method of this file.
 *
 * A report reader that implements its own `parse(...)` and hands the report
 * to a hardened `DocumentBuilder` (`docBuilder.parse(is)`) was reported as a
 * critical XXE: the JDK call bound to the reader's own `parse` by name, and
 * the inter-procedural flow it produced skipped the method-level hardening
 * check. Renaming the reader's method made the finding disappear.
 *
 * A receiver typed as a class of this file, or as a type that a class of this
 * file extends or implements, still binds as before. So does a receiver whose
 * declared type text is not a type the file resolves through an import or
 * `java.lang`: `var`, a type variable, or a type of the same package.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const READER = (hardening: string, methodName: string) => `package demo;

import java.io.StringReader;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

public class ReportReader {
    public Document ${methodName}(ResultFile resultFile) throws Exception {
        DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
${hardening}
        DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
        InputSource is = new InputSource(new StringReader(resultFile.content()));
        Document doc = docBuilder.parse(is);
        return doc;
    }
}
`;

const HARDENED =
  '        docBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);';

const SERVLET = (receiverDecl: string, extraTypes: string) => `package demo;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Launch extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String cmd = req.getParameter("cmd");
        ${receiverDecl}
        runner.run(cmd);
    }
}
${extraTypes}
`;

const IMPL = (header: string) => `
class ${header} {
    public void run(String cmd) throws IOException {
        Runtime.getRuntime().exec(cmd);
    }
}
`;

async function flows(code: string, file: string, options: Parameters<typeof analyze>[3] = {}) {
  const ir = await analyze(code, file, 'java', options);
  return ir.taint.flows ?? [];
}

describe('Java call resolution by receiver type', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('a hardened DocumentBuilder.parse inside a method named parse is not XXE', async () => {
    const found = await flows(READER(HARDENED, 'parse'), 'ReportReader.java');
    expect(found.filter((f) => f.sink_type === 'xxe')).toEqual([]);
  });

  it('agrees with the same reader whose method has another name', async () => {
    const renamed = await flows(READER(HARDENED, 'read'), 'ReportReader.java');
    const named = await flows(READER(HARDENED, 'parse'), 'ReportReader.java');
    expect(named.filter((f) => f.sink_type === 'xxe')).toEqual(renamed.filter((f) => f.sink_type === 'xxe'));
  });

  it('still reports XXE when the factory is not hardened', async () => {
    const found = await flows(READER('', 'parse'), 'ReportReader.java');
    expect(found.some((f) => f.sink_type === 'xxe' && f.sink_line === 15)).toBe(true);
  });

  it('a receiver typed as a class of this file still binds to its method', async () => {
    const code = SERVLET('Runner runner = new Runner();', IMPL('Runner'));
    const found = await flows(code, 'Launch.java');
    expect(found.some((f) => f.sink_type === 'command_injection')).toBe(true);
  });

  it('a receiver typed as an interface a class of this file implements still binds', async () => {
    const code = SERVLET('Task runner = new ShellTask();', IMPL('ShellTask implements Task'));
    const found = await flows(code, 'Launch.java');
    expect(found.some((f) => f.sink_type === 'command_injection')).toBe(true);
  });

  it('a receiver declared with var still binds to the class it is created from', async () => {
    const code = SERVLET('var runner = new Runner();', IMPL('Runner'));
    const found = await flows(code, 'Launch.java');
    expect(found.some((f) => f.sink_type === 'command_injection' && f.source_line === 10 && f.sink_line === 18)).toBe(true);
  });

  it('a field typed by a type variable of the class still binds to its bound', async () => {
    const code = `package demo;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Launch<R extends Runner> extends HttpServlet {
    R runner;
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String cmd = req.getParameter("cmd");
        runner.run(cmd);
    }
}
${IMPL('Runner')}`;
    const found = await flows(code, 'Launch.java');
    expect(found.some((f) => f.sink_type === 'command_injection' && f.source_line === 11 && f.sink_line === 18)).toBe(true);
  });

  it('a parameter typed by a type variable of the method still binds to its bound', async () => {
    const code = `package demo;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Launch extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String cmd = req.getParameter("cmd");
        h(new Runner(), cmd);
    }
    <R extends Runner> void h(R runner, String cmd) throws IOException {
        runner.run(cmd);
    }
}
${IMPL('Runner')}`;
    const found = await flows(code, 'Launch.java');
    expect(found.some((f) => f.sink_type === 'command_injection' && f.source_line === 10 && f.sink_line === 20)).toBe(true);
  });

  it('a receiver typed as a same-package type of another file keeps the same-file binding', async () => {
    const code = SERVLET('Task runner = new ShellTask();', IMPL('ShellTask extends AbstractTask'));
    const found = await flows(code, 'Launch.java');
    expect(found.some((f) => f.sink_type === 'command_injection' && f.source_line === 10 && f.sink_line === 18)).toBe(true);
  });

  it('with type variables known, a type-variable receiver binds to its bound, not the first same-named method', async () => {
    const code = `package demo;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Launch<R extends Runner> extends HttpServlet {
    R runner;
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String cmd = req.getParameter("cmd");
        runner.run(cmd);
    }
}

class Logger {
    public void run(String line) { }
}
${IMPL('Runner')}`;
    const found = await flows(code, 'Launch.java', { navigationTypes: true });
    expect(found.some((f) => f.sink_type === 'command_injection' && f.source_line === 11 && f.sink_line === 22)).toBe(true);
  });
});
