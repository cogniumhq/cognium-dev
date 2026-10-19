/**
 * cognium-dev#590 — a cross-file wrapper-return taint must reach caller-body
 * sinks when the sink argument is a derived local (`sql = "…" + invoice`), not
 * only when the tainted name is passed directly.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';

const requestWrapper = `package com.acme.web;

import javax.servlet.http.HttpServletRequest;

public class RequestWrapper {
    private final HttpServletRequest request;

    public RequestWrapper(HttpServletRequest request) {
        this.request = request;
    }

    public String fetchField(String name) {
        return request.getParameter(name);
    }

    public String fixedField(String name) {
        return "bar";
    }
}
`;

const invoiceQueryServlet = `import java.io.IOException;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import com.acme.web.RequestWrapper;

public class InvoiceQueryServlet extends HttpServlet {
    private Connection conn;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        RequestWrapper wrap = new RequestWrapper(request);
        String invoice = wrap.fetchField("invoice");
        String sql = "SELECT * FROM invoices WHERE ref = '" + invoice + "'";
        try {
            Statement stmt = conn.createStatement();
            stmt.executeQuery(sql);
            stmt.executeQuery("SELECT * FROM invoices WHERE ref = '" + invoice + "'");
        } catch (SQLException e) {
            throw new IOException(e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        RequestWrapper wrap = new RequestWrapper(request);
        String invoice = wrap.fixedField("invoice");
        String sql = "SELECT * FROM invoices WHERE ref = '" + invoice + "'";
        try {
            Statement stmt = conn.createStatement();
            stmt.executeQuery(sql);
        } catch (SQLException e) {
            throw new IOException(e);
        }
    }
}
`;

function sqlSinkLines(file: string, pa: Awaited<ReturnType<typeof analyzeProject>>): number[] {
  const paths = pa.taint_paths.filter(
    p => p.sink.type === 'sql_injection' && p.sink.file === file,
  );
  const perFile = pa.files
    .find(f => f.file === file)
    ?.analysis.taint.flows?.filter(f => f.sink_type === 'sql_injection')
    .map(f => f.sink_line) ?? [];
  return [...new Set([...paths.map(p => p.sink.line), ...perFile])].sort((a, b) => a - b);
}

describe('cognium-dev#590 cross-file wrapper return + derived local', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('reports sql_injection for derived sql and direct invoice sinks; post stays clean', async () => {
    const pa = await analyzeProject(
      [
        { filePath: 'com/acme/web/RequestWrapper.java', code: requestWrapper, language: 'java' },
        { filePath: 'InvoiceQueryServlet.java', code: invoiceQueryServlet, language: 'java' },
      ],
      {},
    );

    const lines = sqlSinkLines('InvoiceQueryServlet.java', pa);
    const getSink = (tag: string) =>
      invoiceQueryServlet.split('\n').findIndex(l => l.includes(tag)) + 1;

    const derivedLine = getSink('stmt.executeQuery(sql)');
    const directLine = getSink('stmt.executeQuery("SELECT * FROM invoices WHERE ref = \'\" + invoice');
    const postLine = getSink('protected void doPost');

    expect(lines).toContain(derivedLine);
    expect(lines).toContain(directLine);
    expect(lines.filter(l => l > postLine)).toEqual([]);
  });
});
