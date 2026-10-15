/**
 * cognium-dev#671 — `getOutputStream().write(...)` on an outbound
 * URLConnection / Socket was reported as xss (CWE-79). Those bytes go to a
 * remote server or peer, not to the HTTP response, so nothing is rendered in
 * the requester's browser. The servlet `response.getOutputStream()` forms must
 * keep firing.
 *
 * SAST regression fixture — the response handlers are deliberately vulnerable.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const outbound = `package com.acme.relay;

import java.net.Socket;
import java.net.URL;
import java.net.URLConnection;
import javax.net.ssl.HttpsURLConnection;
import javax.servlet.http.HttpServletRequest;

public class TokenRelay {
    public int forward(HttpServletRequest req) throws Exception {
        String account = req.getParameter("account");
        String pin = req.getParameter("pin");
        HttpsURLConnection link = (HttpsURLConnection) new URL("https://idp.example/token").openConnection();
        link.setDoOutput(true);
        link.getOutputStream().write(("a=" + account + "&p=" + pin).getBytes());
        return link.getResponseCode();
    }

    public void plain(HttpServletRequest req) throws Exception {
        String note = req.getParameter("note");
        URLConnection uc = new URL("https://audit.example/").openConnection();
        uc.getOutputStream().write(note.getBytes());
    }

    public void peer(HttpServletRequest req) throws Exception {
        String note = req.getParameter("note");
        Socket sock = new Socket("peer.example", 7000);
        sock.getOutputStream().write(note.getBytes());
    }

    public void inline(HttpServletRequest req) throws Exception {
        String note = req.getParameter("note");
        new URL("https://audit.example/").openConnection().getOutputStream().write(note.getBytes());
    }
}
`;

const response = `package com.acme.relay;

import java.io.OutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class EchoBytes {
    public void a(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String v = req.getParameter("v");
        resp.getOutputStream().write(v.getBytes());
    }

    public void b(HttpServletRequest req, HttpServletResponse link) throws Exception {
        String v = req.getParameter("v");
        link.getOutputStream().print(v);
    }

    public void c(HttpServletRequest req, HttpServletResponse response) throws Exception {
        String v = req.getParameter("v");
        OutputStream out = response.getOutputStream();
        out.write(v.getBytes());
    }
}
`;

describe('cognium-dev#671 — outbound getOutputStream() is not xss', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('no xss on URLConnection / Socket output streams', async () => {
    const r = await analyze(outbound, 'TokenRelay.java', 'java');
    const xss = (r.taint.flows ?? []).filter((f) => f.sink_type === 'xss');
    expect(xss).toEqual([]);
    expect(r.taint.sinks.filter((s) => s.type === 'xss')).toEqual([]);
  });

  it('servlet response output streams still report xss', async () => {
    const r = await analyze(response, 'EchoBytes.java', 'java');
    const lines = [...new Set((r.taint.flows ?? []).filter((f) => f.sink_type === 'xss').map((f) => f.sink_line))].sort((a, b) => a - b);
    expect(lines).toEqual([10, 15, 21]);
  });

  it('a `var` alias of the response shadows an earlier URLConnection of the same name', async () => {
    const code = `package com.acme.relay;

import java.net.URL;
import java.net.URLConnection;
import javax.servlet.http.*;

public class Mixed {
    public void push(HttpServletRequest req) throws Exception {
        URLConnection sink = new URL("https://svc.example").openConnection();
        sink.getOutputStream().write(req.getParameter("a").getBytes());
    }

    public void echo(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String v = req.getParameter("v");
        var sink = resp;
        sink.getOutputStream().write(v.getBytes());
    }
}
`;
    const r = await analyze(code, 'Mixed.java', 'java');
    const lines = [...new Set((r.taint.flows ?? []).filter((f) => f.sink_type === 'xss').map((f) => f.sink_line))];
    expect(lines).toEqual([16]);
  });

  it('a commented-out URLConnection declaration must not drop servlet xss', async () => {
    const code = `package com.acme.relay;

import javax.servlet.http.*;

public class Commented {
    public void echo(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String v = req.getParameter("v");
        // was URLConnection resp = client.openConnection();
        resp.getOutputStream().write(v.getBytes());
    }
}
`;
    const r = await analyze(code, 'Commented.java', 'java');
    const lines = [...new Set((r.taint.flows ?? []).filter((f) => f.sink_type === 'xss').map((f) => f.sink_line))];
    expect(lines).toEqual([9]);
  });

  it('a block-comment URLConnection declaration must not drop servlet xss', async () => {
    const code = `package com.acme.relay;

import javax.servlet.http.*;

public class BlockCommented {
    public void echo(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String v = req.getParameter("v");
        /* URLConnection resp = client.openConnection(); */
        resp.getOutputStream().write(v.getBytes());
    }
}
`;
    const r = await analyze(code, 'BlockCommented.java', 'java');
    const lines = [...new Set((r.taint.flows ?? []).filter((f) => f.sink_type === 'xss').map((f) => f.sink_line))];
    expect(lines).toEqual([9]);
  });

});
