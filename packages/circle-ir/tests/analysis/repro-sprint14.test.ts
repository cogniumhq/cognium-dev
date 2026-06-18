/**
 * Repro for Sprint 14 (cognium-dev v3.64.0) — Java FP corpus regression (#101).
 *
 * The fixtures below are byte-equivalent excerpts of the `SafeService.java`
 * and `FalsePositiveCorpus.java` files from `coggiyadmin/java-vuln-demo`,
 * the upstream repro repository attached to issue #101.
 *
 * Every method modelled here is *deliberately safe*:
 *   - `SafeService.java` flows tainted input through documented sanitizers
 *     (PreparedStatement, OWASP Encoder, canonical-path check, allowlist,
 *     ESAPI LDAP encoder, XXE-hardened DocumentBuilderFactory, SecureRandom).
 *   - `FalsePositiveCorpus.java` exercises six documented hard FP categories
 *     for taint analysis (int/UUID type-cast, regex allowlist, switch-to-
 *     constant, reassign-to-literal, bounded enum, unreachable-by-DEBUG).
 *
 * The scanner MUST produce zero security-typed `taint.flows` for these
 * files. Any finding is a false positive (the regression #101 is about).
 *
 * NOTE: SAST regression fixtures — do not "fix" the fixtures.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

// -----------------------------------------------------------------------------
// Fixtures (verbatim from coggiyadmin/java-vuln-demo)
// -----------------------------------------------------------------------------

const SAFE_SERVICE_JAVA = `package com.demo;

import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.SecureRandom;
import java.sql.*;
import java.util.*;
import javax.servlet.http.*;
import javax.xml.parsers.*;
import org.owasp.encoder.Encode;
import org.owasp.esapi.ESAPI;

/**
 * NEGATIVE TEST FILE — secure equivalents of every vulnerable pattern.
 */
public class SafeService {

    private static final String UPLOAD_ROOT = "/var/app/uploads";
    private static final Set<String> ALLOWED_HOSTS =
        Set.of("api.internal.example.com", "cdn.example.com");

    // SAFE sql — parameterized PreparedStatement, no concatenation
    public ResultSet getUser(HttpServletRequest request, Connection conn) throws SQLException {
        String username = request.getParameter("username");
        PreparedStatement ps = conn.prepareStatement(
            "SELECT * FROM users WHERE username = ?");
        ps.setString(1, username);
        return ps.executeQuery();
    }

    // SAFE xss — OWASP Encoder escapes before rendering
    public String renderProfile(HttpServletRequest request) {
        String name = request.getParameter("name");
        String safe = Encode.forHtml(name);
        return "<div class=\\"profile\\"><h2>" + safe + "</h2></div>";
    }

    // SAFE path — canonicalize and verify the result stays under UPLOAD_ROOT
    public String readUpload(HttpServletRequest request) throws IOException {
        String filename = request.getParameter("file");
        File base = new File(UPLOAD_ROOT);
        File target = new File(base, filename);
        String canonical = target.getCanonicalPath();
        if (!canonical.startsWith(base.getCanonicalPath() + File.separator)) {
            throw new SecurityException("path traversal blocked");
        }
        return new String(Files.readAllBytes(Paths.get(canonical)));
    }

    // SAFE ssrf — host validated against an allowlist before the request
    public String fetchResource(HttpServletRequest request) throws IOException {
        String urlParam = request.getParameter("url");
        URL url = new URL(urlParam);
        if (!isAllowedHost(url.getHost())) {
            throw new SecurityException("host not allowed");
        }
        try (InputStream in = url.openStream()) {
            return new String(in.readAllBytes());
        }
    }

    private boolean isAllowedHost(String host) {
        return ALLOWED_HOSTS.contains(host);
    }

    // SAFE ldap — ESAPI encodes the user value before it enters the filter
    public String buildLdapFilter(HttpServletRequest request) {
        String uid = request.getParameter("uid");
        String encoded = ESAPI.encoder().encodeForLDAP(uid);
        return "(&(objectClass=person)(uid=" + encoded + "))";
    }

    // SAFE xxe — external entities and DOCTYPE disabled before parse
    public org.w3c.dom.Document parseXmlSafely(HttpServletRequest request) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        DocumentBuilder builder = factory.newDocumentBuilder();
        byte[] body = request.getInputStream().readAllBytes();
        return builder.parse(new ByteArrayInputStream(body));
    }

    // SAFE random — SecureRandom for token generation
    public String generateToken() {
        SecureRandom rng = new SecureRandom();
        byte[] bytes = new byte[32];
        rng.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    // SAFE config — credentials read from the environment, nothing hardcoded
    public String dbPassword() {
        return System.getenv("DB_PASSWORD");
    }
}
`;

const FALSE_POSITIVE_CORPUS_JAVA = `package com.demo;

import java.io.*;
import java.sql.*;
import java.util.*;
import java.util.regex.Pattern;
import javax.servlet.http.HttpServletRequest;

/**
 * ZERO-FP FALSE-POSITIVE CORPUS — patterns that LOOK tainted but are provably safe.
 */
public class FalsePositiveCorpus {

    // 1. TYPE-CAST — Integer.parseInt: an int cannot carry a SQLi payload
    public ResultSet byId(HttpServletRequest req, Connection conn) throws SQLException {
        int id = Integer.parseInt(req.getParameter("id"));
        Statement st = conn.createStatement();
        return st.executeQuery("SELECT * FROM users WHERE id = " + id);
    }

    // 1b. TYPE-CAST — UUID.fromString validates format; result cannot inject
    public ResultSet byUuid(HttpServletRequest req, Connection conn) throws SQLException {
        UUID uuid = UUID.fromString(req.getParameter("uuid"));
        Statement st = conn.createStatement();
        return st.executeQuery("SELECT * FROM sessions WHERE sid = '" + uuid + "'");
    }

    // 2. REGEX VALIDATION — strict allowlist pattern before use in a path
    private static final Pattern SAFE_NAME = Pattern.compile("^[a-zA-Z0-9_]{1,32}$");
    public String readConfig(HttpServletRequest req) throws IOException {
        String name = req.getParameter("name");
        if (!SAFE_NAME.matcher(name).matches()) {
            throw new IllegalArgumentException("invalid name");
        }
        return new String(java.nio.file.Files.readAllBytes(
            java.nio.file.Paths.get("/etc/app/" + name + ".conf")));
    }

    // 3. SWITCH → CONSTANT — user input only selects among hardcoded commands
    public String runReport(HttpServletRequest req) throws Exception {
        String type = req.getParameter("type");
        String cmd;
        switch (type) {
            case "daily":   cmd = "/usr/bin/report-daily";   break;
            case "weekly":  cmd = "/usr/bin/report-weekly";  break;
            default:        cmd = "/usr/bin/report-default"; break;
        }
        Process p = Runtime.getRuntime().exec(cmd);
        return new String(p.getInputStream().readAllBytes());
    }

    // 4. REASSIGNMENT — tainted value overwritten with a constant before the sink
    public ResultSet lookup(HttpServletRequest req, Connection conn) throws SQLException {
        String table = req.getParameter("table");
        table = "users";
        Statement st = conn.createStatement();
        return st.executeQuery("SELECT * FROM " + table + " LIMIT 10");
    }

    // 5. BOUNDED ENUM — value validated against a fixed allowlist set
    private static final Set<String> COLUMNS = Set.of("name", "email", "created_at");
    public ResultSet sortBy(HttpServletRequest req, Connection conn) throws SQLException {
        String col = req.getParameter("sort");
        if (!COLUMNS.contains(col)) col = "name";
        Statement st = conn.createStatement();
        return st.executeQuery("SELECT * FROM users ORDER BY " + col);
    }

    // 6. DEAD CODE — sink is unreachable (guarded by a compile-time-false constant)
    private static final boolean DEBUG = false;
    public void debugExec(HttpServletRequest req) throws Exception {
        String cmd = req.getParameter("cmd");
        if (DEBUG) {
            Runtime.getRuntime().exec(cmd);
        }
    }
}
`;

// Security-typed taint flow kinds the issue calls out as FPs.
const SECURITY_SINK_TYPES = new Set([
  'sql_injection',
  'command_injection',
  'xss',
  'path_traversal',
  'ssrf',
  'ldap_injection',
  'xxe',
  'deserialization',
  'xpath_injection',
  'open_redirect',
  'weak_random',
]);

function securityFlows(r: { taint?: { flows?: Array<{ sink_type?: string }> } }) {
  return (r.taint?.flows ?? []).filter(
    f => typeof f.sink_type === 'string' && SECURITY_SINK_TYPES.has(f.sink_type)
  );
}

describe('Sprint 14 — issue #101 Java FP corpus regression', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('SafeService.java — documented sanitizers must produce zero security taint flows', async () => {
    const r = await analyze(SAFE_SERVICE_JAVA, 'SafeService.java', 'java');
    const flows = securityFlows(r);
    if (flows.length > 0) {
      // Useful diagnostic when the assertion fires.
      // eslint-disable-next-line no-console
      console.log('SafeService.java FPs:', flows.map(f => ({
        type: f.sink_type, line: (f as { sink_line?: number }).sink_line,
        src: (f as { source_line?: number }).source_line,
        srcType: (f as { source_type?: string }).source_type,
      })));
    }
    expect(flows).toEqual([]);
  });

  it('FalsePositiveCorpus.java — documented FP categories must produce zero security taint flows', async () => {
    const r = await analyze(FALSE_POSITIVE_CORPUS_JAVA, 'FalsePositiveCorpus.java', 'java');
    const flows = securityFlows(r);
    if (flows.length > 0) {
      // eslint-disable-next-line no-console
      console.log('FalsePositiveCorpus.java FPs:', flows.map(f => ({
        type: f.sink_type, line: (f as { sink_line?: number }).sink_line,
        src: (f as { source_line?: number }).source_line,
        srcType: (f as { source_type?: string }).source_type,
      })));
    }
    expect(flows).toEqual([]);
  });

  // -------------------------------------------------------------------------
  // Phase B targeted check: FP-04 (bounded-enum + literal fallback).
  // Even before the other FPs land, the reassign-to-literal suppressor
  // (`isReassignedToLiteralBetween`) must recognize the `if (!COLUMNS...) col
  // = "name";` form. The suppressor short-circuits when the source has no
  // `variable` — Phase B fixes Java source LHS binding to keep this gate open.
  // -------------------------------------------------------------------------
  it('FP-04: bounded enum + literal fallback — no sql_injection flow at the sortBy sink', async () => {
    const r = await analyze(FALSE_POSITIVE_CORPUS_JAVA, 'FalsePositiveCorpus.java', 'java');
    const sqlFlows = (r.taint.flows ?? []).filter(f => f.sink_type === 'sql_injection');
    expect(sqlFlows).toEqual([]);
  });

  // -------------------------------------------------------------------------
  // Phase B sub-check: Java sources emitted via the YAML/call-pattern path
  // must now carry a `variable` whenever the source line is a bare
  // assignment. This is the precondition for every variable-scoped sanitizer
  // detector (`isReassignedToLiteralBetween`, allowlist guards, etc.).
  // -------------------------------------------------------------------------
  it('Phase B: Java sources land with `variable` bound from the source line LHS', async () => {
    const code = `package com.demo;
import javax.servlet.http.*;
public class B {
  public void f(HttpServletRequest req) {
    String col = req.getParameter("sort");
    System.out.println(col);
  }
}
`;
    const r = await analyze(code, 'B.java', 'java');
    const httpParam = (r.taint.sources ?? []).filter(s => s.type === 'http_param');
    expect(httpParam.length).toBeGreaterThan(0);
    expect(httpParam[0].variable).toBe('col');
  });
});
