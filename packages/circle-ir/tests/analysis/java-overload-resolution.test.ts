/**
 * Java inter-procedural call resolution with overloads and method order.
 *
 * Calls used to bind by method name alone, and the last declaration of a name
 * replaced the earlier ones. So adding an unrelated same-arity overload BELOW
 * a method hid a live flow into it (SecuriBench Micro `Inter3.f9` with a
 * `void f9(AtomicLong)` added after `f9(String)`), and moving a method within
 * its file could drop findings (a callee declared above its caller was
 * visited before the caller tainted it).
 *
 * Now a call binds by arity and known argument types, keeps every candidate
 * when that stays ambiguous, and the result does not depend on the order of
 * the methods in the file.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const HEADER = `package demo;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.concurrent.atomic.AtomicLong;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
`;

/** Inter3's shape: doGet -> f1 -> f2 -> f3, and f3 writes its parameter. */
function chain(members: string[]): string {
  return `${HEADER}
public class Chain extends HttpServlet {
    private PrintWriter writer;
${members.join('\n')}
}
`;
}

const DO_GET = `
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        writer = resp.getWriter();
        f1(name);
    }`;
const F1 = `
    private void f1(String name) {
        f2(name);
    }`;
const F2 = `
    private void f2(String name) {
        f3(name);
    }`;
const F3 = `
    private void f3(String name) {
        writer.println(name);       /* BAD */
    }`;
const F3_STUB = `
    private void f3(AtomicLong counter) {
    }`;

/**
 * Findings keyed by what they are, not where: sink type plus the text of the
 * source and sink lines, so two orderings of one file compare equal.
 */
async function flowKeys(code: string): Promise<string[]> {
  const lines = code.split('\n');
  const ir = await analyze(code, 'Chain.java', 'java');
  const keys = ir.taint.flows.map(f =>
    `${f.sink_type}|${(lines[f.source_line - 1] ?? '').trim()}|${(lines[f.sink_line - 1] ?? '').trim()}`);
  return [...new Set(keys)].sort();
}

const BAD = 'writer.println(name);       /* BAD */';

describe('Java call resolution: overloads and method order (C5 F4)', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('control: the chain reports the XSS in f3', async () => {
    const keys = await flowKeys(chain([DO_GET, F1, F2, F3]));
    expect(keys.some(k => k.startsWith('xss|') && k.endsWith(BAD))).toBe(true);
  });

  it('a same-arity overload added BELOW the method keeps the finding (Inter3.f9)', async () => {
    const base = await flowKeys(chain([DO_GET, F1, F2, F3]));
    const below = await flowKeys(chain([DO_GET, F1, F2, F3, F3_STUB]));
    const above = await flowKeys(chain([DO_GET, F1, F2, F3_STUB, F3]));
    expect(below).toEqual(base);
    expect(above).toEqual(base);
  });

  it('a typed argument picks its overload: taint reaches emit(String), not emit(StringBuilder)', async () => {
    const code = `${HEADER}
public class Typed extends HttpServlet {
    private PrintWriter writer;

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        writer = resp.getWriter();
        emit(name);
    }

    private void emit(String s) {
        writer.println(s);          /* BAD: reached with the tainted String */
    }

    private void emit(StringBuilder sb) {
        writer.println(sb);         /* OK: no StringBuilder is ever passed */
    }
}
`;
    const lines = code.split('\n');
    const ir = await analyze(code, 'Typed.java', 'java');
    const sinkTexts = ir.taint.flows.filter(f => f.sink_type === 'xss').map(f => lines[f.sink_line - 1]);
    expect(sinkTexts.some(t => t.includes('writer.println(s);'))).toBe(true);
    expect(sinkTexts.some(t => t.includes('writer.println(sb);'))).toBe(false);
  });

  it('swapping the order of the methods in the file gives identical findings', async () => {
    const forward = await flowKeys(chain([DO_GET, F1, F2, F3]));
    const reversed = await flowKeys(chain([F3, F2, F1, DO_GET]));
    const shuffled = await flowKeys(chain([F2, DO_GET, F3, F1]));
    expect(forward.some(k => k.endsWith(BAD))).toBe(true);
    expect(reversed).toEqual(forward);
    expect(shuffled).toEqual(forward);
  });

  it('moving a helper above its caller keeps the caller\'s escapes (WebGoat VerifyAccount shape)', async () => {
    const controller = `
    @PostMapping(path = "/verify-account")
    @ResponseBody
    public String completed(@RequestParam String userId, HttpServletRequest req) {
        Map<String, String> answers = parseAnswers(req);
        if (helper.verifyAccount(Integer.valueOf(userId), answers)) {
            session.setValue("account-verified-id", userId);
            return "ok";
        }
        return "failed";
    }`;
    const parser = `
    private Map<String, String> parseAnswers(HttpServletRequest req) {
        Map<String, String> answers = new HashMap<>();
        List<String> names = Collections.list(req.getParameterNames());
        for (String name : names) {
            if (name.contains("secQuestion")) {
                answers.put(name, req.getParameter(name));
            }
        }
        return answers;
    }`;
    const file = (members: string[]): string => `package demo;

import java.util.*;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.*;

@RestController
public class VerifyAccount {
    private Helper helper;
    private Session session;
${members.join('\n')}
}
`;
    const callerFirst = await flowKeys(file([controller, parser]));
    const helperFirst = await flowKeys(file([parser, controller]));
    expect(callerFirst.some(k => k.includes('session.setValue('))).toBe(true);
    expect(helperFirst).toEqual(callerFirst);
  });

  it('an ambiguous call is conservative: taint reaches every candidate overload', async () => {
    // `var` with a call initializer has no type we can read, so both
    // one-argument overloads stay candidates.
    const code = `${HEADER}
public class Ambiguous extends HttpServlet {
    private PrintWriter writer;

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        var name = req.getParameter("name");
        writer = resp.getWriter();
        show(name);
    }

    private void show(String s) {
        writer.println(s);          /* candidate 1 */
    }

    private void show(CharSequence cs) {
        writer.println(cs);         /* candidate 2 */
    }
}
`;
    const lines = code.split('\n');
    const ir = await analyze(code, 'Ambiguous.java', 'java');
    const sinkTexts = ir.taint.flows.filter(f => f.sink_type === 'xss').map(f => lines[f.sink_line - 1]);
    expect(sinkTexts.some(t => t.includes('writer.println(s);'))).toBe(true);
    expect(sinkTexts.some(t => t.includes('writer.println(cs);'))).toBe(true);
  });

  it('a call whose arity fits one overload binds to it alone', async () => {
    const code = `${HEADER}
public class Arity extends HttpServlet {
    private PrintWriter writer;

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        writer = resp.getWriter();
        put(name, 1);
    }

    private void put(String s, int n) {
        writer.println(s);          /* BAD */
    }

    private void put(String s) {
        writer.println(s);          /* OK: never called with one argument */
    }
}
`;
    const lines = code.split('\n');
    const ir = await analyze(code, 'Arity.java', 'java');
    const sinkLines = ir.taint.flows.filter(f => f.sink_type === 'xss').map(f => lines[f.sink_line - 1]);
    expect(sinkLines.some(t => t.includes('/* BAD */'))).toBe(true);
    expect(sinkLines.some(t => t.includes('/* OK'))).toBe(false);
  });
});
