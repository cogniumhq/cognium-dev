/**
 * Java heap-field sources and strong updates (SecuriBench StrongUpdates3 shape).
 *
 * `w.value = name; w.value = "abc";` overwrites the only object's field with a
 * constant before the read, so the read is clean. A write that only might run
 * (one branch) or that goes through another reference keeps the taint.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const header = `
package demo.updates;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Holder {
    class Box {
        String value = null;
    }
`;

const STRONG_UPDATE = `${header}
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        Box b = new Box();
        b.value = name;
        b.value = "abc";

        PrintWriter writer = resp.getWriter();
        writer.println(b.value); /* OK */
    }
}
`;

const BRANCH_WRITE = `${header}
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        Box b = new Box();
        b.value = name;
        if (name.length() > 3) {
            b.value = "abc";
        }

        PrintWriter writer = resp.getWriter();
        writer.println(b.value); /* BAD */
    }
}
`;

const ALIAS_WRITE = `${header}
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        Box b = new Box();
        Box other = new Box();
        Box pick = name.isEmpty() ? b : other;
        b.value = name;
        pick.value = "abc";

        PrintWriter writer = resp.getWriter();
        writer.println(b.value); /* BAD */
    }
}
`;

const READ_BEFORE_KILL = `${header}
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        Box b = new Box();
        b.value = name;
        PrintWriter writer = resp.getWriter();
        writer.println(b.value); /* BAD */
        b.value = "abc";
        writer.println(b.value); /* OK */
    }
}
`;

const RETAINT_AFTER_KILL = `${header}
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        Box b = new Box();
        b.value = name;
        b.value = "abc";
        b.value = name;

        PrintWriter writer = resp.getWriter();
        writer.println(b.value); /* BAD */
    }
}
`;

const TRY_DIVISION = `${header}
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        int n = name.length() - 3;
        Box b = new Box();
        PrintWriter writer = resp.getWriter();
        try {
            b.value = name;
            int z = 10 / n;
            b.value = "abc";
        } catch (ArithmeticException e) {
            writer.println(b.value); /* BAD */
        }
    }
}
`;

const TRY_ARRAY = `${header}
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        String[] parts = name.split(",");
        Box b = new Box();
        PrintWriter writer = resp.getWriter();
        try {
            b.value = name;
            String second = parts[1];
            b.value = "abc";
        } catch (ArrayIndexOutOfBoundsException e) {
            writer.println(b.value); /* BAD */
        }
    }
}
`;

const TRY_READ_AFTER = `${header}
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        int n = name.length() - 3;
        Box b = new Box();
        try {
            b.value = name;
            int z = 10 / n;
            b.value = "abc";
        } catch (ArithmeticException e) {
        }
        PrintWriter writer = resp.getWriter();
        writer.println(b.value); /* BAD */
    }
}
`;

const TRY_NO_THROW = `${header}
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        Box b = new Box();
        PrintWriter writer = resp.getWriter();
        try {
            b.value = name;
            int z = 10;
            b.value = "abc";
        } catch (RuntimeException e) {
            writer.println(b.value); /* OK */
        }
    }
}
`;

const SAME_LINE_READ = `${header}
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        Box b = new Box();
        PrintWriter writer = resp.getWriter();
        /* BAD: the read on the next line comes before the constant write */
        b.value = name; writer.println(b.value);
        b.value = "abc";
    }
}
`;

const COMPOUND_AFTER_KILL = `${header}
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        Box b = new Box();
        b.value = name;
        b.value = "abc";
        b.value += name;

        PrintWriter writer = resp.getWriter();
        writer.println(b.value); /* BAD */
    }
}
`;

const SETTER_AFTER_KILL = `
package demo.updates;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Holder {
    class Box {
        String value = null;
        void setValue(String v) {
            value = v;
        }
    }

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        Box b = new Box();
        b.value = name;
        b.value = "abc";
        b.setValue(name);

        PrintWriter writer = resp.getWriter();
        writer.println(b.value); /* BAD */
    }
}
`;

function xssSinkLines(r: Awaited<ReturnType<typeof analyze>>): Set<number> {
  const flows = (r.taint?.flows ?? []).filter(f => f.sink_type === 'xss' && !f.sanitized);
  return new Set(flows.map(f => f.sink_line));
}

function lineOf(code: string, needle: string, from = 0): number {
  const lines = code.split('\n');
  for (let i = from; i < lines.length; i++) {
    if (lines[i].includes(needle)) return i + 1;
  }
  throw new Error(`not found: ${needle}`);
}

describe('Java heap field strong update', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('a later constant write to the same field kills the taint (no flow)', async () => {
    const r = await analyze(STRONG_UPDATE, 'Holder.java', 'java');
    expect(xssSinkLines(r).size).toBe(0);
  });

  it('a write in one branch only is a weak update: the read stays tainted', async () => {
    const r = await analyze(BRANCH_WRITE, 'Holder.java', 'java');
    expect(xssSinkLines(r).has(lineOf(BRANCH_WRITE, 'println(b.value)'))).toBe(true);
  });

  it('a write through another reference keeps the taint', async () => {
    const r = await analyze(ALIAS_WRITE, 'Holder.java', 'java');
    expect(xssSinkLines(r).has(lineOf(ALIAS_WRITE, 'println(b.value)'))).toBe(true);
  });

  it('a read before the constant write stays tainted', async () => {
    const r = await analyze(READ_BEFORE_KILL, 'Holder.java', 'java');
    expect(xssSinkLines(r).has(lineOf(READ_BEFORE_KILL, 'println(b.value)'))).toBe(true);
  });

  it('a tainted write after the constant write keeps the taint', async () => {
    const r = await analyze(RETAINT_AFTER_KILL, 'Holder.java', 'java');
    expect(xssSinkLines(r).has(lineOf(RETAINT_AFTER_KILL, 'println(b.value)'))).toBe(true);
  });

  it('a division between the writes in a try keeps the taint for the catch', async () => {
    const r = await analyze(TRY_DIVISION, 'Holder.java', 'java');
    expect(xssSinkLines(r).has(lineOf(TRY_DIVISION, 'println(b.value)'))).toBe(true);
  });

  it('an array access between the writes in a try keeps the taint for the catch', async () => {
    const r = await analyze(TRY_ARRAY, 'Holder.java', 'java');
    expect(xssSinkLines(r).has(lineOf(TRY_ARRAY, 'println(b.value)'))).toBe(true);
  });

  it('a read after a try whose catch swallows the exception stays tainted', async () => {
    const r = await analyze(TRY_READ_AFTER, 'Holder.java', 'java');
    expect(xssSinkLines(r).has(lineOf(TRY_READ_AFTER, 'println(b.value)'))).toBe(true);
  });

  it('only a literal local assignment between the writes in a try still kills the taint', async () => {
    const r = await analyze(TRY_NO_THROW, 'Holder.java', 'java');
    expect(xssSinkLines(r).size).toBe(0);
  });

  it('a read on the same line as the tainted write stays tainted', async () => {
    const r = await analyze(SAME_LINE_READ, 'Holder.java', 'java');
    expect(xssSinkLines(r).has(lineOf(SAME_LINE_READ, 'println(b.value)'))).toBe(true);
  });

  it('a compound assignment of tainted data after the constant write keeps the taint', async () => {
    const r = await analyze(COMPOUND_AFTER_KILL, 'Holder.java', 'java');
    expect(xssSinkLines(r).has(lineOf(COMPOUND_AFTER_KILL, 'println(b.value)'))).toBe(true);
  });

  it('a method call on the receiver after the constant write keeps the taint', async () => {
    const r = await analyze(SETTER_AFTER_KILL, 'Holder.java', 'java');
    expect(xssSinkLines(r).has(lineOf(SETTER_AFTER_KILL, 'println(b.value)'))).toBe(true);
  });
});
