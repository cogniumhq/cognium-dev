/**
 * #468 (slice) — a tainted value passed to a JDK exception constructor is not
 * an `external_taint_escape`. Building an exception sends the value nowhere.
 * Java counterpart of the error-construction row of the Go gate (#455) and the
 * C# gate (#474). Project-defined exception classes, unresolved library
 * receivers and classical sinks are unchanged.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const escapeLines = (ir: Awaited<ReturnType<typeof analyze>>): number[] =>
  (ir.taint.flows ?? [])
    .filter(f => f.sink_type === 'external_taint_escape')
    .map(f => f.sink_line)
    .sort((a, b) => a - b);

const ORDER = `import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import com.acme.queue.OrderQueue;

public class OrderValidator extends HttpServlet {
    private OrderQueue queue;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String qty = request.getParameter("qty");
        if (qty == null || qty.isEmpty()) {
            throw new IllegalArgumentException("bad qty: " + qty);
        }
        if (qty.length() > 6) {
            throw new IllegalStateException(qty);
        }
        queue.publish(qty);
    }
}
`;

describe('#468 Java: JDK exception construction is not an external_taint_escape', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('reports the escape at the publish call only, not at the exception constructors', async () => {
    const ir = await analyze(ORDER, 'OrderValidator.java', 'java');
    expect(escapeLines(ir)).toEqual([19]);
  });

  it('covers the explicit java.lang set and fully-qualified java.lang names', async () => {
    const names = [
      'RuntimeException', 'UnsupportedOperationException', 'NullPointerException',
      'IndexOutOfBoundsException', 'NumberFormatException', 'AssertionError', 'Error',
      'Exception', 'java.lang.ArithmeticException',
    ];
    for (const n of names) {
      const code = `import javax.servlet.http.HttpServletRequest;
public class Q {
    void run(HttpServletRequest request) {
        String v = request.getParameter("v");
        throw new ${n}(v);
    }
}
`;
      const ir = await analyze(code, 'Q.java', 'java');
      expect(escapeLines(ir), n).toEqual([]);
    }
  });

  it('keeps a project exception class imported from another package escaping, even when it shadows a java.lang name', async () => {
    for (const n of ['OrderRejectedException', 'IllegalStateException']) {
      const code = `import javax.servlet.http.HttpServletRequest;
import com.acme.errors.${n};
public class Q {
    void run(HttpServletRequest request) {
        String v = request.getParameter("v");
        throw new ${n}(v);
    }
}
`;
      const ir = await analyze(code, 'Q.java', 'java');
      expect(escapeLines(ir), n).toEqual([6]);
    }
  });

  it('keeps an unresolved library constructor escaping', async () => {
    const code = `import javax.servlet.http.HttpServletRequest;
import com.acme.audit.AuditEvent;
public class Q {
    void run(HttpServletRequest request) {
        String v = request.getParameter("v");
        new AuditEvent(v);
    }
}
`;
    const ir = await analyze(code, 'Q.java', 'java');
    expect(escapeLines(ir)).toEqual([6]);
  });

  it('does not change classical sinks: a tainted exception message written to the response still reports xss', async () => {
    const code = `import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
public class Q extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String v = request.getParameter("v");
        try {
            throw new IllegalArgumentException(v);
        } catch (IllegalArgumentException e) {
            response.getWriter().println(v);
        }
    }
}
`;
    const ir = await analyze(code, 'Q.java', 'java');
    expect((ir.taint.flows ?? []).some(f => f.sink_type === 'xss')).toBe(true);
    expect(escapeLines(ir)).toEqual([]);
  });
});
