/**
 * cognium-dev #566 — a Spring handler that returns markup built from a
 * request parameter is reflected XSS. Same wiring gap as #368: the return
 * is not a call, so the sink has no arguments and needs an explicit flow.
 *
 * `return "index"` and `return msg` stay clean. Those are view names.
 * A return whose only use of the parameter is inside an HTML escaper stays
 * clean too.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const xssFlows = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === 'xss' && !f.sanitized);

const java = (code: string) => analyze(code, 'HelloController.java', 'java');

describe('#566 Java Spring return-XSS', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('flows for return "<p>" + msg on a @GetMapping handler', async () => {
    const r = await java(`
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
public class HelloController {
  @GetMapping("/echo")
  public String echo(@RequestParam String msg) {
    return "<p>" + msg + "</p>";
  }
}
`);
    const flows = xssFlows(r);
    expect(flows.length).toBeGreaterThan(0);
    expect(flows.some(f => f.sink_line === 7)).toBe(true);
  });

  it('a view name stays clean', async () => {
    const r = await java(`
import org.springframework.web.bind.annotation.GetMapping;
public class HelloController {
  @GetMapping("/")
  public String home() {
    return "index";
  }
}
`);
    expect(xssFlows(r)).toHaveLength(0);
  });

  it('return msg without markup stays clean', async () => {
    const r = await java(`
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
public class HelloController {
  @GetMapping("/echo")
  public String echo(@RequestParam String msg) {
    return msg;
  }
}
`);
    expect(xssFlows(r)).toHaveLength(0);
  });

  it('an HTML escaper around the parameter stays clean', async () => {
    const r = await java(`
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.apache.commons.text.StringEscapeUtils;
public class HelloController {
  @GetMapping("/echo")
  public String echo(@RequestParam String msg) {
    return "<p>" + StringEscapeUtils.escapeHtml4(msg) + "</p>";
  }
}
`);
    expect(xssFlows(r)).toHaveLength(0);
  });
});
