/**
 * cognium-dev #566 — a Spring handler that returns markup built from a
 * request parameter is reflected XSS when the handler writes the response
 * body (`@RestController` or `@ResponseBody`). The `<` must sit inside a
 * string literal of the return, and the flow is the parameter named there.
 *
 * A plain `@Controller` return is a view name. Numeric and boolean
 * parameters are not markup. `return "index"` and `return msg` stay clean.
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

  it('flows for return "<p>" + msg on a @RestController handler', async () => {
    const r = await java(`
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
@RestController
public class HelloController {
  @GetMapping("/echo")
  public String echo(@RequestParam String other, @RequestParam String msg) {
    return "<p>" + msg + "</p>";
  }
}
`);
    const flows = xssFlows(r);
    expect(flows.length).toBeGreaterThan(0);
    expect(flows.every(f => f.path[0]?.variable === 'msg')).toBe(true);
    expect(flows.some(f => f.path.some(p => p.variable === 'other'))).toBe(false);
  });

  it('flows for a method-level @ResponseBody handler', async () => {
    const r = await java(`
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
@Controller
public class HelloController {
  @GetMapping("/echo")
  @ResponseBody
  public String echo(@RequestParam String msg) {
    return "<p>" + msg + "</p>";
  }
}
`);
    const flows = xssFlows(r);
    expect(flows.length).toBeGreaterThan(0);
    expect(flows.every(f => f.path[0]?.variable === 'msg')).toBe(true);
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
import org.springframework.web.bind.annotation.RestController;
@RestController
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
import org.springframework.web.bind.annotation.RestController;
import org.apache.commons.text.StringEscapeUtils;
@RestController
public class HelloController {
  @GetMapping("/echo")
  public String echo(@RequestParam String msg) {
    return "<p>" + StringEscapeUtils.escapeHtml4(msg) + "</p>";
  }
}
`);
    expect(xssFlows(r)).toHaveLength(0);
  });

  it('ResponseEntity of a request body stays clean', async () => {
    const r = await java(`
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
@RestController
public class HelloController {
  @PostMapping("/users")
  public ResponseEntity<User> create(@RequestBody User user) {
    return new ResponseEntity<>(user, HttpStatus.OK);
  }
}
`);
    expect(xssFlows(r)).toHaveLength(0);
  });

  it('a comparison inside a string-less ternary stays clean', async () => {
    const r = await java(`
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
@RestController
public class HelloController {
  @GetMapping("/page")
  public String page(@RequestParam int page) {
    return page < 1 ? "first" : "later";
  }
}
`);
    expect(xssFlows(r)).toHaveLength(0);
  });

  it('a comparison inside a stream filter stays clean', async () => {
    const r = await java(`
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import java.util.List;
@RestController
public class HelloController {
  @GetMapping("/count")
  public long count(@RequestParam int max, List<Integer> xs) {
    return xs.stream().filter(x -> x < max).count();
  }
}
`);
    expect(xssFlows(r)).toHaveLength(0);
  });

  it('markup built from a numeric path variable stays clean', async () => {
    const r = await java(`
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
@RestController
public class HelloController {
  @GetMapping("/items/{id}")
  public String item(@PathVariable int id) {
    return "<p>" + id + "</p>";
  }
}
`);
    expect(xssFlows(r)).toHaveLength(0);
  });

  it('a plain @Controller view return stays clean', async () => {
    const r = await java(`
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
@Controller
public class HelloController {
  @GetMapping("/echo")
  public String echo(@RequestParam String msg) {
    return "<p>" + msg + "</p>";
  }
}
`);
    expect(xssFlows(r)).toHaveLength(0);
  });
});
