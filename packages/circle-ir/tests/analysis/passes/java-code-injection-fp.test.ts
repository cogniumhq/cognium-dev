/**
 * Tests for cognium-dev #155 + #156 + #159 + #160 — Java
 * `code_injection` (CWE-094) Stage 9 FP suppression.
 *
 * Sprint 42 adds a new Stage 9 to `sink-filter-pass.ts`, scoped to
 * `language === 'java'` AND `sink.type === 'code_injection'`. Four
 * sub-stages:
 *
 *   9a (#155): non-script data parsers (commonmark Parser, hutool
 *              DateParser, zxing ResultParser, SimpleDateFormat,
 *              CLI arg parsers, …). Suppressed when the receiver
 *              variable's declared type matches `DATA_PARSER_TYPES`.
 *
 *   9b (#156): compiled-template render / process / merge / renderTo.
 *              Risk lives at the compile step (`getTemplate(tainted)`),
 *              not at the render step. Suppressed when the receiver
 *              variable's declared type matches
 *              `COMPILED_TEMPLATE_TYPES`.
 *
 *   9c (#159): reflection / SpEL with literal / annotation-accessor
 *              first arg (Class.forName("Foo"),
 *              parseExpression("#root"), method.invoke(target), …).
 *              Suppressed when first arg is a string literal, an
 *              annotation accessor (ann.value() / ann.name() /
 *              ann.key()), or empty.
 *
 *   9d (#160): no-arg Constructor#newInstance(). Empty arg list
 *              means the constructor was statically resolved.
 *
 * Recall lock: any code_injection sink whose receiver type or arg
 * shape doesn't match one of the four known-safe shapes continues to
 * fire. Tainted `Class.forName(userInput)`,
 * `spel.parseExpression(userInput)`, and the compile-step
 * `engine.getTemplate(tainted)` remain detected.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const countCodeInjectionSinks = (
  sinks: Array<{ type?: string }> | undefined,
) => (sinks ?? []).filter((s) => s.type === 'code_injection').length;

describe('cognium-dev #155 + #156 + #159 + #160 — Java code_injection Stage 9 FP suppression', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // -------------------------------------------------------------------------
  // 9a — #155: non-script data parsers
  // -------------------------------------------------------------------------

  it('FP #155 — commonmark Parser.parse(md): no code_injection sink', async () => {
    const code = `import org.commonmark.parser.Parser;
import org.commonmark.node.Node;

public class MarkdownService {
  public Node render(String md) {
    Parser parser = Parser.builder().build();
    Node node = parser.parse(md);
    return node;
  }
}
`;
    const r = await analyze(code, 'MarkdownService.java', 'java');
    expect(countCodeInjectionSinks(r.taint?.sinks)).toBe(0);
  });

  it('FP #155 — SimpleDateFormat.parse(input): no code_injection sink', async () => {
    const code = `import java.text.SimpleDateFormat;
import java.util.Date;

public class DateService {
  public Date parseDate(String input) throws Exception {
    SimpleDateFormat fmt = new SimpleDateFormat("yyyy-MM-dd");
    Date d = fmt.parse(input);
    return d;
  }
}
`;
    const r = await analyze(code, 'DateService.java', 'java');
    expect(countCodeInjectionSinks(r.taint?.sinks)).toBe(0);
  });

  it('FP #155 — zxing ResultParser.parseResult(barcode): no code_injection sink', async () => {
    const code = `import com.google.zxing.client.result.ResultParser;
import com.google.zxing.client.result.ParsedResult;
import com.google.zxing.Result;

public class BarcodeService {
  public ParsedResult decode(Result barcode) {
    ResultParser p = new ResultParser();
    ParsedResult r = p.parseResult(barcode);
    return r;
  }
}
`;
    const r = await analyze(code, 'BarcodeService.java', 'java');
    expect(countCodeInjectionSinks(r.taint?.sinks)).toBe(0);
  });

  // -------------------------------------------------------------------------
  // 9b — #156: compiled-template render / process
  // -------------------------------------------------------------------------

  it('FP #156 — Freemarker Template.process(model, writer): no code_injection sink', async () => {
    const code = `import freemarker.template.Template;
import freemarker.template.Configuration;
import java.io.Writer;
import java.util.Map;

public class FreemarkerService {
  public void render(Configuration cfg, Map<String,Object> model, Writer writer) throws Exception {
    Template tpl = cfg.getTemplate("hello.ftl");
    tpl.process(model, writer);
  }
}
`;
    const r = await analyze(code, 'FreemarkerService.java', 'java');
    expect(countCodeInjectionSinks(r.taint?.sinks)).toBe(0);
  });

  it('FP #156 — Jetbrick JetTemplate.render(model): no code_injection sink', async () => {
    const code = `import jetbrick.template.JetTemplate;
import jetbrick.template.JetEngine;
import java.util.Map;

public class JetbrickService {
  public String render(JetEngine engine, Map<String,Object> model) {
    JetTemplate t = engine.getTemplate("a.jetx");
    return t.render(model);
  }
}
`;
    const r = await analyze(code, 'JetbrickService.java', 'java');
    expect(countCodeInjectionSinks(r.taint?.sinks)).toBe(0);
  });

  // -------------------------------------------------------------------------
  // 9c — #159: reflection / SpEL with literal / annotation arg
  // -------------------------------------------------------------------------

  it('FP #159 — Class.forName("literal"): no code_injection sink', async () => {
    const code = `public class ReflectionService {
  public Class<?> load() throws Exception {
    Class<?> c = Class.forName("com.example.Foo");
    return c;
  }
}
`;
    const r = await analyze(code, 'ReflectionService.java', 'java');
    expect(countCodeInjectionSinks(r.taint?.sinks)).toBe(0);
  });

  it('FP #159 — Class.forName(annotation.value()): no code_injection sink', async () => {
    const code = `import java.lang.annotation.Annotation;

public class AnnotationLoader {
  public Class<?> load(MyAnn ann) throws Exception {
    Class<?> c = Class.forName(ann.value());
    return c;
  }
}
`;
    const r = await analyze(code, 'AnnotationLoader.java', 'java');
    expect(countCodeInjectionSinks(r.taint?.sinks)).toBe(0);
  });

  // -------------------------------------------------------------------------
  // 9d — #160: no-arg Constructor#newInstance()
  // -------------------------------------------------------------------------

  it('FP #160 — Constructor.newInstance() no args: no code_injection sink', async () => {
    const code = `public class FactoryService {
  public Object make() throws Exception {
    Class<?> c = Class.forName("com.example.X");
    Object o = c.getConstructor().newInstance();
    return o;
  }
}
`;
    const r = await analyze(code, 'FactoryService.java', 'java');
    expect(countCodeInjectionSinks(r.taint?.sinks)).toBe(0);
  });

  // -------------------------------------------------------------------------
  // Recall locks — sinks that MUST continue to fire
  // -------------------------------------------------------------------------

  it('Recall — Class.forName(userInput): code_injection sink fires', async () => {
    const code = `import javax.servlet.http.HttpServletRequest;

public class DangerousReflection {
  public Class<?> load(HttpServletRequest req) throws Exception {
    String name = req.getParameter("cls");
    Class<?> c = Class.forName(name);
    return c;
  }
}
`;
    const r = await analyze(code, 'DangerousReflection.java', 'java');
    expect(countCodeInjectionSinks(r.taint?.sinks)).toBeGreaterThanOrEqual(1);
  });

  it('Recall — SpelExpressionParser.parseExpression(userInput): code_injection sink fires', async () => {
    const code = `import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.Expression;
import javax.servlet.http.HttpServletRequest;

public class DangerousSpel {
  public Object eval(HttpServletRequest req) {
    String expr = req.getParameter("expr");
    SpelExpressionParser spel = new SpelExpressionParser();
    Expression e = spel.parseExpression(expr);
    return e.getValue();
  }
}
`;
    const r = await analyze(code, 'DangerousSpel.java', 'java');
    expect(countCodeInjectionSinks(r.taint?.sinks)).toBeGreaterThanOrEqual(1);
  });

  it('Recall — engine.getTemplate(tainted) compile step: code_injection sink fires', async () => {
    const code = `import freemarker.template.Configuration;
import freemarker.template.Template;
import javax.servlet.http.HttpServletRequest;

public class DangerousCompile {
  public Template load(Configuration cfg, HttpServletRequest req) throws Exception {
    String s = req.getParameter("t");
    Template t = cfg.getTemplate(s);
    return t;
  }
}
`;
    const r = await analyze(code, 'DangerousCompile.java', 'java');
    expect(countCodeInjectionSinks(r.taint?.sinks)).toBeGreaterThanOrEqual(1);
  });

  it('Regression — GroovyShell.parse(userInput) existing real sink shape: code_injection sink fires', async () => {
    const code = `import groovy.lang.GroovyShell;
import javax.servlet.http.HttpServletRequest;

public class DangerousGroovy {
  public Object run(HttpServletRequest req) {
    String script = req.getParameter("script");
    GroovyShell shell = new GroovyShell();
    return shell.parse(script).run();
  }
}
`;
    const r = await analyze(code, 'DangerousGroovy.java', 'java');
    expect(countCodeInjectionSinks(r.taint?.sinks)).toBeGreaterThanOrEqual(1);
  });
});
