/**
 * Template-engine sinks are reported as `template_injection` (CWE-1336).
 *
 * A request value used as the source text of a template (Go `text/template`
 * and `html/template`, Jinja2, Mako, Django, Flask `render_template_string`,
 * Handlebars, EJS, Pug, Nunjucks, doT, Velocity, FreeMarker) is template
 * injection. Eval-style sinks (`eval`, `new Function`, `ScriptEngine.eval`)
 * stay `code_injection` (CWE-94). A fixed template that receives the value as
 * data is not a finding.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze, analyzeProject } from '../../src/analyzer.js';
import { reportTemplateInjection, ruleSinkType } from '../../src/analysis/template-injection.js';
import { sanitizerCoversSink } from '../../src/analysis/sanitizer-index.js';
import { canSourceReachSink } from '../../src/analysis/findings.js';
import type { SupportedLanguage, TaintFlowInfo, TaintSink } from '../../src/types/index.js';

type IR = Awaited<ReturnType<typeof analyze>>;

const flowLines = (ir: IR, type: string): number[] =>
  [...new Set((ir.taint.flows ?? []).filter(f => f.sink_type === type).map(f => f.sink_line))].sort((a, b) => a - b);

async function scan(code: string, file: string, language: SupportedLanguage): Promise<IR> {
  return analyze(code, file, language);
}

describe('template_injection: sinks that compile request text', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it.each([
    ['text/template'],
    ['html/template'],
  ])('Go %s: Parse(request value) is template_injection, CWE-1336', async (pkg) => {
    const ir = await scan([
      'package main',
      `import ("net/http"; "${pkg}")`,
      'func preview(w http.ResponseWriter, r *http.Request) {',
      '\tsrc := r.URL.Query().Get("t")',
      '\tt, _ := template.New("p").Parse(src)',
      '\tt.Execute(w, nil)',
      '}',
    ].join('\n'), 'preview.go', 'go');
    expect(flowLines(ir, 'template_injection')).toEqual([5]);
    expect(flowLines(ir, 'code_injection')).toEqual([]);
    expect(ir.taint.sinks.find(s => s.line === 5)?.cwe).toBe('CWE-1336');
  });

  it('Go: a fixed template that renders the request value as data is not template injection', async () => {
    const ir = await scan([
      'package main',
      'import ("net/http"; "text/template")',
      'func greet(w http.ResponseWriter, r *http.Request) {',
      '\tname := r.URL.Query().Get("name")',
      '\tt, _ := template.New("p").Parse("Hello {{.}}")',
      '\tt.Execute(w, name)',
      '}',
    ].join('\n'), 'greet.go', 'go');
    expect(flowLines(ir, 'template_injection')).toEqual([]);
  });

  it('Python: Jinja2, Mako, Django and render_template_string templates built from request text', async () => {
    const ir = await scan([
      'from flask import Flask, request, render_template_string',   // 1
      'import jinja2',                                                // 2
      'from jinja2 import Environment',                               // 3
      'app = Flask(__name__)',                                        // 4
      "@app.route('/a')",                                             // 5
      'def a():',                                                     // 6
      "    a_src = request.args.get('t')",                            // 7
      '    return jinja2.Template(a_src).render()',                   // 8
      "@app.route('/b')",                                             // 9
      'def b():',                                                     // 10
      "    b_src = request.args.get('t')",                            // 11
      '    return Environment().from_string(b_src).render()',         // 12
      "@app.route('/c')",                                             // 13
      'def c():',                                                     // 14
      "    c_src = request.args.get('t')",                            // 15
      '    return render_template_string(c_src)',                     // 16
    ].join('\n'), 'app.py', 'python');
    expect(flowLines(ir, 'template_injection')).toEqual([8, 12, 16]);
    expect(flowLines(ir, 'code_injection')).toEqual([]);
  });

  it('Python: Mako and Django Template classes imported by name', async () => {
    const mako = await scan([
      'from flask import request',
      'from mako.template import Template',
      'def page():',
      "    src = request.args.get('t')",
      '    return Template(src).render()',
    ].join('\n'), 'mako_page.py', 'python');
    expect(flowLines(mako, 'template_injection')).toEqual([5]);
    const django = await scan([
      'from flask import request',
      'from django.template import Template, Context',
      'def page():',
      "    src = request.args.get('t')",
      '    return Template(src).render(Context({}))',
    ].join('\n'), 'django_page.py', 'python');
    expect(flowLines(django, 'template_injection')).toEqual([5]);
  });

  it('Python: fixed templates, string.Template and eval are not template injection', async () => {
    const ir = await scan([
      'from flask import request, render_template_string',            // 1
      'from jinja2 import Environment',                               // 2
      'from django.template import Template, Context',                // 3
      'import string',                                                // 4
      'def a():',                                                     // 5
      "    name = request.args.get('name')",                          // 6
      "    return render_template_string('<p>{{ n }}</p>', n=name)",  // 7
      'def b():',                                                     // 8
      "    name = request.args.get('name')",                          // 9
      "    return Environment().from_string('<p>{{ n }}</p>').render(n=name)", // 10
      'def c():',                                                     // 11
      "    name = request.args.get('name')",                          // 12
      "    return Template('<p>{{ n }}</p>').render(Context({'n': name}))", // 13
      'def d():',                                                     // 14
      "    text = request.args.get('t')",                             // 15
      '    return string.Template(text).substitute(a=1)',             // 16
      'def e():',                                                     // 17
      "    code = request.args.get('x')",                             // 18
      '    return str(eval(code))',                                   // 19
    ].join('\n'), 'safe.py', 'python');
    expect(flowLines(ir, 'template_injection')).toEqual([]);
    expect(flowLines(ir, 'code_injection')).toEqual([19]);
    expect(ir.taint.sinks.find(s => s.line === 19 && s.type === 'code_injection')?.cwe).toBe('CWE-94');
  });

  it('JavaScript: Handlebars, EJS, Pug, Nunjucks and doT compile request text; eval and new Function stay code injection', async () => {
    const ir = await scan([
      "const express = require('express');",                                                  // 1
      "const ejs = require('ejs');",                                                          // 2
      "const pug = require('pug');",                                                          // 3
      "const nunjucks = require('nunjucks');",                                                // 4
      "const Handlebars = require('handlebars');",                                            // 5
      "const doT = require('dot');",                                                          // 6
      'const app = express();',                                                               // 7
      "app.get('/a', (req, res) => { res.send(Handlebars.compile(req.query.t)({})); });",     // 8
      "app.get('/b', (req, res) => { res.send(ejs.render(req.query.t, {})); });",             // 9
      "app.get('/c', (req, res) => { res.send(ejs.compile(req.query.t)({})); });",            // 10
      "app.get('/d', (req, res) => { res.send(pug.render(req.query.t)); });",                 // 11
      "app.get('/e', (req, res) => { res.send(pug.compile(req.query.t)()); });",              // 12
      "app.get('/f', (req, res) => { res.send(nunjucks.renderString(req.query.t, {})); });",  // 13
      "app.get('/g', (req, res) => { res.send(doT.template(req.query.t)({})); });",           // 14
      "app.get('/h', (req, res) => { res.send(String(eval(req.query.code))); });",            // 15
      "app.get('/k', (req, res) => { res.send(new Function(req.query.code)()); });",          // 16
    ].join('\n'), 'app.js', 'javascript');
    expect(flowLines(ir, 'template_injection')).toEqual([8, 9, 10, 11, 12, 13, 14]);
    expect(flowLines(ir, 'code_injection')).toEqual([15, 16]);
  });

  it('JavaScript: fixed EJS and doT templates given the request value as data are not template injection', async () => {
    const ir = await scan([
      "const express = require('express');",
      "const ejs = require('ejs');",
      "const doT = require('dot');",
      'const app = express();',
      "app.get('/i', (req, res) => { res.send(ejs.render('<p><%= name %></p>', { name: req.query.n })); });",
      "app.get('/j', (req, res) => { res.send(doT.template('<p>{{=it.name}}</p>')({ name: req.query.n })); });",
    ].join('\n'), 'safe.js', 'javascript');
    expect(flowLines(ir, 'template_injection')).toEqual([]);
    expect(flowLines(ir, 'code_injection')).toEqual([]);
  });

  it('Java: Velocity.evaluate and FreeMarker new Template(name, reader, cfg) over request text', async () => {
    const ir = await scan([
      'import java.io.StringReader;',                                                     // 1
      'import java.io.StringWriter;',                                                     // 2
      'import javax.servlet.http.HttpServletRequest;',                                    // 3
      'import org.apache.velocity.app.Velocity;',                                         // 4
      'import org.apache.velocity.VelocityContext;',                                      // 5
      'import freemarker.template.Configuration;',                                        // 6
      'import freemarker.template.Template;',                                             // 7
      'public class Preview {',                                                           // 8
      '    public void velocity(HttpServletRequest request) throws Exception {',          // 9
      '        String src = request.getParameter("t");',                                  // 10
      '        Velocity.evaluate(new VelocityContext(), new StringWriter(), "tag", src);', // 11
      '    }',                                                                            // 12
      '    public void freemarker(HttpServletRequest request, Configuration cfg) throws Exception {', // 13
      '        String src = request.getParameter("t");',                                  // 14
      '        Template t = new Template("name", new StringReader(src), cfg);',          // 15
      '    }',                                                                            // 16
      '}',
    ].join('\n'), 'Preview.java', 'java');
    expect(flowLines(ir, 'template_injection')).toEqual([11, 15]);
    expect(flowLines(ir, 'code_injection')).toEqual([]);
  });

  it('Java: fixed Velocity and FreeMarker templates are not template injection', async () => {
    const ir = await scan([
      'import java.io.StringReader;',
      'import java.io.StringWriter;',
      'import javax.servlet.http.HttpServletRequest;',
      'import org.apache.velocity.app.Velocity;',
      'import org.apache.velocity.VelocityContext;',
      'import freemarker.template.Configuration;',
      'import freemarker.template.Template;',
      'public class Fixed {',
      '    public void velocity(HttpServletRequest request) throws Exception {',
      '        String name = request.getParameter("name");',
      '        VelocityContext ctx = new VelocityContext();',
      '        ctx.put("name", name);',
      '        Velocity.evaluate(ctx, new StringWriter(), "tag", "Hello $name");',
      '    }',
      '    public void freemarker(HttpServletRequest request, Configuration cfg) throws Exception {',
      '        Template t = new Template("name", new StringReader("Hello ${name}"), cfg);',
      '    }',
      '}',
    ].join('\n'), 'Fixed.java', 'java');
    expect(flowLines(ir, 'template_injection')).toEqual([]);
  });

  it('a cross-file path into a template sink carries the template type and CWE-1336', async () => {
    const r = await analyzeProject([
      {
        filePath: 'handler.go', language: 'go', code: [
          'package main',
          'import "net/http"',
          'func preview(w http.ResponseWriter, r *http.Request) {',
          '\tsrc := r.URL.Query().Get("t")',
          '\trender(w, src)',
          '}',
        ].join('\n'),
      },
      {
        filePath: 'render.go', language: 'go', code: [
          'package main',
          'import ("net/http"; "text/template")',
          'func render(w http.ResponseWriter, src string) {',
          '\tt, _ := template.New("p").Parse(src)',
          '\tt.Execute(w, nil)',
          '}',
        ].join('\n'),
      },
    ]);
    const path = r.taint_paths.find(p => p.sink.file === 'render.go');
    expect(path?.sink).toMatchObject({ type: 'template_injection', cwe: 'CWE-1336', line: 4 });
  });
});

describe('template_injection follows the code-injection rules', () => {
  const sink = (line: number, cwe: string): TaintSink => ({ type: 'code_injection', cwe, location: '', line, confidence: 1 });
  const flow = (line: number): TaintFlowInfo => ({
    source_line: 1, sink_line: line, source_type: 'http_param', sink_type: 'code_injection', path: [], confidence: 1, sanitized: false,
  });

  it('retypes template sinks and their flows; a line that also has an eval-style sink keeps code_injection', () => {
    const taint = { sinks: [sink(3, 'CWE-1336'), sink(5, 'CWE-1336'), sink(5, 'CWE-94'), sink(7, 'CWE-94')], flows: [flow(3), flow(5), flow(7)] };
    reportTemplateInjection(taint);
    expect(taint.sinks.map(s => s.type)).toEqual(['template_injection', 'template_injection', 'code_injection', 'code_injection']);
    expect(taint.flows.map(f => f.sink_type)).toEqual(['template_injection', 'code_injection', 'code_injection']);
  });

  it('is reached by the same sources and cleared by the same sanitizers as code injection', () => {
    expect(ruleSinkType('template_injection')).toBe('code_injection');
    expect(ruleSinkType('xss')).toBe('xss');
    expect(canSourceReachSink('http_param', 'template_injection')).toBe(true);
    expect(canSourceReachSink('db_input', 'template_injection')).toBe(false);
    const parseInt = { type: 'number', method: 'parseInt', line: 1, sanitizes: ['sql_injection', 'code_injection'] } as Parameters<typeof sanitizerCoversSink>[0];
    expect(sanitizerCoversSink(parseInt, 'template_injection')).toBe(true);
    const htmlEscape = { type: 'html', method: 'escapeHtml', line: 1, sanitizes: ['xss'] } as Parameters<typeof sanitizerCoversSink>[0];
    expect(sanitizerCoversSink(htmlEscape, 'template_injection')).toBe(false);
  });
});
