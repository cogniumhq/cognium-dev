import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/index.js';

/**
 * cognium-dev #219 — FP: Jinja Environment autoescape safe mirror fires
 * template_injection / XSS.
 *
 * IL-01 shape: `Environment(autoescape=True).get_template(...).render(user=tainted)`.
 * Autoescape=True (or select_autoescape) causes Jinja to HTML-escape all
 * context values at render time, so tainted context is not user-controlled
 * HTML. The corresponding `Environment()` default (autoescape is off by
 * default in raw Environment — Flask's render_template wraps it with
 * escaping) and `Environment(autoescape=False)` SHOULD still fire.
 *
 * Fix: taint-matcher.ts — extend `isSafeJinjaRenderCall` Case D with a
 * whole-file text scan for `Environment(autoescape=True|select_autoescape)`
 * gated by absence of `Environment(autoescape=False)`. Shipped 3.144.2.
 */
describe('#219 Jinja autoescape safe mirror', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  async function countTaintSignals(code: string, file = 'x.py') {
    const ir = await analyze(code, file, 'python');
    const sinks = ir.taint.sinks.filter(
      s => s.type === 'code_injection' || s.type === 'xss',
    );
    const flows = ((ir.taint.flows ?? []) as Array<{ sink_type: string }>).filter(
      f => f.sink_type === 'code_injection' || f.sink_type === 'xss',
    );
    return { sinks: sinks.length, flows: flows.length };
  }

  it('SAFE: Environment(autoescape=True).render(tainted) emits no sink/flow', async () => {
    const { sinks, flows } = await countTaintSignals(`
from jinja2 import Environment
from flask import request

def render_page():
    user = request.args.get('name')
    env = Environment(autoescape=True)
    template = env.get_template('page.html')
    return template.render(user=user)
`);
    expect(sinks).toBe(0);
    expect(flows).toBe(0);
  });

  it('SAFE: Environment(autoescape=select_autoescape([...])) emits no sink/flow', async () => {
    const { sinks, flows } = await countTaintSignals(`
from jinja2 import Environment, select_autoescape
from flask import request

def render_page():
    user = request.args.get('name')
    env = Environment(autoescape=select_autoescape(['html', 'xml']))
    template = env.get_template('page.html')
    return template.render(user=user)
`);
    expect(sinks).toBe(0);
    expect(flows).toBe(0);
  });

  it('UNSAFE: Environment() default (no autoescape kwarg) emits sink', async () => {
    const { sinks, flows } = await countTaintSignals(`
from jinja2 import Environment
from flask import request

def render_page():
    user = request.args.get('name')
    env = Environment()
    template = env.get_template('page.html')
    return template.render(user=user)
`);
    expect(sinks).toBeGreaterThan(0);
    expect(flows).toBeGreaterThan(0);
  });

  it('UNSAFE: Environment(autoescape=False) emits sink', async () => {
    const { sinks, flows } = await countTaintSignals(`
from jinja2 import Environment
from flask import request

def render_page():
    user = request.args.get('name')
    env = Environment(autoescape=False)
    template = env.get_template('page.html')
    return template.render(user=user)
`);
    expect(sinks).toBeGreaterThan(0);
    expect(flows).toBeGreaterThan(0);
  });

  it('MIXED: autoescape=True AND autoescape=False in same file — gate disabled, sink fires', async () => {
    // Recall guard: when both safe and unsafe Environments coexist we
    // conservatively let the sink fire rather than mask the unsafe branch.
    const { sinks, flows } = await countTaintSignals(`
from jinja2 import Environment
from flask import request

def render_safe():
    user = request.args.get('name')
    safe_env = Environment(autoescape=True)
    template = safe_env.get_template('page.html')
    return template.render(user=user)

def render_unsafe():
    user = request.args.get('name')
    unsafe_env = Environment(autoescape=False)
    template = unsafe_env.get_template('raw.html')
    return template.render(user=user)
`);
    expect(sinks).toBeGreaterThan(0);
    expect(flows).toBeGreaterThan(0);
  });

  it('RECALL: Template(concat_with_tainted).render(...) still fires when file has no Environment', async () => {
    // A tainted-template-source shape must still be flagged when the file
    // does NOT construct a Jinja Environment at all.
    const { sinks } = await countTaintSignals(`
from jinja2 import Template
from flask import request

def render_page():
    user = request.args.get('name')
    template = Template("Hello " + user)
    return template.render()
`);
    expect(sinks).toBeGreaterThan(0);
  });
});
