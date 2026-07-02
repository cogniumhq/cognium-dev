import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/index.js';

/**
 * cognium-dev #156 (reopen 3.144.0) — template-engine safe mirror
 * fires `code_injection` when the template name is a compile-time
 * string literal.
 *
 * Original 3.100.0 ship fixed the *compiled-Template.merge/render*
 * shape (Stage 9b on `Template#{merge,render,process,renderTo}`
 * with receiver ∈ COMPILED_TEMPLATE_TYPES). The 3.144.0 reopen
 * (REG-144-03 java, REG-144-04 python) surfaces the engine-level
 * shape:
 *
 *   VelocityEngine engine = ...;
 *   engine.merge("safe.vm", ctx, writer);  // arg 0 is literal
 *
 * The user payload flows into `ctx` (the Context object), not the
 * template body. `"safe.vm"` is a compile-time constant, so the
 * template compilation cannot be attacker-influenced.
 *
 * Fix: extend Stage 9b — when the receiver type is a template
 * *engine* (VelocityEngine, TemplateEngine, PebbleEngine,
 * Configuration, …) AND the method is `merge`/`process`/`render`/
 * `renderTo`, drop the sink if the first arg is a literal.
 * Symmetric extension for `evaluate(...)` uses the *last* arg
 * (the template string) instead of the first.
 */
describe('cognium-dev #156 — template-engine safe mirror', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('VelocityEngine#merge with literal template name — no code_injection', async () => {
    const code = `
package com.demo.libapi;

import org.apache.velocity.VelocityEngine;
import org.apache.velocity.context.Context;
import java.io.Writer;

public class SafeVelocityRender {
    private final VelocityEngine engine;
    public SafeVelocityRender() {
        this.engine = new VelocityEngine();
        this.engine.init();
    }
    public void render(String userName, Writer writer) {
        Context ctx = new org.apache.velocity.VelocityContext();
        ctx.put("name", userName);
        engine.merge("safe.vm", "UTF-8", ctx, writer);
    }
}
`;
    const ir = await analyze(code, 'SafeVelocityRender.java', 'java');
    const codeInj = (ir.taint.sinks ?? []).filter(
      s => s.type === 'code_injection',
    );
    expect(codeInj.length).toBe(0);
  });

  it('TemplateEngine#process with literal template name — no code_injection', async () => {
    const code = `
package com.demo.libapi;

import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import java.io.Writer;

public class SafeThymeleafRender {
    private final TemplateEngine engine;
    public SafeThymeleafRender() { this.engine = new TemplateEngine(); }
    public String render(String userName) {
        Context ctx = new Context();
        ctx.setVariable("name", userName);
        return engine.process("safe-view", ctx);
    }
}
`;
    const ir = await analyze(code, 'SafeThymeleafRender.java', 'java');
    const codeInj = (ir.taint.sinks ?? []).filter(
      s => s.type === 'code_injection',
    );
    expect(codeInj.length).toBe(0);
  });

  it('recall guard — VelocityEngine#merge with tainted template name still fires', async () => {
    // Non-literal first arg: the template *name* itself is under
    // attacker control. That's real code_injection — file-loader
    // gadget or SSTI depending on Velocity's resolver setup.
    const code = `
package com.demo.libapi;

import org.apache.velocity.VelocityEngine;
import org.apache.velocity.context.Context;
import java.io.Writer;

public class UnsafeVelocityRender {
    private final VelocityEngine engine = new VelocityEngine();
    public void render(String templateName, Context ctx, Writer w) {
        engine.merge(templateName, "UTF-8", ctx, w);
    }
}
`;
    const ir = await analyze(code, 'UnsafeVelocityRender.java', 'java');
    const codeInj = (ir.taint.sinks ?? []).filter(
      s => s.type === 'code_injection',
    );
    expect(codeInj.length).toBeGreaterThan(0);
  });

  it('recall guard — Velocity#evaluate with tainted template body still fires', async () => {
    // Non-literal template string in the last arg — attacker
    // controls the actual Velocity script body. Real SSTI.
    const code = `
package com.demo.libapi;

import org.apache.velocity.app.Velocity;
import org.apache.velocity.context.Context;
import java.io.Writer;

public class UnsafeVelocityEvaluate {
    public void run(Context ctx, Writer w, String userTemplate) {
        Velocity.evaluate(ctx, w, "log", userTemplate);
    }
}
`;
    const ir = await analyze(code, 'UnsafeVelocityEvaluate.java', 'java');
    const codeInj = (ir.taint.sinks ?? []).filter(
      s => s.type === 'code_injection',
    );
    expect(codeInj.length).toBeGreaterThan(0);
  });

  it('recall guard — Configuration.getTemplate(tainted) compile step still fires', async () => {
    // Freemarker's Configuration.getTemplate(name) is a real
    // code_injection sink (config-loader.ts:1217). The 3.100.0 ship
    // kept this shape and the new engine-level literal-first-arg
    // gate does not affect it (we only gate `merge/process/render/
    // renderTo/evaluate`, not `getTemplate`).
    const code = `
package com.demo.libapi;

import freemarker.template.Configuration;
import freemarker.template.Template;

public class UnsafeFreemarkerGetTemplate {
    public Template get(Configuration cfg, String user) throws Exception {
        return cfg.getTemplate(user);
    }
}
`;
    const ir = await analyze(code, 'UnsafeFreemarkerGetTemplate.java', 'java');
    const codeInj = (ir.taint.sinks ?? []).filter(
      s => s.type === 'code_injection',
    );
    expect(codeInj.length).toBeGreaterThan(0);
  });
});
