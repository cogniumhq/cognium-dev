/**
 * cognium-dev#624 (minimal slice) — the `String` returned from `execute(...)` of
 * a class implementing JSPWiki's `WikiPlugin` / `Plugin` is HTML output, so a
 * tainted value reaching the return is `xss`. Keyed on the interface, not the
 * method name. The `WikiContext.getPage()` source (CVE-2019-10076) is out of
 * this slice.
 *
 * SAST regression fixtures — the macros are deliberately vulnerable.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';
import { generateFindings } from '../../src/analysis/findings.js';

const greeting = `package com.example.wikiext;

import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import org.apache.wiki.WikiContext;
import org.apache.wiki.api.exceptions.PluginException;
import org.apache.wiki.api.plugin.WikiPlugin;

public class GreetingMacro implements WikiPlugin {
    @Override
    public String execute(WikiContext context, Map<String, String> params) throws PluginException {
        HttpServletRequest req = context.getHttpRequest();
        String who = req.getParameter("visitor");
        StringBuilder html = new StringBuilder();
        html.append("<div class=\\"greet\\">Hello ").append(who).append("</div>");
        return html.toString();
    }
}
`;

const banner = `package com.example.wikiext;

import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.wiki.WikiContext;
import org.apache.wiki.api.exceptions.PluginException;
import org.apache.wiki.api.plugin.WikiPlugin;

public class BannerMacro implements WikiPlugin {
    @Override
    public String execute(WikiContext context, Map<String, String> params) throws PluginException {
        HttpServletRequest req = context.getHttpRequest();
        String who = StringEscapeUtils.escapeHtml4(req.getParameter("visitor"));
        return "<div class=\\"banner\\">" + who + "</div>";
    }
}
`;

const formatter = `package com.example.wikiext;

import javax.servlet.http.HttpServletRequest;

public class LabelFormatter {
    public String execute(HttpServletRequest req) {
        return "<b>" + req.getParameter("label") + "</b>";
    }
}
`;

async function xss(code: string, file: string) {
  const r = await analyze(code, file, 'java');
  const flows = (r.taint.flows ?? []).filter((f) => f.sink_type === 'xss');
  const findings = generateFindings(
    r.taint.sources, r.taint.sinks, r.dfg, file, code, 'java', r.taint.sanitizers, r.types, r.taint.flows,
  ).filter((f) => f.type === 'xss');
  const proximity = generateFindings(r.taint.sources, r.taint.sinks, r.dfg, file, code, 'java')
    .filter((f) => f.type === 'xss');
  return {
    flows: flows.map((f) => [f.source_line, f.sink_line]),
    sinkLines: r.taint.sinks.filter((s) => s.type === 'xss').map((s) => s.line),
    findings: findings.length,
    proximity: proximity.length,
  };
}

describe('#624: JSPWiki WikiPlugin.execute return is an xss sink', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('GreetingMacro: xss at the return (line 16) with a flow from line 13', async () => {
    const r = await xss(greeting, 'GreetingMacro.java');
    expect(r.flows).toEqual([[13, 16]]);
    expect(r.findings).toBeGreaterThan(0);
  });

  it('is not keyed on names: renamed class, method locals and file still fire', async () => {
    const code = greeting.replace(/GreetingMacro/g, 'HelloPanel').replace(/\bwho\b/g, 'visitorName').replace(/\bhtml\b/g, 'out');
    expect((await xss(code, 'HelloPanel.java')).flows).toEqual([[13, 16]]);
  });

  it('the older org.apache.wiki.api.plugin.Plugin interface and a fully-qualified implements also fire', async () => {
    const older = greeting.replace('import org.apache.wiki.api.plugin.WikiPlugin;', 'import org.apache.wiki.api.plugin.Plugin;').replace('implements WikiPlugin', 'implements Plugin');
    expect((await xss(older, 'GreetingMacro.java')).flows).toEqual([[13, 16]]);
    const fqn = greeting.replace('import org.apache.wiki.api.plugin.WikiPlugin;\n', '').replace('implements WikiPlugin', 'implements org.apache.wiki.api.plugin.WikiPlugin');
    expect((await xss(fqn, 'GreetingMacro.java')).flows).toEqual([[12, 15]]);
  });

  it('BannerMacro (escapeHtml4 before the return): no xss flow, sink or finding', async () => {
    const r = await xss(banner, 'BannerMacro.java');
    expect(r.flows).toEqual([]);
    expect(r.findings).toBe(0);
    expect(r.proximity).toBe(0);
  });

  it('LabelFormatter (not a WikiPlugin, same execute shape): no xss flow, sink or finding', async () => {
    const r = await xss(formatter, 'LabelFormatter.java');
    expect(r.flows).toEqual([]);
    expect(r.sinkLines).toEqual([]);
    expect(r.proximity).toBe(0);
  });

  it('a WikiPlugin whose execute returns only constants has no sink', async () => {
    const code = greeting.replace('append(who)', 'append("friend")');
    const r = await xss(code, 'GreetingMacro.java');
    expect(r.flows).toEqual([]);
  });

  it('#268: StringBuilder.append is still not an xss sink on its own (non-plugin class)', async () => {
    const code = `import javax.servlet.http.HttpServletRequest;
public class Builder {
    public String build(HttpServletRequest req) {
        StringBuilder html = new StringBuilder();
        html.append("<div>").append(req.getParameter("q"));
        return html.toString();
    }
}
`;
    const r = await xss(code, 'Builder.java');
    expect(r.flows).toEqual([]);
    expect(r.sinkLines).toEqual([]);
  });

  it('WikiPlugin imported only: a class that implements some other `Plugin` is not a wiki plugin', async () => {
    const code = greeting.replace('implements WikiPlugin', 'implements Plugin');
    const r = await xss(code, 'GreetingMacro.java');
    expect(r.flows).toEqual([]);
    expect(r.sinkLines).toEqual([]);
    expect(r.findings).toBe(0);
    expect(r.proximity).toBe(0);
  });

  it('Plugin imported only: a class that implements some other `WikiPlugin` is not a wiki plugin', async () => {
    const code = greeting.replace('import org.apache.wiki.api.plugin.WikiPlugin;', 'import org.apache.wiki.api.plugin.Plugin;');
    const r = await xss(code, 'GreetingMacro.java');
    expect(r.flows).toEqual([]);
    expect(r.sinkLines).toEqual([]);
    expect(r.proximity).toBe(0);
  });

  it('a wildcard import of the plugin package accepts either simple name', async () => {
    const wild = greeting.replace('import org.apache.wiki.api.plugin.WikiPlugin;', 'import org.apache.wiki.api.plugin.*;');
    expect((await xss(wild, 'GreetingMacro.java')).flows).toEqual([[13, 16]]);
    expect((await xss(wild.replace('implements WikiPlugin', 'implements Plugin'), 'GreetingMacro.java')).flows).toEqual([[13, 16]]);
  });

  it('a return above a later append is not a sink; the return below it is', async () => {
    const code = greeting.replace(
      '        html.append("<div class=\\"greet\\">Hello ").append(who).append("</div>");\n        return html.toString();',
      '        if (params.isEmpty()) {\n            return html.toString();\n        }\n        html.append("<div class=\\"greet\\">Hello ").append(who).append("</div>");\n        return html.toString();',
    );
    expect(code).not.toBe(greeting);
    const lines = code.split('\n');
    const early = lines.findIndex((l) => l.includes('return html.toString();')) + 1;
    const late = lines.length - [...lines].reverse().findIndex((l) => l.includes('return html.toString();'));
    const r = await xss(code, 'GreetingMacro.java');
    expect(r.flows.map((f) => f[1])).toEqual([late]);
    expect(r.sinkLines).not.toContain(early);
  });

  it('a name reassigned from the request after it was appended is not a carrier: no xss', async () => {
    const code = greeting.replace(
      '        String who = req.getParameter("visitor");\n        StringBuilder html = new StringBuilder();\n        html.append("<div class=\\"greet\\">Hello ").append(who).append("</div>");\n',
      '        StringBuilder html = new StringBuilder();\n        String who = "guest";\n        html.append(who);\n        who = req.getParameter("visitor");\n',
    );
    expect(code).not.toBe(greeting);
    const r = await xss(code, 'GreetingMacro.java');
    expect(r.flows).toEqual([]);
    expect(r.sinkLines).toEqual([]);
    expect(r.findings).toBe(0);
    expect(r.proximity).toBe(0);
  });

  it('a carrier name only inside a trailing comment of an append does not taint the builder', async () => {
    const code = greeting.replace(
      '        html.append("<div class=\\"greet\\">Hello ").append(who).append("</div>");',
      '        html.append("safe"); // who',
    );
    expect(code).not.toBe(greeting);
    const r = await xss(code, 'GreetingMacro.java');
    expect(r.flows).toEqual([]);
    expect(r.sinkLines).toEqual([]);
    expect(r.findings).toBe(0);
    expect(r.proximity).toBe(0);
  });

  it('a carrier name only in a chained non-append call does not taint the builder', async () => {
    const code = greeting.replace(
      '        html.append("<div class=\\"greet\\">Hello ").append(who).append("</div>");',
      '        html.append("safe").indexOf(who);',
    );
    expect(code).not.toBe(greeting);
    const r = await xss(code, 'GreetingMacro.java');
    expect(r.flows).toEqual([]);
    expect(r.sinkLines).toEqual([]);
    expect(r.findings).toBe(0);
    expect(r.proximity).toBe(0);
  });

  it('a carrier name after the append statement semicolon does not taint the builder', async () => {
    const code = greeting.replace(
      '        String who = req.getParameter("visitor");\n        StringBuilder html = new StringBuilder();\n        html.append("<div class=\\"greet\\">Hello ").append(who).append("</div>");',
      '        StringBuilder html = new StringBuilder();\n        html.append("safe"); String who = req.getParameter("visitor");',
    );
    expect(code).not.toBe(greeting);
    const r = await xss(code, 'GreetingMacro.java');
    expect(r.flows).toEqual([]);
    expect(r.sinkLines).toEqual([]);
    expect(r.findings).toBe(0);
    expect(r.proximity).toBe(0);
  });

  it('a second append(who) after the semicolon on the same line still fires', async () => {
    const code = greeting.replace(
      '        html.append("<div class=\\"greet\\">Hello ").append(who).append("</div>");',
      '        html.append("safe"); html.append(who);',
    );
    expect(code).not.toBe(greeting);
    const r = await xss(code, 'GreetingMacro.java');
    expect(r.flows).toEqual([[13, 16]]);
    expect(r.findings).toBeGreaterThan(0);
  });

  it('each statement on a line taints only its own receiver: other.append(who) fires on other, not html', async () => {
    const shape = (ret: string) => greeting.replace(
      '        html.append("<div class=\\"greet\\">Hello ").append(who).append("</div>");\n        return html.toString();',
      `        StringBuilder other = new StringBuilder();\n        html.append("safe"); other.append(who);\n        return ${ret}.toString();`,
    );
    const viaOther = shape('other');
    expect(viaOther).not.toBe(greeting);
    expect((await xss(viaOther, 'GreetingMacro.java')).flows).toEqual([[13, 17]]);
    const viaHtml = await xss(shape('html'), 'GreetingMacro.java');
    expect(viaHtml.flows).toEqual([]);
    expect(viaHtml.sinkLines).toEqual([]);
    expect(viaHtml.findings).toBe(0);
    expect(viaHtml.proximity).toBe(0);
  });

  it('html += who fires; a name in a later statement after `html += "safe";` does not taint html', async () => {
    const accumulate = greeting.replace(
      '        StringBuilder html = new StringBuilder();\n        html.append("<div class=\\"greet\\">Hello ").append(who).append("</div>");\n        return html.toString();',
      '        String html = "";\n        html += who;\n        return html;',
    );
    expect(accumulate).not.toBe(greeting);
    expect((await xss(accumulate, 'GreetingMacro.java')).flows).toEqual([[13, 16]]);
    const later = greeting.replace(
      '        String who = req.getParameter("visitor");\n        StringBuilder html = new StringBuilder();\n        html.append("<div class=\\"greet\\">Hello ").append(who).append("</div>");\n        return html.toString();',
      '        String html = "";\n        html += "safe"; String who = req.getParameter("visitor");\n        return html;',
    );
    expect(later).not.toBe(greeting);
    const r = await xss(later, 'GreetingMacro.java');
    expect(r.flows).toEqual([]);
    expect(r.sinkLines).toEqual([]);
    expect(r.findings).toBe(0);
    expect(r.proximity).toBe(0);
    // Same shape with `who` already tainted above: only `copy` gets it, not `html`.
    const copied = greeting.replace(
      '        StringBuilder html = new StringBuilder();\n        html.append("<div class=\\"greet\\">Hello ").append(who).append("</div>");\n        return html.toString();',
      '        String html = "";\n        html += "safe"; String copy = who;\n        return html;',
    );
    expect(copied).not.toBe(greeting);
    const c = await xss(copied, 'GreetingMacro.java');
    expect(c.flows).toEqual([]);
    expect(c.sinkLines).toEqual([]);
    expect(c.findings).toBe(0);
    expect(c.proximity).toBe(0);
  });

  it('a `;` inside a string or comment does not end the += right-hand side', async () => {
    const code = greeting.replace(
      '        StringBuilder html = new StringBuilder();\n        html.append("<div class=\\"greet\\">Hello ").append(who).append("</div>");\n        return html.toString();',
      '        String html = "";\n        html += "a;b" + /* ; */ who;\n        return html;',
    );
    expect(code).not.toBe(greeting);
    expect((await xss(code, 'GreetingMacro.java')).flows).toEqual([[13, 16]]);
  });

  it('a chained .append(who) after a safe append still fires', async () => {
    const code = greeting.replace(
      '        html.append("<div class=\\"greet\\">Hello ").append(who).append("</div>");',
      '        html.append("safe").append(who);',
    );
    expect(code).not.toBe(greeting);
    const r = await xss(code, 'GreetingMacro.java');
    expect(r.flows).toEqual([[13, 16]]);
    expect(r.findings).toBeGreaterThan(0);
  });

  it('a nested call inside append(String.valueOf(who)) still fires', async () => {
    const code = greeting.replace(
      '        html.append("<div class=\\"greet\\">Hello ").append(who).append("</div>");',
      '        html.append(String.valueOf(who));',
    );
    expect(code).not.toBe(greeting);
    const r = await xss(code, 'GreetingMacro.java');
    expect(r.flows).toEqual([[13, 16]]);
    expect(r.findings).toBeGreaterThan(0);
  });

  describe('same-line liveness: a name carries the source only after the statement that assigns it', () => {
    const oneLine = (body: string, ret: string) => greeting.replace(
      '        String who = req.getParameter("visitor");\n        StringBuilder html = new StringBuilder();\n        html.append("<div class=\\"greet\\">Hello ").append(who).append("</div>");\n        return html.toString();',
      `${body}\n        return ${ret};`,
    );
    const clean = async (code: string) => {
      expect(code).not.toBe(greeting);
      const r = await xss(code, 'GreetingMacro.java');
      expect(r.flows).toEqual([]);
      expect(r.sinkLines).toEqual([]);
      expect(r.findings).toBe(0);
      expect(r.proximity).toBe(0);
    };

    it('append(who) before `who = req.getParameter(...)` on the same line: no xss', async () => {
      await clean(oneLine(
        '        StringBuilder html = new StringBuilder();\n        String who = "guest"; html.append(who); who = req.getParameter("visitor");',
        'html.toString()',
      ));
    });

    it('html += who before `who = req.getParameter(...)` on the same line: no xss', async () => {
      await clean(oneLine(
        '        String html = ""; String who = "guest"; html += who; who = req.getParameter("visitor");',
        'html',
      ));
    });

    it('the source bound to a later statement on the line (`extra`), not the first `=`: no xss', async () => {
      await clean(oneLine(
        '        StringBuilder html = new StringBuilder();\n        String who = "guest"; html.append(who); String extra = req.getParameter("visitor");',
        'html.toString()',
      ));
    });

    it('the same line with extra appended instead does fire', async () => {
      const code = oneLine(
        '        StringBuilder html = new StringBuilder();\n        String who = "guest"; String extra = req.getParameter("visitor"); html.append(extra);',
        'html.toString()',
      );
      expect(code).not.toBe(greeting);
      expect((await xss(code, 'GreetingMacro.java')).flows).toEqual([[14, 15]]);
    });

    it('`String who = req.getParameter(...); html.append(who);` on one line still fires', async () => {
      const code = oneLine(
        '        StringBuilder html = new StringBuilder();\n        String who = req.getParameter("visitor"); html.append(who);',
        'html.toString()',
      );
      expect(code).not.toBe(greeting);
      expect((await xss(code, 'GreetingMacro.java')).flows).toEqual([[14, 15]]);
    });

    it('`who = req.getParameter(...); html += who;` on one line still fires', async () => {
      const code = oneLine(
        '        String html = ""; String who = "guest"; who = req.getParameter("visitor"); html += who;',
        'html',
      );
      expect(code).not.toBe(greeting);
      expect((await xss(code, 'GreetingMacro.java')).flows).toEqual([[13, 14]]);
    });

    it('a copy made on the line before the source is assigned carries nothing; one made after does', async () => {
      await clean(oneLine(
        '        StringBuilder html = new StringBuilder();\n        String who = "guest"; String copy = who; who = req.getParameter("visitor");\n        html.append(copy);',
        'html.toString()',
      ));
      const after = oneLine(
        '        StringBuilder html = new StringBuilder();\n        String who = req.getParameter("visitor"); String copy = who;\n        html.append(copy);',
        'html.toString()',
      );
      expect((await xss(after, 'GreetingMacro.java')).flows).toEqual([[14, 16]]);
    });

    it('an earlier `prefs.getParameter(...)` on the source line is not the source: no xss', async () => {
      await clean(oneLine(
        '        StringBuilder html = new StringBuilder();\n        String label = prefs.getParameter("ui.theme"); html.append(label); String who = req.getParameter("visitor");',
        'html.toString()',
      ));
      // Renamed locals: the request receiver is matched by its name, not by `req`.
      const renamed = oneLine(
        '        StringBuilder out = new StringBuilder();\n        String label = prefs.getParameter("ui.theme"); out.append(label); String visitorName = request.getParameter("visitor");',
        'out.toString()',
      ).replace('HttpServletRequest req = ', 'HttpServletRequest request = ');
      await clean(renamed);
      // The request call after it on the same line, appended, still fires.
      const real = oneLine(
        '        StringBuilder html = new StringBuilder();\n        String label = prefs.getParameter("ui.theme"); html.append(label); String who = req.getParameter("visitor"); html.append(who);',
        'html.toString()',
      );
      expect((await xss(real, 'GreetingMacro.java')).flows).toEqual([[14, 15]]);
    });

    it('a same-line sanitizer that wraps a different request value does not cover the returned one', async () => {
      const code = oneLine(
        '        String who = req.getParameter("a"); String safe = StringEscapeUtils.escapeHtml4(req.getParameter("b"));',
        '"<div>" + who + "</div>"',
      ).replace('import org.apache.wiki.WikiContext;', 'import org.apache.commons.lang3.StringEscapeUtils;\nimport org.apache.wiki.WikiContext;');
      expect(code).not.toBe(greeting);
      const r = await xss(code, 'GreetingMacro.java');
      expect(r.flows.map((f) => f[1])).toEqual([15]);
      expect(r.findings).toBeGreaterThan(0);
      // Returning the escaped one instead stays clean.
      await clean(code.replace('return "<div>" + who + "</div>";', 'return "<div>" + safe + "</div>";'));
      // Renamed locals and request: still fires.
      const renamed = code.replace(/\bwho\b/g, 'visitorName').replace(/\bsafe\b/g, 'escaped').replace(/\breq\b/g, 'request');
      expect(renamed).not.toBe(code);
      expect((await xss(renamed, 'GreetingMacro.java')).flows.map((f) => f[1])).toEqual([15]);
      // The returned name itself escaped later on the same line stays clean.
      await clean(code.replace(
        'String safe = StringEscapeUtils.escapeHtml4(req.getParameter("b"));',
        'who = StringEscapeUtils.escapeHtml4(who);',
      ));
    });

    it('html += who with who tainted on an earlier line still fires', async () => {
      const code = oneLine(
        '        String who = req.getParameter("visitor");\n        String html = ""; html += who;',
        'html',
      );
      expect(code).not.toBe(greeting);
      expect((await xss(code, 'GreetingMacro.java')).flows).toEqual([[13, 15]]);
    });
  });

  it('only the escaped value is returned while a later, unused parameter is read: no xss', async () => {
    const code = banner.replace(
      '        return',
      '        String extra = req.getParameter("extra");\n        return',
    );
    expect(code).not.toBe(banner);
    const r = await xss(code, 'BannerMacro.java');
    expect(r.flows).toEqual([]);
    expect(r.findings).toBe(0);
    expect(r.proximity).toBe(0);
  });

  it('an escaped value read after the returned raw one does not suppress it', async () => {
    const code = greeting.replace(
      '        StringBuilder html = new StringBuilder();',
      '        String other = org.apache.commons.lang3.StringEscapeUtils.escapeHtml4(req.getParameter("other"));\n        StringBuilder html = new StringBuilder();',
    );
    const r = await xss(code, 'GreetingMacro.java');
    expect(r.flows).toEqual([[13, 17]]);
  });
});
