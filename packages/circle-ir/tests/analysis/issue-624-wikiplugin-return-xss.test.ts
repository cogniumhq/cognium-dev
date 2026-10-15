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
});
