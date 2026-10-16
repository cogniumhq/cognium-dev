/**
 * cognium-dev#624 (next slice) — `WikiPage.getName()` on a page from
 * `m_wikiContext.getPage()` carries taint into locals used at JSP sinks.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';
import { buildJavaTaintedVars } from '../../src/analysis/passes/language-sources-pass.js';

const pageBadgeGetName = `package com.example.wikiext;

import java.io.IOException;
import javax.servlet.jsp.JspWriter;
import org.apache.wiki.WikiPage;
import org.apache.wiki.tags.WikiTagBase;

public class PageBadgeGetNameTag extends WikiTagBase {
    @Override
    public int doWikiStartTag() throws IOException {
        WikiPage page = m_wikiContext.getPage();
        String label = page.getName();
        JspWriter out = pageContext.getOut();
        out.print("<b>" + label + "</b>");
        return SKIP_BODY;
    }
}
`;

const xssFlows = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint.flows ?? []).filter(f => f.sink_type === 'xss' && !f.sanitized);

beforeAll(async () => {
  await initAnalyzer();
});

describe('#624 WikiPage.getName after getPage', () => {
  it('buildJavaTaintedVars derives label from page', () => {
    const derived = buildJavaTaintedVars(pageBadgeGetName, new Set(['page']));
    expect(derived.get('label')).toBe(12);
  });

  it('PageBadgeGetNameTag: xss flow from getPage line to out.print', async () => {
    const r = await analyze(pageBadgeGetName, 'PageBadgeGetNameTag.java', 'java');
    const flows = xssFlows(r);
    expect(flows.length).toBeGreaterThan(0);
    expect(flows.some(f => f.source_line === 11 && f.sink_line === 14)).toBe(true);
  });
});
