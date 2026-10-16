/**
 * cognium-dev#624 (WikiTag slice) — inherited `m_wikiContext.getPage()` on
 * JSPWiki tag handlers is a WikiContext source; unrelated classes that reuse
 * the field name are not.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const pageBadgeTag = `package com.example.wikiext;

import java.io.IOException;
import javax.servlet.jsp.JspWriter;
import org.apache.wiki.WikiPage;
import org.apache.wiki.tags.WikiTagBase;

public class PageBadgeTag extends WikiTagBase {
    @Override
    public int doWikiStartTag() throws IOException {
        WikiPage page = m_wikiContext.getPage();
        JspWriter out = pageContext.getOut();
        out.print("<b>" + page + "</b>");
        return SKIP_BODY;
    }
}
`;

const pageBadgeHelper = `package com.example.wikiext;

import java.io.IOException;
import javax.servlet.jsp.JspWriter;

public class PageBadgeHelper {
    private final PageRegistry m_wikiContext = new PageRegistry();

    public void render(JspWriter out) throws IOException {
        String label = m_wikiContext.getPage();
        out.print("<b>" + label + "</b>");
    }
}

class PageRegistry {
    String getPage() { return "x"; }
}
`;

beforeAll(async () => {
  await initAnalyzer();
});

describe('#624 WikiTag inherited m_wikiContext.getPage source', () => {
  it('PageBadgeTag: io_input source at getPage and xss flow to out.print', async () => {
    const r = await analyze(pageBadgeTag, 'PageBadgeTag.java', 'java');
    const getPageSources = (r.taint.sources ?? []).filter(s => s.location?.includes('getPage'));
    expect(getPageSources.length).toBeGreaterThan(0);
    expect(getPageSources.some(s => s.line === 11)).toBe(true);
    const xssFlows = (r.taint.flows ?? []).filter(f => f.sink_type === 'xss');
    expect(xssFlows.length).toBeGreaterThan(0);
    expect(xssFlows.some(f => f.source_line === 11 && f.sink_line === 13)).toBe(true);
  });

  it('PageBadgeHelper: no getPage source and no xss flow', async () => {
    const r = await analyze(pageBadgeHelper, 'PageBadgeHelper.java', 'java');
    expect((r.taint.sources ?? []).filter(s => s.location?.includes('getPage'))).toHaveLength(0);
    expect((r.taint.flows ?? []).filter(f => f.sink_type === 'xss')).toHaveLength(0);
  });
});
