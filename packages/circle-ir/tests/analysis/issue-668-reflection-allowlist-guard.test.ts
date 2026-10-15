/**
 * cognium-dev#668 — a rejecting `!<literal set>.contains(name)` guard before
 * `Class.forName(name)` was not credited, so the allowlisted shape reported
 * code_injection. Past the guard the class name is one of the set's literals.
 *
 * SAST regression fixture — the `Plugins` handlers are deliberately vulnerable.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const guarded = `package com.acme.render;

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;

public class RendererFactory {
    private static final Set<String> KNOWN_RENDERERS = Set.of("com.acme.render.Pdf", "com.acme.render.Html");
    private static final List<String> legacy = Arrays.asList(
        "com.acme.render.Rtf",
        "com.acme.render.Txt");

    public Object build(HttpServletRequest req) throws Exception {
        String flavour = req.getParameter("flavour");
        if (!KNOWN_RENDERERS.contains(flavour)) {
            throw new SecurityException("unknown renderer");
        }
        return Class.forName(flavour).getDeclaredConstructor().newInstance();
    }

    public Object old(HttpServletRequest req) throws Exception {
        String flavour = req.getParameter("flavour");
        if (!legacy.contains(flavour)) return null;
        Class<?> k = Class.forName(flavour);
        return k.newInstance();
    }
}
`;

const unguarded = `package com.acme.render;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;

public class Plugins {
    private static final Set<String> KNOWN = Set.of("com.acme.render.Pdf");
    private final Map<String, String> cache = new HashMap<>();
    private static final Set<String> FROM_ENV = Set.of(System.getenv("RENDERERS"));

    public Object logs(HttpServletRequest req) throws Exception {
        String flavour = req.getParameter("flavour");
        if (!KNOWN.contains(flavour)) {
            System.err.println("unknown " + flavour);
        }
        return Class.forName(flavour).newInstance();
    }

    public Object otherName(HttpServletRequest req) throws Exception {
        String flavour = req.getParameter("flavour");
        String alt = req.getParameter("alt");
        if (!KNOWN.contains(alt)) throw new SecurityException("no");
        return Class.forName(flavour).newInstance();
    }

    public Object reassigned(HttpServletRequest req) throws Exception {
        String flavour = req.getParameter("flavour");
        if (!KNOWN.contains(flavour)) throw new SecurityException("no");
        flavour = req.getHeader("X-Flavour");
        return Class.forName(flavour).newInstance();
    }

    public Object notLiteral(HttpServletRequest req) throws Exception {
        String flavour = req.getParameter("flavour");
        if (!FROM_ENV.contains(flavour)) throw new SecurityException("no");
        return Class.forName(flavour).newInstance();
    }
}
`;

function codeInjectionLines(r: Awaited<ReturnType<typeof analyze>>): number[] {
  return [...new Set((r.taint.flows ?? []).filter((f) => f.sink_type === 'code_injection').map((f) => f.sink_line))].sort((a, b) => a - b);
}

describe('cognium-dev#668 — reflection allowlist guard', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('a rejecting literal-set guard clears Class.forName', async () => {
    const r = await analyze(guarded, 'RendererFactory.java', 'java');
    expect(codeInjectionLines(r)).toEqual([]);
  });

  it('non-rejecting, other-variable, reassigned and non-literal guards still report', async () => {
    const r = await analyze(unguarded, 'Plugins.java', 'java');
    expect(codeInjectionLines(r)).toEqual([18, 25, 32, 38]);
  });
});
