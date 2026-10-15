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

  it('a branch-only guard, a mutated set and a second tainted value on the sink still report', async () => {
    const code = `package com.acme.render;

import java.util.*;
import javax.servlet.http.HttpServletRequest;

public class Loader {
    private static final List<String> NAMES = List.of("com.acme.A", "com.acme.B");
    private static final Set<String> GROWN = new HashSet<>(Arrays.asList("com.acme.C"));

    public Object branch(HttpServletRequest req, boolean strict) throws Exception {
        String kind = req.getParameter("kind");
        if (strict) {
            if (!NAMES.contains(kind)) {
                throw new SecurityException("denied");
            }
        }
        return Class.forName(kind).newInstance();
    }

    public Object mutated(HttpServletRequest req) throws Exception {
        GROWN.add(req.getParameter("extra"));
        String kind = req.getParameter("kind");
        if (!GROWN.contains(kind)) throw new SecurityException("denied");
        return Class.forName(kind).newInstance();
    }

    public Object joined(HttpServletRequest req) throws Exception {
        String kind = req.getParameter("kind");
        String tail = req.getParameter("tail");
        if (!NAMES.contains(kind)) throw new SecurityException("denied");
        return Class.forName(kind + tail).newInstance();
    }

    // Braceless outer if — guard must not clear the sink outside the branch.
    public Object braceless(HttpServletRequest req, boolean strict) throws Exception {
        String kind = req.getParameter("kind");
        if (strict)
            if (!NAMES.contains(kind))
                throw new SecurityException("denied");
        return Class.forName(kind).newInstance();
    }
}
`;
    const r = await analyze(code, 'Loader.java', 'java');
    expect(codeInjectionLines(r)).toEqual([17, 24, 31, 40]);
  });

  it('a final String "allowlist" is not a collection; String.contains must not clear Class.forName', async () => {
    const code = `package com.acme.render;

import javax.servlet.http.HttpServletRequest;

public class StringGuard {
    private static final String ALLOWED = "com.acme.Safe";

    public Object load(HttpServletRequest req) throws Exception {
        String cls = req.getParameter("cls");
        if (!ALLOWED.contains(cls)) throw new SecurityException("denied");
        return Class.forName(cls).newInstance();
    }
}
`;
    const r = await analyze(code, 'StringGuard.java', 'java');
    expect(codeInjectionLines(r)).toEqual([11]);
  });

  it('nearest final declaration wins over an earlier field of the same name', async () => {
    const code = `package com.acme.render;

import java.util.Set;
import javax.servlet.http.HttpServletRequest;

public class Shadow {
    private static final Set<String> ALLOWED = Set.of("com.acme.Safe");

    public Object load(HttpServletRequest req) throws Exception {
        final Set<String> ALLOWED = Set.of(req.getParameter("x"));
        String cls = req.getParameter("cls");
        if (!ALLOWED.contains(cls)) throw new SecurityException("denied");
        return Class.forName(cls).newInstance();
    }
}
`;
    const r = await analyze(code, 'Shadow.java', 'java');
    expect(codeInjectionLines(r)).toEqual([13]);
  });

  it('} else / same-line nested braceless if must not clear Class.forName', async () => {
    const code = `package com.acme.render;

import java.util.Set;
import javax.servlet.http.HttpServletRequest;

public class NestedElse {
    private static final Set<String> SET = Set.of("com.acme.Safe");

    public Object elseForm(HttpServletRequest req, boolean other) throws Exception {
        String v = req.getParameter("v");
        if (other) {
            doSomething();
        } else
            if (!SET.contains(v))
                throw new SecurityException("denied");
        return Class.forName(v).newInstance();
    }

    public Object sameLine(HttpServletRequest req, boolean strict) throws Exception {
        String v = req.getParameter("v");
        if (strict) if (!SET.contains(v)) throw new SecurityException("denied");
        return Class.forName(v).newInstance();
    }

    private void doSomething() {}
}
`;
    const r = await analyze(code, 'NestedElse.java', 'java');
    expect(codeInjectionLines(r)).toEqual([16, 22]);
  });

  it('a closer non-final local shadows a final field allowlist', async () => {
    const code = `package com.acme.render;

import java.util.Set;
import javax.servlet.http.HttpServletRequest;

public class NonFinalShadow {
    private static final Set<String> ALLOWED = Set.of("com.acme.Safe");

    public Object load(HttpServletRequest req) throws Exception {
        Set<String> ALLOWED = Set.of(req.getParameter("x"));
        String cls = req.getParameter("cls");
        if (!ALLOWED.contains(cls)) throw new SecurityException("denied");
        return Class.forName(cls).newInstance();
    }

    public Object withVar(HttpServletRequest req) throws Exception {
        var ALLOWED = Set.of(req.getParameter("x"));
        String cls = req.getParameter("cls");
        if (!ALLOWED.contains(cls)) throw new SecurityException("denied");
        return Class.forName(cls).newInstance();
    }
}
`;
    const r = await analyze(code, 'NonFinalShadow.java', 'java');
    expect(codeInjectionLines(r)).toEqual([13, 20]);
  });

});
