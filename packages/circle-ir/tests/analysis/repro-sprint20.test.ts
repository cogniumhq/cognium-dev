/**
 * Repro for cognium-dev Sprint 20 — cache-no-vary detection (CWE-524).
 *
 * Issue in scope:
 *   - #96 L91 — Python (Flask/Django/FastAPI) handlers that set
 *               `Cache-Control: public, max-age>0` for user-specific responses
 *               without `Vary: Cookie`/`Vary: Authorization`.
 *
 * Extended cross-language coverage: JS/TS (Express), Go (net/http), Java (Spring).
 *
 * Trigger mode: strict + auth-qualifier. Fire only when (a) cache-public
 * signal present, (b) auth signal present in same handler, (c) no covering
 * `Vary` in same handler.
 *
 * Layout (12 fixtures, 3 per language: 1 positive + 2 negatives):
 *   - JS.1   — Express handler reads req.cookies + Cache-Control public + no Vary → fires
 *   - JS.2   — Same + res.vary('Cookie') → no fire
 *   - JS.3   — /health endpoint, Cache-Control public, no auth signal → no fire
 *   - PY.1   — Flask handler reads request.cookies + Cache-Control public + no Vary → fires
 *   - PY.2   — Same + @vary_on_cookie decorator → no fire
 *   - PY.3   — FastAPI public /version endpoint, no auth signal → no fire
 *   - GO.1   — net/http handler reads r.Cookie + w.Header().Set Cache-Control public + no Vary → fires
 *   - GO.2   — Same + w.Header().Set("Vary", "Cookie") → no fire
 *   - GO.3   — Static-asset handler, no cookie/auth read → no fire
 *   - JAVA.1 — Spring @CookieValue param + setHeader Cache-Control public + no Vary → fires
 *   - JAVA.2 — Same + addHeader("Vary", "Cookie") → no fire
 *   - JAVA.3 — Public CDN endpoint, no @CookieValue/@RequestHeader → no fire
 *
 * Target release: circle-ir 3.70.0 / cognium-dev 3.70.0
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

describe('cognium-dev Sprint 20 — cache-no-vary pass', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const cacheNoVaryFindings = (
    findings: Array<{ rule_id?: string }> | undefined,
  ) => (findings ?? []).filter((f) => f.rule_id === 'cache-no-vary');

  // ---------------------------------------------------------------------------
  // JS/TS — Express
  // ---------------------------------------------------------------------------

  it('JS.1 — Express handler with req.cookies + Cache-Control public + no Vary should fire', async () => {
    const code = `app.get('/me', (req, res) => {
  const sid = req.cookies.session;
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.json({ user: lookup(sid) });
});
`;
    const r = await analyze(code, 'me.js', 'javascript');
    expect(cacheNoVaryFindings(r.findings).length).toBeGreaterThanOrEqual(1);
  });

  it("JS.2 — Same handler with res.vary('Cookie') should NOT fire", async () => {
    const code = `app.get('/me', (req, res) => {
  const sid = req.cookies.session;
  res.vary('Cookie');
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.json({ user: lookup(sid) });
});
`;
    const r = await analyze(code, 'me.js', 'javascript');
    expect(cacheNoVaryFindings(r.findings).length).toBe(0);
  });

  it('JS.3 — /health endpoint with no auth signal should NOT fire', async () => {
    const code = `app.get('/health', (req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.send('ok');
});
`;
    const r = await analyze(code, 'health.js', 'javascript');
    expect(cacheNoVaryFindings(r.findings).length).toBe(0);
  });

  // ---------------------------------------------------------------------------
  // Python — Flask / FastAPI
  // ---------------------------------------------------------------------------

  it('PY.1 — Flask handler with request.cookies + Cache-Control public + no Vary should fire', async () => {
    const code = `from flask import Flask, request, make_response
app = Flask(__name__)

@app.route('/profile')
def profile():
    sid = request.cookies.get('session')
    resp = make_response(render_user(sid))
    resp.headers['Cache-Control'] = 'public, max-age=3600'
    return resp
`;
    const r = await analyze(code, 'profile.py', 'python');
    expect(cacheNoVaryFindings(r.findings).length).toBeGreaterThanOrEqual(1);
  });

  it('PY.2 — Flask handler with @vary_on_cookie decorator should NOT fire', async () => {
    const code = `from flask import Flask, request, make_response
from flask.views import vary_on_cookie
app = Flask(__name__)

@app.route('/profile')
@vary_on_cookie
def profile():
    sid = request.cookies.get('session')
    resp = make_response(render_user(sid))
    resp.headers['Cache-Control'] = 'public, max-age=3600'
    return resp
`;
    const r = await analyze(code, 'profile.py', 'python');
    expect(cacheNoVaryFindings(r.findings).length).toBe(0);
  });

  it('PY.3 — FastAPI public /version with no auth signal should NOT fire', async () => {
    const code = `from fastapi import FastAPI
from fastapi.responses import JSONResponse

app = FastAPI()

@app.get('/version')
def version():
    return JSONResponse(
        {'v': '1.0'},
        headers={'Cache-Control': 'public, max-age=300'},
    )
`;
    const r = await analyze(code, 'version.py', 'python');
    expect(cacheNoVaryFindings(r.findings).length).toBe(0);
  });

  // ---------------------------------------------------------------------------
  // Go — net/http
  // ---------------------------------------------------------------------------

  it('GO.1 — net/http handler with r.Cookie + Cache-Control public + no Vary should fire', async () => {
    const code = `package main

import (
\t"fmt"
\t"net/http"
)

func profile(w http.ResponseWriter, r *http.Request) {
\tc, _ := r.Cookie("session")
\tw.Header().Set("Cache-Control", "public, max-age=3600")
\tfmt.Fprintln(w, lookup(c.Value))
}
`;
    const r = await analyze(code, 'main.go', 'go');
    expect(cacheNoVaryFindings(r.findings).length).toBeGreaterThanOrEqual(1);
  });

  it('GO.2 — Same handler with Vary: Cookie should NOT fire', async () => {
    const code = `package main

import (
\t"fmt"
\t"net/http"
)

func profile(w http.ResponseWriter, r *http.Request) {
\tc, _ := r.Cookie("session")
\tw.Header().Set("Vary", "Cookie")
\tw.Header().Set("Cache-Control", "public, max-age=3600")
\tfmt.Fprintln(w, lookup(c.Value))
}
`;
    const r = await analyze(code, 'main.go', 'go');
    expect(cacheNoVaryFindings(r.findings).length).toBe(0);
  });

  it('GO.3 — Static-asset handler with no cookie/auth read should NOT fire', async () => {
    const code = `package main

import "net/http"

func assets(w http.ResponseWriter, r *http.Request) {
\tw.Header().Set("Cache-Control", "public, max-age=86400")
\thttp.ServeFile(w, r, "/var/static/app.js")
}
`;
    const r = await analyze(code, 'main.go', 'go');
    expect(cacheNoVaryFindings(r.findings).length).toBe(0);
  });

  // ---------------------------------------------------------------------------
  // Java — Spring
  // ---------------------------------------------------------------------------

  it('JAVA.1 — Spring handler with @CookieValue + setHeader Cache-Control public + no Vary should fire', async () => {
    const code = `import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import javax.servlet.http.HttpServletResponse;

@RestController
public class ProfileController {
    @GetMapping("/profile")
    public ResponseEntity<String> profile(@CookieValue("session") String sid, HttpServletResponse resp) {
        resp.setHeader("Cache-Control", "public, max-age=3600");
        return ResponseEntity.ok(lookup(sid));
    }
}
`;
    const r = await analyze(code, 'ProfileController.java', 'java');
    expect(cacheNoVaryFindings(r.findings).length).toBeGreaterThanOrEqual(1);
  });

  it('JAVA.2 — Same handler with addHeader("Vary","Cookie") should NOT fire', async () => {
    const code = `import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import javax.servlet.http.HttpServletResponse;

@RestController
public class ProfileController {
    @GetMapping("/profile")
    public ResponseEntity<String> profile(@CookieValue("session") String sid, HttpServletResponse resp) {
        resp.addHeader("Vary", "Cookie");
        resp.setHeader("Cache-Control", "public, max-age=3600");
        return ResponseEntity.ok(lookup(sid));
    }
}
`;
    const r = await analyze(code, 'ProfileController.java', 'java');
    expect(cacheNoVaryFindings(r.findings).length).toBe(0);
  });

  it('JAVA.3 — Public CDN endpoint with no auth annotation should NOT fire', async () => {
    const code = `import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import javax.servlet.http.HttpServletResponse;

@RestController
public class VersionController {
    @GetMapping("/static/version")
    public ResponseEntity<String> version(HttpServletResponse resp) {
        resp.setHeader("Cache-Control", "public, max-age=86400");
        return ResponseEntity.ok("1.0");
    }
}
`;
    const r = await analyze(code, 'VersionController.java', 'java');
    expect(cacheNoVaryFindings(r.findings).length).toBe(0);
  });
});
