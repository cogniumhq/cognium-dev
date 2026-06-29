/**
 * Sprint 60 — FP regression cluster (#102 + #113 + #114 + #115).
 *
 * Recall lock + FP fix verification for the four tickets:
 *
 *   - #102 / #115 — Rust safe_handler (Command fixed-argv, HashSet host
 *     allowlist, canonicalize().starts_with path guard) — shipped 3.84.0,
 *     locked here.
 *   - #114 — Python safe-handler (urlparse netloc allow-list,
 *     int(qty) + range check) — shipped 3.84.0, locked here.
 *   - #113 — external_taint_escape over-fire across JS/Java/Go on benign
 *     and guarded sinks. 10/12 shipped progressively across Sprints
 *     24/29/31; the remaining two (FP-46 JS `path.basename`, FP-52 Java
 *     `Pattern.matcher`) are fixed in Sprint 60 by extending the
 *     sanitizer config table in `config-loader.ts`.
 *
 * Assertion: zero `taint.flows` entries of the claimed `sink_type`. The
 * raw `taint.sinks` array can still contain entries post-sanitization
 * (it tracks detection, not validated flows); `taint.flows` is the
 * user-visible signal post-filter.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

const sinksOfType = (
  sinks: Array<{ type?: string; line?: number }> | undefined,
  type: string,
) => (sinks ?? []).filter((s) => s.type === type);

const flowsOfType = (
  flows: Array<{ sink_type?: string }> | undefined,
  type: string,
) => (flows ?? []).filter((f) => f.sink_type === type);

describe('Sprint 60 baseline — FP cluster #102/#113/#114/#115', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // ===========================================================================
  // #102 / #115 — Rust safe-handler regression
  // ===========================================================================

  it('#115 FP-21 — Rust Command::new with fixed program + args slice: no command_injection', async () => {
    const code = `use std::process::Command;
use actix_web::{web, HttpResponse, Responder};

pub async fn run_listing(query: web::Query<std::collections::HashMap<String, String>>) -> impl Responder {
    let dir = query.get("dir").cloned().unwrap_or_default();
    let output = Command::new("ls")
        .args(&["-la", &dir])
        .output();
    match output {
        Ok(o) => HttpResponse::Ok().body(String::from_utf8_lossy(&o.stdout).to_string()),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}
`;
    const r = await analyze(code, 'safe_handler.rs', 'rust');
    expect(flowsOfType(r.taint?.flows, 'command_injection').length).toBe(0);
  });

  it('#115 FP-23 — Rust HashSet host allowlist before reqwest: no ssrf', async () => {
    const code = `use std::collections::HashSet;
use actix_web::{web, HttpResponse, Responder};

pub async fn fetch(query: web::Query<std::collections::HashMap<String, String>>) -> impl Responder {
    let allowed: HashSet<&str> = ["trusted.com", "api.trusted.com"].iter().cloned().collect();
    let host = query.get("host").cloned().unwrap_or_default();
    if !allowed.contains(host.as_str()) {
        return HttpResponse::BadRequest().finish();
    }
    let url = format!("https://{}/data", host);
    let resp = reqwest::get(&url).await;
    match resp {
        Ok(r) => HttpResponse::Ok().body(r.text().await.unwrap_or_default()),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}
`;
    const r = await analyze(code, 'safe_handler.rs', 'rust');
    expect(flowsOfType(r.taint?.flows, 'ssrf').length).toBe(0);
  });

  it('#115 FP-22a — Rust canonicalize().starts_with(root) before file read: no xss', async () => {
    const code = `use std::path::PathBuf;
use actix_web::{web, HttpResponse, Responder};

pub async fn read_file(query: web::Query<std::collections::HashMap<String, String>>) -> impl Responder {
    let root = PathBuf::from("/srv/uploads");
    let rel = query.get("name").cloned().unwrap_or_default();
    let full = root.join(&rel);
    let canon = match full.canonicalize() {
        Ok(p) => p,
        Err(_) => return HttpResponse::BadRequest().finish(),
    };
    if !canon.starts_with(&root) {
        return HttpResponse::BadRequest().finish();
    }
    let body = std::fs::read_to_string(canon).unwrap_or_default();
    HttpResponse::Ok().body(body)
}
`;
    const r = await analyze(code, 'safe_handler.rs', 'rust');
    expect(flowsOfType(r.taint?.flows, 'xss').length).toBe(0);
  });

  // ===========================================================================
  // #114 — Python safe-handler regression
  // ===========================================================================

  it('#114 defect-1 — Python urlparse(target).netloc in ALLOWED_HOSTS before redirect: no open_redirect', async () => {
    const code = `from flask import Flask, request, redirect
from urllib.parse import urlparse

app = Flask(__name__)
ALLOWED_HOSTS = {"trusted.com", "www.trusted.com"}

@app.route("/fetch")
def fetch():
    target = request.args.get("url", "")
    host = urlparse(target).netloc
    if host not in ALLOWED_HOSTS:
        return "blocked", 400
    return redirect(target)
`;
    const r = await analyze(code, 'safe_permissive_allowlist.py', 'python');
    expect(flowsOfType(r.taint?.flows, 'open_redirect').length).toBe(0);
  });

  it('#114 defect-2 — Python int(qty) with range-check then numeric output: no xss', async () => {
    const code = `from flask import Flask, request

app = Flask(__name__)
MAX_QTY = 1000
UNIT_PRICE = 9

@app.route("/order")
def order():
    qty = int(request.args.get("qty", "0"))
    if qty < 1 or qty > MAX_QTY:
        return "qty out of range", 400
    items = [None] * qty
    return "total=" + str(qty * UNIT_PRICE) + " items=" + str(len(items))
`;
    const r = await analyze(code, 'safe_quantity_validation.py', 'python');
    expect(flowsOfType(r.taint?.flows, 'xss').length).toBe(0);
  });

  // ===========================================================================
  // #113 — external_taint_escape over-fire (JS / Java / Go)
  // ===========================================================================

  it('#113 FP-45 — JS allow-list before process.env write: no external_taint_escape', async () => {
    const code = `const express = require('express');
const app = express();
const ALLOWED = new Set(['DEBUG', 'LOG_LEVEL']);

app.post('/config', (req, res) => {
  const key = req.body.key;
  const value = req.body.value;
  if (!ALLOWED.has(key)) {
    return res.status(400).send('bad key');
  }
  process.env[key] = value;
  res.sendStatus(200);
});
`;
    const r = await analyze(code, 'safe_ext_control_config.js', 'javascript');
    expect(flowsOfType(r.taint?.flows, 'external_taint_escape').length).toBe(0);
  });

  it('#113 FP-46 — JS path.basename + atomic wx open: no external_taint_escape', async () => {
    const code = `const express = require('express');
const path = require('path');
const fs = require('fs');
const app = express();

app.post('/upload', (req, res) => {
  const name = path.basename(req.body.name);
  const dest = path.join('/srv/uploads', name);
  const fd = fs.openSync(dest, 'wx');
  fs.writeSync(fd, req.body.data);
  fs.closeSync(fd);
  res.sendStatus(200);
});
`;
    const r = await analyze(code, 'safe_toctou.js', 'javascript');
    expect(flowsOfType(r.taint?.flows, 'external_taint_escape').length).toBe(0);
  });

  it('#113 FP-47 — JS qty range-validated numeric only: no external_taint_escape', async () => {
    const code = `const express = require('express');
const app = express();
const MAX_QTY = 1000;
const UNIT_PRICE = 9;

app.get('/order', (req, res) => {
  const qty = parseInt(req.query.qty, 10);
  if (qty < 1 || qty > MAX_QTY) {
    return res.status(400).send('qty out of range');
  }
  const total = qty * UNIT_PRICE;
  res.json({ total });
});
`;
    const r = await analyze(code, 'safe_quantity_validation.js', 'javascript');
    expect(flowsOfType(r.taint?.flows, 'external_taint_escape').length).toBe(0);
  });

  it('#113 FP-48 — JS index bounds-checked: no external_taint_escape', async () => {
    const code = `const express = require('express');
const app = express();
const items = ['a', 'b', 'c'];

app.get('/item', (req, res) => {
  const i = parseInt(req.query.i, 10);
  if (i < 0 || i >= items.length) {
    return res.status(400).send('bad index');
  }
  res.json({ item: items[i] });
});
`;
    const r = await analyze(code, 'safe_range_min_check.js', 'javascript');
    expect(flowsOfType(r.taint?.flows, 'external_taint_escape').length).toBe(0);
  });

  it('#113 FP-49 — JS static regex + numeric count: no external_taint_escape', async () => {
    const code = `const express = require('express');
const app = express();
const DIGITS = /\\d/g;

app.get('/count', (req, res) => {
  const text = String(req.query.text || '');
  const matches = text.match(DIGITS);
  const count = matches ? matches.length : 0;
  res.json({ count });
});
`;
    const r = await analyze(code, 'safe_executable_regex.js', 'javascript');
    expect(flowsOfType(r.taint?.flows, 'external_taint_escape').length).toBe(0);
  });

  it('#113 FP-50 — Java Set.contains allowlist before System.setProperty: no external_taint_escape', async () => {
    const code = `package demo;
import java.util.Set;
import javax.servlet.http.*;
import java.io.IOException;

public class SafeExtControlConfig extends HttpServlet {
    private static final Set<String> ALLOWED = Set.of("DEBUG", "LOG_LEVEL");

    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String key = req.getParameter("key");
        String value = req.getParameter("value");
        if (!ALLOWED.contains(key)) {
            resp.sendError(400);
            return;
        }
        System.setProperty(key, value);
    }
}
`;
    const r = await analyze(code, 'SafeExtControlConfig.java', 'java');
    expect(flowsOfType(r.taint?.flows, 'external_taint_escape').length).toBe(0);
  });

  it('#113 FP-51 — Java Pattern.matches email validation: no external_taint_escape', async () => {
    const code = `package demo;
import java.util.regex.Pattern;
import javax.servlet.http.*;
import java.io.IOException;

public class SafeImproperValidation extends HttpServlet {
    private static final String EMAIL_RE = "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\\\.[A-Za-z]{2,}$";

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String email = req.getParameter("email");
        if (!Pattern.matches(EMAIL_RE, email)) {
            resp.sendError(400);
            return;
        }
        resp.getWriter().write("welcome " + email);
    }
}
`;
    const r = await analyze(code, 'SafeImproperValidation.java', 'java');
    expect(flowsOfType(r.taint?.flows, 'external_taint_escape').length).toBe(0);
  });

  it('#113 FP-52 — Java static DIGITS pattern + numeric: no external_taint_escape', async () => {
    const code = `package demo;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import javax.servlet.http.*;
import java.io.IOException;

public class SafeExecutableRegex extends HttpServlet {
    private static final Pattern DIGITS = Pattern.compile("\\\\d");

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String text = req.getParameter("text");
        Matcher m = DIGITS.matcher(text);
        int count = 0;
        while (m.find()) count++;
        resp.getWriter().write("count=" + count);
    }
}
`;
    const r = await analyze(code, 'SafeExecutableRegex.java', 'java');
    expect(flowsOfType(r.taint?.flows, 'external_taint_escape').length).toBe(0);
  });

  it('#113 FP-53 — Go filepath.Base + O_EXCL: no external_taint_escape', async () => {
    const code = `package main

import (
    "net/http"
    "os"
    "path/filepath"
)

func upload(w http.ResponseWriter, r *http.Request) {
    name := filepath.Base(r.FormValue("name"))
    dest := filepath.Join("/srv/uploads", name)
    f, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
    if err != nil {
        http.Error(w, "exists", 400)
        return
    }
    defer f.Close()
    f.WriteString(r.FormValue("data"))
}
`;
    const r = await analyze(code, 'safe_toctou.go', 'go');
    expect(flowsOfType(r.taint?.flows, 'external_taint_escape').length).toBe(0);
  });

  it('#113 FP-54 — Go size clamped to maxAllocBytes: no external_taint_escape', async () => {
    const code = `package main

import (
    "net/http"
    "strconv"
)

const maxAllocBytes = 1 << 20

func alloc(w http.ResponseWriter, r *http.Request) {
    raw := r.FormValue("size")
    n, err := strconv.Atoi(raw)
    if err != nil || n < 0 || n > maxAllocBytes {
        http.Error(w, "bad size", 400)
        return
    }
    buf := make([]byte, n)
    w.Write([]byte(strconv.Itoa(len(buf))))
}
`;
    const r = await analyze(code, 'safe_unbounded_allocation.go', 'go');
    expect(flowsOfType(r.taint?.flows, 'external_taint_escape').length).toBe(0);
  });

  it('#113 FP-55 — Go regex MatchString email: no external_taint_escape', async () => {
    const code = `package main

import (
    "net/http"
    "regexp"
)

var emailRe = regexp.MustCompile(` + '`^[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}$`' + `)

func welcome(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    if !emailRe.MatchString(email) {
        http.Error(w, "bad email", 400)
        return
    }
    w.Write([]byte("welcome " + email))
}
`;
    const r = await analyze(code, 'safe_improper_validation.go', 'go');
    expect(flowsOfType(r.taint?.flows, 'external_taint_escape').length).toBe(0);
  });

  it('#113 FP-56 — Go log.Printf with username: no external_taint_escape (application logging, not a sphere escape)', async () => {
    const code = `package main

import (
    "log"
    "net/http"
)

func access(w http.ResponseWriter, r *http.Request) {
    user := r.FormValue("user")
    log.Printf("access by %s", user)
    w.WriteHeader(200)
}
`;
    const r = await analyze(code, 'safe_sensitive_data_logging.go', 'go');
    expect(flowsOfType(r.taint?.flows, 'external_taint_escape').length).toBe(0);
  });
});
