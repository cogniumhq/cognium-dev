#!/usr/bin/env node
/**
 * circle-ir perf harness — cognium-dev #263.
 *
 * Runs the built engine (from `dist/`) against three synthetic Java
 * corpora and reports wall-clock, throughput, memory, and per-pass
 * timings. Baseline lives in `BASELINE.md`; regressions in throughput
 * on subsequent perf work should re-run this harness and update the
 * baseline (or add a CI perf gate — deferred).
 *
 * Why synthetic rather than a curated OSS corpus:
 *   - Reproducible without checking in a large binary blob.
 *   - Deterministic — every run produces the same wall-clock target.
 *   - Fixture-selection is a genuine design question; adding
 *     real-corpus support (`--corpus <dir>` flag) is a follow-up.
 *
 * Usage:
 *   node perf/harness.mjs             # small + medium tiers, JSON to stderr
 *   node perf/harness.mjs --json      # machine-readable JSON to stdout
 *   node perf/harness.mjs --large     # add the large tier (slower)
 *   node perf/harness.mjs --tier=medium  # only run a specific tier
 *   node perf/harness.mjs --iters=5   # override iteration count per tier
 *
 * Requires: `npm run build` has produced `dist/`.
 */

import { performance } from 'node:perf_hooks';

// ---------------------------------------------------------------------------
// CLI argument parsing (zero-dep)
// ---------------------------------------------------------------------------

const args = new Set(process.argv.slice(2));
const kvArg = (name, fallback) => {
  for (const a of process.argv.slice(2)) {
    if (a.startsWith(`--${name}=`)) return a.slice(name.length + 3);
  }
  return fallback;
};

const wantJson = args.has('--json');
const includeLarge = args.has('--large');
const onlyTier = kvArg('tier', null); // 'small' | 'medium' | 'large' | null
const iterations = Number(kvArg('iters', '3'));

// ---------------------------------------------------------------------------
// Analyzer import — from the built dist (so this also smoke-tests the ship)
// ---------------------------------------------------------------------------

const { initAnalyzer, analyze } = await import('../dist/analyzer.js');

// Turn on per-pass timers before initAnalyzer runs (they're read at
// pass-registration time, harmless here but consistent).
globalThis.__circleIrPassTiming = false; // opt-in per tier below.

await initAnalyzer();

// ---------------------------------------------------------------------------
// Deterministic synthetic Java generators
// ---------------------------------------------------------------------------

/** A "small" file — a single servlet-shaped class with taint source → sink. */
function smallTierFile() {
  return `package example.small;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

public class SmallController {
  public void handle(HttpServletRequest req, HttpServletResponse res) throws Exception {
    String id = req.getParameter("id");
    String name = req.getParameter("name");
    Connection conn = DriverManager.getConnection("jdbc:h2:mem:test");
    Statement stmt = conn.createStatement();
    stmt.execute("SELECT * FROM users WHERE id = " + id);
    stmt.execute("UPDATE users SET name = '" + name + "' WHERE id = " + id);
    conn.close();
  }

  public void safeHandle(HttpServletRequest req) throws Exception {
    String id = req.getParameter("id");
    if (!id.matches("[0-9]+")) { throw new IllegalArgumentException(); }
    Connection conn = DriverManager.getConnection("jdbc:h2:mem:test");
    java.sql.PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
    ps.setString(1, id);
    ps.execute();
    conn.close();
  }
}
`;
}

/** A pseudo-random-but-deterministic file for the medium tier. */
function mediumTierFile(seed) {
  // Deterministic seeded shape variation. Each seed produces a
  // different class name + method count + taint-shape mix without
  // needing an RNG library.
  const kinds = ['SqlHandler', 'FileHandler', 'XssRenderer', 'CmdRunner', 'PathResolver'];
  const kind = kinds[seed % kinds.length];
  const className = `${kind}${seed}`;
  const methodCount = 3 + (seed % 4); // 3-6 methods per file
  const methods = [];
  for (let m = 0; m < methodCount; m++) {
    const kindForMethod = (seed + m) % 5;
    methods.push(mediumMethodBody(m, kindForMethod));
  }
  return `package example.medium;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.sql.PreparedStatement;
import java.io.File;
import java.io.FileInputStream;
import java.io.PrintWriter;

public class ${className} {
${methods.join('\n\n')}
}
`;
}

function mediumMethodBody(idx, kind) {
  const name = `handle${idx}`;
  switch (kind) {
    case 0: // SQLi
      return `  public void ${name}(HttpServletRequest req) throws Exception {
    String q = req.getParameter("q");
    Connection c = DriverManager.getConnection("jdbc:h2:mem:test");
    Statement s = c.createStatement();
    s.execute("SELECT * FROM t WHERE x = '" + q + "'");
    c.close();
  }`;
    case 1: // Path traversal
      return `  public void ${name}(HttpServletRequest req) throws Exception {
    String p = req.getParameter("path");
    File f = new File("/data/" + p);
    FileInputStream in = new FileInputStream(f);
    in.close();
  }`;
    case 2: // XSS
      return `  public void ${name}(HttpServletRequest req, HttpServletResponse res) throws Exception {
    String msg = req.getParameter("msg");
    PrintWriter w = res.getWriter();
    w.println("<div>" + msg + "</div>");
    w.close();
  }`;
    case 3: // Command injection
      return `  public void ${name}(HttpServletRequest req) throws Exception {
    String host = req.getParameter("host");
    Process p = Runtime.getRuntime().exec("ping " + host);
    p.waitFor();
  }`;
    case 4: // Safe (parameterized SQL)
      return `  public int ${name}(HttpServletRequest req) throws Exception {
    String id = req.getParameter("id");
    if (!id.matches("[0-9]+")) return -1;
    Connection c = DriverManager.getConnection("jdbc:h2:mem:test");
    PreparedStatement ps = c.prepareStatement("SELECT COUNT(*) FROM t WHERE x = ?");
    ps.setString(1, id);
    ps.execute();
    c.close();
    return 0;
  }`;
    default:
      return `  public void ${name}() { /* no-op */ }`;
  }
}

// ---------------------------------------------------------------------------
// Tier definitions
// ---------------------------------------------------------------------------

const TIERS = {
  small: {
    name: 'small',
    files: [
      { path: 'small/SmallController.java', code: smallTierFile() },
    ],
  },
  medium: {
    name: 'medium',
    files: Array.from({ length: 30 }, (_, i) => ({
      path: `medium/Handler${i}.java`,
      code: mediumTierFile(i),
    })),
  },
  large: {
    name: 'large',
    files: Array.from({ length: 200 }, (_, i) => ({
      path: `large/Handler${i}.java`,
      code: mediumTierFile(i * 7 + 3), // different seeds than medium
    })),
  },
};

// ---------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------

function totalLoc(files) {
  return files.reduce((acc, f) => acc + f.code.split('\n').length, 0);
}

async function runTier(tier) {
  const files = tier.files;
  const loc = totalLoc(files);
  const fileCount = files.length;

  // Warm-up: one analyze() to eat lazy WASM cost.
  await analyze(files[0].code, files[0].path, 'java');

  const iterationsResults = [];
  for (let iter = 0; iter < iterations; iter++) {
    if (global.gc) global.gc();
    const rssBefore = process.memoryUsage().rss;
    const t0 = performance.now();
    for (const f of files) {
      await analyze(f.code, f.path, 'java');
    }
    const t1 = performance.now();
    const rssAfter = process.memoryUsage().rss;
    iterationsResults.push({
      wallMs: +(t1 - t0).toFixed(2),
      throughputLocPerSec: Math.round((loc * 1000) / (t1 - t0)),
      rssDeltaMb: +((rssAfter - rssBefore) / (1024 * 1024)).toFixed(2),
    });
  }

  const wallMsSorted = iterationsResults.map((r) => r.wallMs).sort((a, b) => a - b);
  const median = wallMsSorted[Math.floor(wallMsSorted.length / 2)];
  const min = wallMsSorted[0];
  const max = wallMsSorted[wallMsSorted.length - 1];

  return {
    tier: tier.name,
    files: fileCount,
    loc,
    iterations: iterationsResults,
    summary: {
      wallMsMedian: median,
      wallMsMin: min,
      wallMsMax: max,
      throughputLocPerSecMedian: Math.round((loc * 1000) / median),
      rssDeltaMbMedian: iterationsResults
        .map((r) => r.rssDeltaMb)
        .sort((a, b) => a - b)[Math.floor(iterationsResults.length / 2)],
    },
  };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

const tiersToRun = onlyTier
  ? [TIERS[onlyTier]].filter(Boolean)
  : includeLarge
    ? [TIERS.small, TIERS.medium, TIERS.large]
    : [TIERS.small, TIERS.medium];

if (tiersToRun.length === 0) {
  console.error(`Unknown tier: ${onlyTier}. Valid: small | medium | large.`);
  process.exit(2);
}

const results = [];
for (const tier of tiersToRun) {
  const r = await runTier(tier);
  results.push(r);
}

const output = {
  harness: 'circle-ir/perf/harness.mjs',
  node: process.version,
  platform: `${process.platform}-${process.arch}`,
  iterationsPerTier: iterations,
  results,
};

if (wantJson) {
  process.stdout.write(JSON.stringify(output, null, 2) + '\n');
} else {
  for (const r of results) {
    process.stderr.write(
      `[${r.tier}] files=${r.files} loc=${r.loc} ` +
        `median=${r.summary.wallMsMedian}ms ` +
        `throughput=${r.summary.throughputLocPerSecMedian} LOC/s ` +
        `rssΔ=${r.summary.rssDeltaMbMedian}MB ` +
        `(min=${r.summary.wallMsMin}ms max=${r.summary.wallMsMax}ms, n=${iterations})\n`,
    );
  }
  process.stderr.write(
    `\nnode=${output.node} platform=${output.platform}\n` +
      `run with --json for machine-readable output.\n`,
  );
}
