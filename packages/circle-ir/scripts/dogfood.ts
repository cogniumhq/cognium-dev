#!/usr/bin/env npx tsx
/**
 * Self-analysis (dogfood) script.
 *
 * Runs circle-ir against its own TypeScript source code to detect
 * regressions and verify the build output works end-to-end.
 *
 * Exit code 0: no unexpected high-confidence findings.
 * Exit code 1: new high-confidence taint flow detected — needs review.
 */

import { initAnalyzer, analyze } from '../dist/index.js';
import type { SupportedLanguage } from '../dist/index.js';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/** Confidence threshold — flows above this are flagged as unexpected. */
const CONFIDENCE_THRESHOLD = 0.8;

/**
 * Known-safe findings that are intentional.
 * Format: "relative/file/path:line"
 */
const ALLOWLIST = new Set([
  // Intentional new Function() to hide dynamic imports from bundlers.
  'src/core/parser.ts:28',
]);

function collectTSFiles(dir: string): string[] {
  const files: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...collectTSFiles(fullPath));
    } else if (entry.name.endsWith('.ts') && !entry.name.endsWith('.d.ts')) {
      files.push(fullPath);
    }
  }
  return files;
}

async function main() {
  const projectRoot = path.resolve(__dirname, '..');
  const srcDir = path.join(projectRoot, 'src');

  console.log('=== Circle-IR Self-Analysis (Dogfood) ===\n');

  await initAnalyzer();

  const files = collectTSFiles(srcDir);
  console.log(`Analyzing ${files.length} source files...\n`);

  let totalSources = 0;
  let totalSinks = 0;
  let totalFlows = 0;
  let errors = 0;

  interface UnexpectedFlow {
    file: string;
    sourceLine: number;
    sourceType: string;
    sinkLine: number;
    sinkType: string;
    confidence: number;
  }

  const unexpected: UnexpectedFlow[] = [];

  for (const filePath of files) {
    const relPath = path.relative(projectRoot, filePath);
    const code = fs.readFileSync(filePath, 'utf-8');

    try {
      const ir = await analyze(code, relPath, 'javascript' as SupportedLanguage);

      const sources = ir.taint?.sources ?? [];
      const sinks = ir.taint?.sinks ?? [];
      const flows = ir.taint?.flows ?? [];

      totalSources += sources.length;
      totalSinks += sinks.length;
      totalFlows += flows.length;

      for (const flow of flows) {
        const confidence = flow.confidence ?? 0;
        if (confidence <= CONFIDENCE_THRESHOLD) continue;

        // Check each path step against the allowlist.
        const isAllowlisted = (flow.path ?? []).some((step: { line: number }) => {
          const key = `${relPath}:${step.line}`;
          return ALLOWLIST.has(key);
        });

        if (!isAllowlisted) {
          unexpected.push({
            file: relPath,
            sourceLine: flow.source?.line ?? 0,
            sourceType: flow.source?.type ?? 'unknown',
            sinkLine: flow.sink?.line ?? 0,
            sinkType: flow.sink?.type ?? 'unknown',
            confidence,
          });
        }
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.log(`  ERROR ${relPath}: ${msg}`);
      errors++;
    }
  }

  // Summary
  console.log(`Files analyzed:      ${files.length}`);
  console.log(`Analysis errors:     ${errors}`);
  console.log(`Taint sources:       ${totalSources}`);
  console.log(`Taint sinks:         ${totalSinks}`);
  console.log(`Taint flows:         ${totalFlows}`);
  console.log(`Allowlisted:         ${ALLOWLIST.size}`);
  console.log(`Unexpected (>${(CONFIDENCE_THRESHOLD * 100).toFixed(0)}%): ${unexpected.length}`);

  if (unexpected.length > 0) {
    console.log('\n--- UNEXPECTED HIGH-CONFIDENCE FINDINGS ---\n');
    for (const u of unexpected) {
      console.log(`  ${u.file}`);
      console.log(`    ${u.sourceType} (line ${u.sourceLine}) -> ${u.sinkType} (line ${u.sinkLine})`);
      console.log(`    Confidence: ${(u.confidence * 100).toFixed(0)}%`);
      console.log();
    }
    console.log('FAIL: Unexpected findings detected. Review and either fix or add to ALLOWLIST.\n');
    process.exit(1);
  }

  console.log('\nPASS: No unexpected findings.\n');
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
