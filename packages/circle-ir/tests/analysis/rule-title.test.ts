/**
 * ruleTitle(): a short title for every rule id a finding can carry, so a
 * consumer can label findings by rule without a table of its own.
 */

import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ruleTitle } from '../../src/index.js';
import { RULE_DEFINITIONS } from '../../src/analysis/rules.js';

/**
 * Every rule id a finding can carry, read from the source: literal
 * `rule_id: '…'` / `ruleId: '…'` values, and the pass name of each pass
 * that reports findings as `rule_id: this.name`.
 */
function reportedRuleIds(): string[] {
  const ids = new Set<string>();
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) { walk(path); continue; }
      if (!entry.name.endsWith('.ts')) continue;
      const src = readFileSync(path, 'utf8');
      for (const m of src.matchAll(/\b(?:rule_id|ruleId|RULE_ID)\s*[:=]\s*'([A-Za-z0-9_.-]+)'/g)) ids.add(m[1]);
      if (/rule_id:\s*this\.name\b/.test(src)) {
        const name = /readonly name\s*=\s*'([^']+)'/.exec(src);
        if (name) ids.add(name[1]);
      }
    }
  };
  walk(join(__dirname, '../../src'));
  return [...ids].sort();
}

describe('ruleTitle', () => {
  it('uses the rule name for a sink type', () => {
    expect(ruleTitle('sql_injection')).toBe('SQL Injection');
    expect(ruleTitle('xss')).toBe('Cross-Site Scripting (XSS)');
    for (const [id, info] of Object.entries(RULE_DEFINITIONS)) {
      expect(ruleTitle(id)).toBe(info.name);
    }
  });

  it('names a cross-file rule after its sink', () => {
    expect(ruleTitle('cross-file-sql_injection')).toBe('Cross-file SQL Injection');
    expect(ruleTitle('cross-file-path_traversal')).toBe('Cross-file Path Traversal');
  });

  it('turns a pass rule id into words, keeping acronyms', () => {
    expect(ruleTitle('variable-shadowing')).toBe('Variable shadowing');
    expect(ruleTitle('orphan-module')).toBe('Orphan module');
    expect(ruleTitle('resource-leak')).toBe('Resource leak');
    expect(ruleTitle('jwt-verify-disabled')).toBe('JWT verify disabled');
    expect(ruleTitle('html-missing-sri')).toBe('HTML missing SRI');
    expect(ruleTitle('module-side-effect')).toBe('Module side effect');
    expect(ruleTitle('cors-null-origin')).toBe('CORS null origin');
    expect(ruleTitle('xml_entity_expansion')).toBe('XML entity expansion');
  });

  it('has a set title where the words alone read badly', () => {
    expect(ruleTitle('n-plus-one')).toBe('N+1 query');
    expect(ruleTitle('todo-in-prod')).toBe('TODO in production code');
    expect(ruleTitle('missing-x-frame-options')).toBe('Missing X-Frame-Options');
  });

  it('never returns an empty title', () => {
    expect(ruleTitle('')).toBe('Unknown rule');
    expect(ruleTitle('--')).toBe('Unknown rule');
    expect(ruleTitle('some-new-rule')).toBe('Some new rule');
  });

  it('gives a plain title to the quality rules whose words alone read badly', () => {
    expect(ruleTitle('missing-public-doc')).toBe('Missing doc comment');
    expect(ruleTitle('null-deref')).toBe('Null dereference');
    expect(ruleTitle('sync-io-async')).toBe('Blocking I/O in async code');
    expect(ruleTitle('cleanup-verify')).toBe('Cleanup missed on some paths');
    expect(ruleTitle('missing-stream')).toBe('Whole file read into memory');
    expect(ruleTitle('stale-doc-ref')).toBe('Broken doc link');
    expect(ruleTitle('dependency-fan-out')).toBe('Too many imports');
    expect(ruleTitle('missing-override')).toBe('Missing @Override');
    expect(ruleTitle('god-class')).toBe('Class does too much');
    expect(ruleTitle('saturated-file')).toBe('Too many findings in one file');
  });

  it('keeps product and protocol words in their usual case', () => {
    expect(ruleTitle('html-javascript-uri')).toBe('HTML JavaScript URI');
    expect(ruleTitle('cors-http-origin')).toBe('CORS HTTP origin');
    expect(ruleTitle('mybatis-annotation-sql-sink')).toBe('MyBatis annotation SQL sink');
  });

  it('every rule a finding can carry has a plain-words title', () => {
    const ids = reportedRuleIds();
    // the walk finds the passes (a floor, so a broken walk cannot pass)
    expect(ids.length).toBeGreaterThan(80);
    expect(ids).toEqual(expect.arrayContaining(['dead-code', 'orphan-module', 'missing-public-doc', 'xss']));
    const bad = ids.filter(id => {
      const title = ruleTitle(id);
      return title === 'Unknown rule'
        || !/^[A-Z0-9]/.test(title)                       // starts with a capital
        || /[A-Za-z0-9]_[A-Za-z0-9]/.test(title)          // no snake_case
        || /\b[a-z]+-[a-z]+\b/.test(title)               // no lower-case kebab-case
        || title.length > 40;                             // short
    }).map(id => `${id} -> ${ruleTitle(id)}`);
    expect(bad).toEqual([]);
  });
});
