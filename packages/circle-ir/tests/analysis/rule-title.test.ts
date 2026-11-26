/**
 * ruleTitle(): a short title for every rule id a finding can carry, so a
 * consumer can label findings by rule without a table of its own.
 */

import { describe, it, expect } from 'vitest';
import { ruleTitle } from '../../src/index.js';
import { RULE_DEFINITIONS } from '../../src/analysis/rules.js';

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
    expect(ruleTitle('sync-io-async')).toBe('Sync I/O async');
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
});
