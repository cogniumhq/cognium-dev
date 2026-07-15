/**
 * `cognium://sast-finding-schema` resource — the canonical shape of a
 * `SastFinding` object as produced by circle-ir. Callers can consume
 * this at prompt-construction time to know which fields to expect.
 *
 * We hand-write the schema here (rather than reflecting one from the
 * TypeScript type) so it remains stable and hand-tuned for LLM
 * consumption.
 */

export const SAST_FINDING_SCHEMA = {
  $schema: 'http://json-schema.org/draft-07/schema#',
  $id: 'cognium://sast-finding-schema',
  title: 'SastFinding',
  description:
    'Deterministic security or quality finding emitted by circle-ir. Every field is populated by ' +
    'static analysis; there is no LLM in the emission path.',
  type: 'object',
  required: [
    'id',
    'pass',
    'category',
    'rule_id',
    'cwe',
    'severity',
    'level',
    'message',
    'file',
    'line',
  ],
  properties: {
    id: { type: 'string', description: 'Stable per-run id, formed as `<pass>-<file>-<line>` (or with a discriminator suffix when multiple findings collide).' },
    pass: { type: 'string', description: 'Name of the AnalysisPass that emitted the finding.' },
    category: {
      type: 'string',
      enum: ['security', 'reliability', 'performance', 'maintainability', 'architecture'],
      description: 'High-level PassCategory. Filters use this axis first.',
    },
    rule_id: { type: 'string', description: 'Canonical rule identifier — matches `docs/PASSES.md rule_id` column.' },
    cwe: { type: 'string', description: 'CWE identifier (e.g. `CWE-89`) for security findings; empty for quality findings.' },
    severity: {
      type: 'string',
      enum: ['critical', 'high', 'medium', 'low'],
      description: 'Coarse severity bucket. Not linear — critical is >2x high in practice.',
    },
    level: {
      type: 'string',
      enum: ['error', 'warning', 'note', 'none'],
      description: 'SARIF level for the finding. Maps into SARIF `result.level`.',
    },
    message: { type: 'string', description: 'Human-readable one-line description.' },
    file: { type: 'string', description: 'Repository-relative path (may be absolute when scanned outside a repo).' },
    line: { type: 'integer', description: '1-indexed line number.' },
    column: { type: 'integer', description: '1-indexed column, when available.' },
    snippet: { type: 'string', description: 'Short source excerpt (may be truncated to 2KB by this server).' },
    fix: { type: 'string', description: 'Suggested remediation code / instruction.' },
    metadata: {
      type: 'object',
      description: 'Free-form per-rule metadata (e.g. sink type, confidence, taint path id).',
      additionalProperties: true,
    },
  },
  additionalProperties: true,
} as const;
