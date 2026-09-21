/**
 * Tests for mass-assignment (CWE-915, category: security).
 *
 * This pass covers only the SYNTACTIC splat/spread forms — `Model(**request.form)`,
 * `{ ...req.body }`. The discrete-argument forms (`Object.assign(user, req.body)`)
 * are a taint sink handled elsewhere, so a test asserting those fire here would
 * be asserting the wrong thing.
 */
import { describe, it, expect } from 'vitest';
import { MassAssignmentPass } from '../../../src/analysis/passes/mass-assignment-pass.js';
import { makeIR, makeCtx } from './_pass-fixtures.js';

const run = (code: string, language: string) => {
  const ir = makeIR({
    meta: {
      circle_ir: '3.0',
      file: language === 'python' ? 'views.py' : 'routes.js',
      language,
      loc: code.split('\n').length,
      hash: '',
    },
  });
  const ctx = makeCtx(ir, code, language);
  new MassAssignmentPass().run(ctx);
  return ctx;
};

describe('MassAssignmentPass', () => {
  describe('Python kwargs splat', () => {
    it.each([
      ['User(**request.form)', 'form'],
      ['User(**request.json)', 'json'],
      ['User(**request.get_json())', 'get_json()'],
      ['User(**request.args)', 'args'],
      ['User.objects.create(**request.values)', 'Django create'],
    ])('flags %s', (line) => {
      const ctx = run(`def h():\n    return ${line}`, 'python');
      expect(ctx.findings).toHaveLength(1);
      expect(ctx.findings[0].cwe).toBe('CWE-915');
      expect(ctx.findings[0].severity).toBe('high');
    });

    it('does not flag a splat of a non-request mapping', () => {
      const ctx = run('def h():\n    return User(**defaults)', 'python');
      expect(ctx.findings).toHaveLength(0);
    });

    it('does not flag an explicit allow-listed construction', () => {
      const ctx = run('def h():\n    return User(name=request.form["name"])', 'python');
      expect(ctx.findings).toHaveLength(0);
    });
  });

  describe('JS object spread', () => {
    it.each([
      'const u = { ...req.body };',
      'const u = { ...req.query };',
      'const u = { ...request.params };',
      'await User.create({ ...req.body });',
      'await user.update({ ...ctx.request.body });',
    ])('flags %s', (line) => {
      const ctx = run(`function h(req) {\n  ${line}\n}`, 'javascript');
      expect(ctx.findings).toHaveLength(1);
    });

    it('does not flag spreading a non-request object', () => {
      const ctx = run('function h() {\n  const u = { ...defaults };\n}', 'javascript');
      expect(ctx.findings).toHaveLength(0);
    });

    it('does not flag an explicit field pick', () => {
      const ctx = run('function h(req) {\n  const u = { name: req.body.name };\n}', 'javascript');
      expect(ctx.findings).toHaveLength(0);
    });
  });

  it('reports the offending line number', () => {
    const ctx = run('function h(req) {\n  log();\n  const u = { ...req.body };\n}', 'javascript');
    expect(ctx.findings).toHaveLength(1);
    expect(ctx.findings[0].line).toBe(3);
  });

  it('does nothing without source text', () => {
    const ir = makeIR({ meta: { circle_ir: '3.0', file: 'x.py', language: 'python', loc: 0, hash: '' } });
    const ctx = makeCtx(ir, '', 'python');
    new MassAssignmentPass().run(ctx);
    expect(ctx.findings).toHaveLength(0);
  });
});
