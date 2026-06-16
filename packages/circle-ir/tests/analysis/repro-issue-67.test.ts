/**
 * cognium-dev#67 — TypeScript NestJS / Angular method + parameter decorators
 * were not extracted (`method.annotations: []`, `param.annotations: []`),
 * so the annotation-based source path in `taint-matcher.ts` never matched
 * on TypeScript code. `@Query` was only accidentally caught via the
 * unrelated Axum `{ method: 'Query', return_tainted: true }` rule;
 * `@Param` / `@Body` had no fallback at all.
 *
 * Fix (src/core/extractors/types.ts):
 *   1. `extractDecoratorName` covers all four decorator shapes
 *      (`@Foo`, `@Foo(...)`, `@ns.Foo`, `@ns.Foo(...)`).
 *   2. `extractJSMethods` accumulates `decorator` siblings inside `class_body`
 *      and attaches them to the next `method_definition`. Pending decorators
 *      are reset on ANY non-decorator class member to prevent a decorated
 *      field's annotation from leaking onto the following method.
 *   3. `extractJSParameters` scans `required_parameter` / `optional_parameter`
 *      children for nested `decorator` nodes.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

describe('cognium-dev#67 — TypeScript NestJS decorator extraction', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const NESTJS_CONTROLLER = `
import { Controller, Get, Post, Query, Param, Body } from '@nestjs/common';
import { Repository } from 'typeorm';

declare const db: { query: (sql: string) => Promise<any> };

interface User {
  id: number;
  name: string;
}

@Controller('users')
export class UsersController {
  constructor(private readonly repo: Repository<User>) {}

  @Get('search')
  async search(@Query('q') q: string): Promise<User[]> {
    // Template-literal SQLi
    const sql = \`SELECT * FROM users WHERE name LIKE '%\${q}%'\`;
    return db.query(sql);
  }

  @Get(':id')
  async findOne(@Param('id') id: string): Promise<User> {
    // Another template-literal SQLi
    return db.query(\`SELECT * FROM users WHERE id = \${id}\`);
  }

  @Post()
  async create(@Body() body: { name: string }): Promise<void> {
    await db.query(\`INSERT INTO users (name) VALUES ('\${body.name}')\`);
  }
}
`;

  it('extracts method + parameter decorators on NestJS controller', async () => {
    const r = await analyze(NESTJS_CONTROLLER, 'users.controller.ts', 'typescript');

    // The IR contract: tree-sitter parses cleanly, and the extractor surfaces
    // decorators on both methods and their parameters.
    expect(r.parse_status?.errorCount ?? 0).toBe(0);

    const controller = (r.types ?? []).find(t => t.name === 'UsersController');
    expect(controller).toBeDefined();
    const search = controller!.methods.find(m => m.name === 'search');
    const findOne = controller!.methods.find(m => m.name === 'findOne');
    const create = controller!.methods.find(m => m.name === 'create');
    expect(search).toBeDefined();
    expect(findOne).toBeDefined();
    expect(create).toBeDefined();

    // Method-level decorators are attached.
    expect(search!.annotations).toContain('Get');
    expect(findOne!.annotations).toContain('Get');
    expect(create!.annotations).toContain('Post');

    // Parameter decorators are attached on the right parameter.
    const qParam = search!.parameters.find(p => p.name === 'q');
    const idParam = findOne!.parameters.find(p => p.name === 'id');
    const bodyParam = create!.parameters.find(p => p.name === 'body');
    expect(qParam?.annotations).toContain('Query');
    expect(idParam?.annotations).toContain('Param');
    expect(bodyParam?.annotations).toContain('Body');
  });

  it('NestJS controller fires SQL injection findings via parameter decorators', async () => {
    const r = await analyze(NESTJS_CONTROLLER, 'users.controller.ts', 'typescript');
    const sqliFlows = r.taint.flows.filter(f => f.sink_type === 'sql_injection');
    expect(sqliFlows.length).toBeGreaterThanOrEqual(2);
  });

  it('decorator on a field does NOT leak onto the next method (issue review #1)', async () => {
    // Regression guard for the pending-decorator reset rule: a decorated
    // field between two methods must not transfer its decorator to the
    // method below it. Without the per-iteration reset in extractJSMethods,
    // `search.annotations` would incorrectly include `Inject`.
    const code = `
import { Controller, Get, Inject } from '@nestjs/common';

@Controller('users')
export class UsersController {
  @Inject('USER_REPO') private repo: any;

  @Get('search')
  async search(): Promise<void> {}
}
`;
    const r = await analyze(code, 'users.controller.ts', 'typescript');
    const controller = (r.types ?? []).find(t => t.name === 'UsersController');
    const search = controller?.methods.find(m => m.name === 'search');
    expect(search).toBeDefined();
    // Must NOT contain Inject — that decorator belongs to `repo`, not `search`.
    expect(search!.annotations).not.toContain('Inject');
    // The legitimate decorator must still attach.
    expect(search!.annotations).toContain('Get');
  });

  it('comment between decorator and method does NOT clear pending decorators (issue review #A)', async () => {
    // Regression guard: tree-sitter emits `// ...` comments as anonymous
    // children of `class_body`. The pending-decorator reset rule must
    // skip comment nodes — otherwise a `// note` line between
    // `@Get('search')` and the method below would silently drop the
    // decorator from `search.annotations`.
    const code = `
import { Controller, Get } from '@nestjs/common';

@Controller('users')
export class UsersController {
  @Get('search')
  // doc comment between decorator and method
  async search(): Promise<void> {}
}
`;
    const r = await analyze(code, 'users.controller.ts', 'typescript');
    const controller = (r.types ?? []).find(t => t.name === 'UsersController');
    const search = controller?.methods.find(m => m.name === 'search');
    expect(search).toBeDefined();
    expect(search!.annotations).toContain('Get');
  });

  it('extracts decorators of all four grammar shapes', async () => {
    // @Foo            → decorator > identifier
    // @Foo('bar')     → decorator > call_expression > identifier
    // @ns.Foo         → decorator > member_expression
    // @ns.Foo('bar')  → decorator > call_expression > member_expression
    const code = `
import { Get, ns } from 'somewhere';

class C {
  @Bare
  @Called('arg')
  @ns.Member
  @ns.MemberCalled('arg')
  m(): void {}
}
`;
    const r = await analyze(code, 'c.ts', 'typescript');
    const c = (r.types ?? []).find(t => t.name === 'C');
    const m = c?.methods.find(x => x.name === 'm');
    expect(m).toBeDefined();
    expect(m!.annotations).toEqual(
      expect.arrayContaining(['Bare', 'Called', 'Member', 'MemberCalled']),
    );
  });
});
