/** A small TypeScript service used by the reach and dead-code tests. */

import type { TsSourceFile } from '../../src/navigation/index.js';

export const APP: Record<string, string> = {
  'src/server.ts': [
    "import express from 'express';",
    "import { listUsers, getUser } from './users';",
    "import { audit } from './audit';",
    'const app = express();',
    "app.get('/users', listUsers);",
    "app.post('/users/:id', (req, res) => { audit(req); res.send(getUser(req.params.id)); });",
    'export default app;',
  ].join('\n'),
  'src/users.ts': [
    "import { Repo } from './repo';",
    'const repo = new Repo();',
    'export function listUsers(req: any, res: any) { res.json(repo.all()); }',
    'export function getUser(id: string) { return repo.find(id); }',
    'export function unusedHelper() { return formatName("x"); }',
    'function formatName(s: string) { return s.toUpperCase(); }',
    'export function onlyByName(x: any) { x.mystery(); }',
  ].join('\n'),
  'src/repo.ts': [
    'export interface Store { all(): string[]; }',
    'export class Repo implements Store {',
    '  private rows: string[] = [];',
    '  all() { return this.rows; }',
    '  find(id: string) { return this.rows.find(r => r === id); }',
    '  legacy() { return 1; }',
    '  mystery() { return 2; }',
    '}',
  ].join('\n'),
  'src/audit.ts': [
    'export function audit(req: any) { const fn = pick(); fn(req); }',
    'function pick() { return (r: any) => r; }',
    'export function escaped() { return 3; }',
    'export const handlers = { escaped };',
  ].join('\n'),
  'src/cli.ts': "import { getUser } from './users';\nconsole.log(getUser(process.argv[2]));",
  'src/nest.ts': [
    "import { Controller, Get, Injectable } from '@nestjs/common';",
    '@Injectable()',
    'export class Svc { constructor() {} hello() { return "hi"; } }',
    "@Controller('greet')",
    'export class GreetController {',
    '  constructor(private svc: Svc) {}',
    "  @Get('/:name')",
    '  greet() { return this.svc.hello(); }',
    '}',
  ].join('\n'),
  'src/users.test.ts': [
    "import { unusedHelper } from './users';",
    "describe('users', () => { it('helps', () => { unusedHelper(); }); });",
  ].join('\n'),
  'src/types.ts': 'export interface Shape { area(): number; }\nexport type Id = string;\ndeclare function ambient(): void;',
};

export const PACKAGE_JSON = JSON.stringify({
  name: 'svc',
  main: 'dist/server.js',
  bin: { svc: './dist/cli.js' },
  exports: { '.': './dist/server.js', './package.json': './package.json' },
});

export const files = (extra: Record<string, string> = {}): TsSourceFile[] =>
  Object.entries({ ...APP, ...extra }).map(([path, code]) => ({ path, code, ids: { packageName: 'svc' } }));
