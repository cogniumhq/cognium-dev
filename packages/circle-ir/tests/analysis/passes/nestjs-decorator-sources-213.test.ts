/**
 * Tests for cognium-dev #213 — eighth slice: NestJS controller param
 * decorator sources.
 *
 * NestJS shares @Body/@Query/@Header/@Cookie names with FastAPI and
 * Spring (already covered) but adds unique ones: @Param (route path),
 * @Req/@Request (whole request object), @Session, @Ip (client IP),
 * @HostParam (subdomain), @UploadedFile / @UploadedFiles (multer).
 *
 * Registered without a `languages:` filter so they cover both the
 * TypeScript-first NestJS convention and any JS project adopting it.
 */

import { describe, it, beforeAll, expect } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

describe('cognium-dev #213 eighth slice — NestJS controller decorator sources', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  const hasFlow = (r: Awaited<ReturnType<typeof analyze>>) =>
    (r.taint.flows?.length ?? 0) > 0;

  it('TP — `@Param(\'id\') id: string` flows to command exec', async () => {
    const code = `import { Controller, Get, Param } from '@nestjs/common';
import { exec } from 'child_process';

@Controller('users')
class UsersController {
  @Get(':id')
  find(@Param('id') id: string) {
    exec('ls /users/' + id);
  }
}`;
    const r = await analyze(code, 'p.ts', 'typescript');
    expect(hasFlow(r)).toBe(true);
  });

  it('TP — `@Req() req` flows to command exec via req.query', async () => {
    const code = `import { Controller, Get, Req } from '@nestjs/common';
import { exec } from 'child_process';

@Controller('users')
class UsersController {
  @Get()
  find(@Req() req: any) {
    exec('echo ' + req.query.q);
  }
}`;
    const r = await analyze(code, 'r.ts', 'typescript');
    expect(hasFlow(r)).toBe(true);
  });

  it('TP — `@Ip() ip` flows to log-injection command exec', async () => {
    const code = `import { Controller, Get, Ip } from '@nestjs/common';
import { exec } from 'child_process';

@Controller('users')
class UsersController {
  @Get()
  logIp(@Ip() ip: string) {
    exec('echo ' + ip + ' >> /var/log/access.log');
  }
}`;
    const r = await analyze(code, 'ip.ts', 'typescript');
    expect(hasFlow(r)).toBe(true);
  });

  it('TP — `@UploadedFile() file` flows to path-traversal fs.writeFileSync', async () => {
    const code = `import { Controller, Post, UploadedFile } from '@nestjs/common';
import * as fs from 'fs';

@Controller('upload')
class UploadController {
  @Post()
  upload(@UploadedFile() file: any) {
    fs.writeFileSync('/tmp/' + file.originalname, file.buffer);
  }
}`;
    const r = await analyze(code, 'u.ts', 'typescript');
    expect(hasFlow(r)).toBe(true);
  });

  it('TP — `@HostParam(\'sub\') sub` treated as http_path source', async () => {
    const code = `import { Controller, Get, HostParam } from '@nestjs/common';
import { exec } from 'child_process';

@Controller({ host: ':sub.example.com' })
class TenantController {
  @Get()
  tenant(@HostParam('sub') sub: string) {
    exec('ls /tenants/' + sub);
  }
}`;
    const r = await analyze(code, 'h.ts', 'typescript');
    expect(hasFlow(r)).toBe(true);
  });
});
