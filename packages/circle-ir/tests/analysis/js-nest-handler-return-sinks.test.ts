/**
 * NestJS controller handlers: with the default Express adapter a returned
 * string is the response body, sent as `text/html`, so a handler returning a
 * string built from request input is XSS; a `@Redirect()` handler's returned
 * `url` is an open redirect. A returned object (JSON), a constant, a
 * non-HTML `@Header('Content-Type', …)`, `@Res()` handlers (they write the
 * response themselves) and `@Render()` handlers are not sinks.
 *
 * SAST regression fixtures — the handlers are deliberately vulnerable.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const HEAD = `import { Controller, Get, Post, Query, Param, Body, Headers, Header, Redirect, Res, Req, Render } from '@nestjs/common';
import { Request, Response } from 'express'; import { execSync } from 'child_process';

@Controller('greet')
export class GreetController {
`;

/** `[source, sink]` lines of every flow of `type` in a controller whose body is `members`. */
async function flowsOf(members: string, type: string): Promise<Array<[number, number]>> {
  const r = await analyze(`${HEAD}${members}}\n`, 'src/greet.controller.ts', 'typescript');
  return r.taint.flows
    .filter(f => f.sink_type === type)
    .map(f => [f.source_line, f.sink_line] as [number, number]);
}

describe('NestJS handler return values', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  describe('xss: a returned string with request input', () => {
    it('a template literal, a concatenation and a derived local', async () => {
      expect(await flowsOf(`  @Get('a')
  a(@Query('name') name: string) {
    return \`<h1>Hello \${name}</h1>\`;
  }

  @Post('b')
  b(@Body('title') title: string) {
    return '<h2>' + title + '</h2>';
  }

  @Get('c')
  c(@Query('q') q: string) {
    const html = \`<p>\${q}</p>\`;
    return html;
  }
`, 'xss')).toEqual([[7, 8], [12, 13], [17, 19]]);
    });

    it('a returned string parameter, a header, and a member read when the handler returns string', async () => {
      expect(await flowsOf(`  @Get(':id')
  a(@Param('id') id: string) {
    return id;
  }

  @Get('h')
  b(@Headers('x-name') who: string) {
    return \`Hi \${who}\`;
  }

  @Get('m')
  c(@Query() query: Record<string, string>): string {
    return query.name;
  }
`, 'xss')).toEqual([[7, 8], [12, 13], [17, 18]]);
    });

    it('a request read through @Req(), and an explicit text/html content type', async () => {
      expect(await flowsOf(`  @Get('r')
  a(@Req() req: Request) {
    const who = req.query.who;
    return \`<b>\${who}</b>\`;
  }

  @Get('html')
  @Header('Content-Type', 'text/html')
  b(@Query('q') q: string) {
    return \`<p>\${q}</p>\`;
  }
`, 'xss')).toEqual([[8, 9], [14, 15]]);
    });

    it('NEGATIVE: an object, a constant, a JSON content type, @Res(), @Render()', async () => {
      expect(await flowsOf(`  @Get('obj')
  a(@Query('name') name: string) {
    return { greeting: 'hi ' + name };
  }

  @Get('const')
  b(@Query('name') name: string): string {
    return 'hello';
  }

  @Get('json')
  @Header('Content-Type', 'application/json')
  c(@Query('name') name: string): string {
    return \`{"name": "\${name}"}\`;
  }

  @Get('raw')
  d(@Query('q') q: string, @Res() res: Response) {
    res.json({ q });
    return \`<p>\${q}</p>\`;
  }

  @Get('view')
  @Render('index')
  e(@Query('q') q: string) {
    return { message: \`hi \${q}\` };
  }
`, 'xss')).toEqual([]);
    });

    it('NEGATIVE: an encoded value, a number, a reassigned local, a nested return, a helper call', async () => {
      expect(await flowsOf(`  @Get('esc')
  a(@Query('q') q: string) {
    return \`<p>\${escapeHtml(q)}</p>\`;
  }

  @Get('num')
  b(@Query('n') n: number) {
    return \`<i>\${n}</i>\`;
  }

  @Get('fixed')
  c(@Query('q') q: string) {
    let out = \`<p>\${q}</p>\`;
    out = 'fixed';
    return out;
  }

  @Get('list')
  d(@Query('q') q: string) {
    const items = [1, 2].map((i) => {
      return \`<li>\${q}</li>\`;
    });
    return { items };
  }

  @Get('svc')
  e(@Query('q') q: string): string {
    return this.render(q);
  }

  render(q: string): string {
    return q.length > 3 ? 'long' : 'short';
  }

  @Get('ls')
  f(@Query('dir') dir: string) {
    return execSync('ls ' + dir).toString();
  }
`, 'xss')).toEqual([]);
    });

    it('NEGATIVE: a method without an HTTP decorator, and a class without @Controller', async () => {
      expect(await flowsOf(`  helper(@Query('q') q: string) {
    return \`<p>\${q}</p>\`;
  }
`, 'xss')).toEqual([]);
      const plain = `import { Get, Query } from '@nestjs/common';
export class NotAController {
  @Get('a')
  a(@Query('q') q: string) {
    return \`<p>\${q}</p>\`;
  }
}
`;
      const r = await analyze(plain, 'src/plain.ts', 'typescript');
      expect(r.taint.flows.filter(f => f.sink_type === 'xss')).toEqual([]);
    });
  });

  describe('request headers', () => {
    it('a @Headers() parameter is a request source; a handler that ignores it is not', async () => {
      expect(await flowsOf(`  @Get('a')
  a(@Headers('x-host') host: string) {
    return execSync('ping -c 1 ' + host).toString();
  }

  @Get('b')
  b(@Headers('x-host') host: string) {
    return execSync('ping -c 1 localhost').toString();
  }
`, 'command_injection')).toEqual([[7, 8]]);
    });
  });

  describe('open redirect', () => {
    it('a @Redirect() handler returning a url from request input', async () => {
      expect(await flowsOf(`  @Get('go')
  @Redirect()
  a(@Query('next') next: string) {
    return { url: next };
  }

  @Get('go2')
  @Redirect('https://example.com', 302)
  b(@Query('to') to: string) {
    if (!to) return { url: '/home' };
    return { statusCode: 301, url: to };
  }
`, 'open_redirect')).toEqual([[8, 9], [14, 16]]);
    });

    it('NEGATIVE: a constant url, a fixed origin, and a url field without @Redirect()', async () => {
      expect(await flowsOf(`  @Get('go')
  @Redirect()
  a(@Query('next') next: string) {
    return { url: '/home' };
  }

  @Get('docs')
  @Redirect('https://docs.example.com', 302)
  b(@Query('version') version: string) {
    return { url: \`https://docs.example.com/\${version}/\` };
  }

  @Get('plain')
  c(@Query('next') next: string) {
    return { url: next };
  }
`, 'open_redirect')).toEqual([]);
    });

    it('@Res() with res.redirect(tainted) is still an open redirect', async () => {
      expect(await flowsOf(`  @Get('res')
  a(@Query('next') next: string, @Res() res: Response) {
    res.redirect(next);
  }
`, 'open_redirect')).toEqual([[7, 8]]);
    });
  });
});
