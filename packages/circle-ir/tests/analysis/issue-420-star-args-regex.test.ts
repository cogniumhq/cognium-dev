/**
 * #420 — CrossFileResolver.findTaintedParams interpolated Python `*args` /
 * `**kwargs` into `new RegExp('\\b' + name + '\\b')`. That pattern is
 * `/\b*args\b/` ("Nothing to repeat") and the SyntaxError escaped
 * CrossFilePass, aborting the whole project scan with exit 2.
 *
 * The body refers to the bare name (`args`), so the leading stars must be
 * stripped for matching and the remainder escaped. A malformed identifier
 * must skip that symbol, not kill the run.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyzeProject } from '../../src/analyzer.js';

const VIEWS = `import os
from django.http import HttpResponse

def run_cmd(request, *args, **kwargs):
    cmd = request.GET.get('cmd')
    os.system(cmd)
    return HttpResponse("ok")
`;

describe('#420 Python *args does not abort analyzeProject', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('completes instead of throwing Invalid regular expression /\\b*args\\b/', async () => {
    await expect(
      analyzeProject([
        { filePath: 'views.py', language: 'python', code: VIEWS },
        { filePath: 'app.py', language: 'python', code: 'from views import run_cmd\n' },
      ]),
    ).resolves.toMatchObject({ files: expect.any(Array) });
  });

  it('still reports the os.system command_injection on the request param', async () => {
    const r = await analyzeProject([
      { filePath: 'views.py', language: 'python', code: VIEWS },
      { filePath: 'app.py', language: 'python', code: 'from views import run_cmd\n' },
    ]);
    const views = r.files.find((f) => f.file === 'views.py')?.analysis;
    const sinks = views?.taint.sinks ?? [];
    expect(sinks.some((s) => s.type === 'command_injection')).toBe(true);
  });
});
