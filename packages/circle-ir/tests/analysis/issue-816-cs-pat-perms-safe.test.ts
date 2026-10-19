/**
 * cognium-dev #816 — PAT-PERMS-01 C# safe mirror: a library `string path`
 * parameter must not seed path_traversal when no HTTP entry-point applies.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';

const pathFlows = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint.flows ?? []).filter((f) => f.sink_type === 'path_traversal' && !f.sanitized);

const safeLibrary = `using System.IO;
public class IncorrectDefaultPermsSafe {
  public void OpenAt(string path) {
    using var fs = new FileStream(path, FileMode.Open);
  }
}`;

const controllerTp = `using System.IO;
using Microsoft.AspNetCore.Mvc;

[ApiController]
public class FilesController {
  [HttpGet("{name}")]
  public void Get(string name) {
    using var fs = new FileStream(name, FileMode.Open);
  }
}`;

const controllerBaseTp = `using System.IO;
using Microsoft.AspNetCore.Mvc;

public class Ctl : ControllerBase {
  public void M([FromQuery] string p) {
    using var fs = new FileStream(p, FileMode.Open);
  }
}`;

beforeAll(async () => {
  await initAnalyzer();
});

describe('#816 PAT-PERMS-01 C# library parameter', () => {
  it('safe mirror: FileStream on a plain public parameter stays clean', async () => {
    const r = await analyze(safeLibrary, 'IncorrectDefaultPermsSafe.cs', 'csharp');
    expect(pathFlows(r)).toEqual([]);
  });

  it('recall: controller action parameter still reaches FileStream', async () => {
    const r = await analyze(controllerTp, 'FilesController.cs', 'csharp');
    expect(pathFlows(r).length).toBeGreaterThan(0);
  });

  it('recall: ControllerBase with FromQuery still reaches FileStream', async () => {
    const r = await analyze(controllerBaseTp, 'Ctl.cs', 'csharp');
    expect(pathFlows(r).length).toBeGreaterThan(0);
  });
});
