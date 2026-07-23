/**
 * Tests for cognium-dev #261 (Python slice) — extends the
 * DeserializationSafetyGatePass with Gate D: PyYAML ≥ 6.0 default-safe.
 *
 * Semantics: under pyyaml ≥ 6.0, `yaml.load(x)` without an explicit
 * `Loader=` kwarg raises TypeError instead of silently invoking the
 * unsafe default. Callers that pass `Loader=SafeLoader` are safe.
 * Callers that pass `Loader=Loader` / `UnsafeLoader` / `FullLoader`
 * are still dangerous — those must NOT be suppressed even under a
 * hardened version pin.
 *
 * The gate reads pyyaml version from either `requirementsTxt` or
 * `pyprojectToml` (requirements takes precedence), and inspects the
 * sink line (+ up to 9 following lines for multi-line calls) for the
 * explicit-unsafe-Loader escape hatch.
 */

import { describe, it, beforeAll, expect } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

const countDeserSinks = (r: any) =>
  (r.taint?.sinks ?? []).filter((s: any) => s.type === 'deserialization').length;

// ---------------------------------------------------------------------------
// Sample Python manifests
// ---------------------------------------------------------------------------

const REQS_PYYAML_6 = `flask==2.3.0
PyYAML==6.0.1
requests>=2.28.0
`;

const REQS_PYYAML_5 = `flask==2.3.0
PyYAML==5.4.1
requests>=2.28.0
`;

const REQS_PYYAML_GTE_6 = `pyyaml>=6.0
`;

const REQS_PYYAML_TILDE_6 = `PyYAML ~= 6.0
`;

const REQS_NO_PYYAML = `flask==2.3.0
requests>=2.28.0
`;

const PYPROJECT_POETRY_PYYAML_6 = `
[tool.poetry]
name = "example"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.10"
PyYAML = "^6.0"
`;

const PYPROJECT_POETRY_TABLE_PYYAML_6 = `
[tool.poetry.dependencies]
pyyaml = { version = "6.0.1", extras = ["dev"] }
`;

const PYPROJECT_PEP621_PYYAML_6 = `
[project]
name = "example"
dependencies = [
    "PyYAML>=6.0.1",
    "flask==2.3.0",
]
`;

const PYPROJECT_POETRY_PYYAML_5 = `
[tool.poetry.dependencies]
PyYAML = "5.4.1"
`;

// ---------------------------------------------------------------------------
// Sample Python source shapes
// ---------------------------------------------------------------------------

const CODE_YAML_LOAD_NO_LOADER = `
import yaml
from flask import request

def handler():
    payload = request.get_data(as_text=True)
    return yaml.load(payload)
`;

const CODE_YAML_LOAD_UNSAFE_LOADER = `
import yaml
from flask import request

def handler():
    payload = request.get_data(as_text=True)
    return yaml.load(payload, Loader=yaml.Loader)
`;

const CODE_YAML_LOAD_UNSAFE_LOADER_UNQUALIFIED = `
import yaml
from yaml import Loader
from flask import request

def handler():
    payload = request.get_data(as_text=True)
    return yaml.load(payload, Loader=Loader)
`;

const CODE_YAML_LOAD_FULL_LOADER = `
import yaml
from flask import request

def handler():
    payload = request.get_data(as_text=True)
    return yaml.load(payload, Loader=yaml.FullLoader)
`;

const CODE_YAML_LOAD_SAFE_LOADER = `
import yaml
from flask import request

def handler():
    payload = request.get_data(as_text=True)
    return yaml.load(payload, Loader=yaml.SafeLoader)
`;

const CODE_YAML_LOAD_MULTILINE_UNSAFE = `
import yaml
from flask import request

def handler():
    payload = request.get_data(as_text=True)
    return yaml.load(
        payload,
        Loader=yaml.UnsafeLoader,
    )
`;

// ---------------------------------------------------------------------------
// Gate D — PyYAML ≥ 6.0
// ---------------------------------------------------------------------------

describe('#261 Python slice — Gate D (PyYAML ≥ 6.0)', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('FP suppress — pyyaml==6.0.1 + yaml.load(payload) with no Loader kwarg: drop sink', async () => {
    const r = await analyze(CODE_YAML_LOAD_NO_LOADER, 'view.py', 'python', {
      dependencyContext: { python: { requirementsTxt: REQS_PYYAML_6 } },
    });
    expect(countDeserSinks(r)).toBe(0);
  });

  it('FP suppress — pyyaml>=6.0 requirement string also fires the gate', async () => {
    const r = await analyze(CODE_YAML_LOAD_NO_LOADER, 'view.py', 'python', {
      dependencyContext: { python: { requirementsTxt: REQS_PYYAML_GTE_6 } },
    });
    expect(countDeserSinks(r)).toBe(0);
  });

  it('FP suppress — pyyaml ~= 6.0 (compatible-release) also fires', async () => {
    const r = await analyze(CODE_YAML_LOAD_NO_LOADER, 'view.py', 'python', {
      dependencyContext: { python: { requirementsTxt: REQS_PYYAML_TILDE_6 } },
    });
    expect(countDeserSinks(r)).toBe(0);
  });

  it('FP suppress — pyproject.toml Poetry key = string form drops the sink', async () => {
    const r = await analyze(CODE_YAML_LOAD_NO_LOADER, 'view.py', 'python', {
      dependencyContext: { python: { pyprojectToml: PYPROJECT_POETRY_PYYAML_6 } },
    });
    expect(countDeserSinks(r)).toBe(0);
  });

  it('FP suppress — pyproject.toml Poetry table form drops the sink', async () => {
    const r = await analyze(CODE_YAML_LOAD_NO_LOADER, 'view.py', 'python', {
      dependencyContext: { python: { pyprojectToml: PYPROJECT_POETRY_TABLE_PYYAML_6 } },
    });
    expect(countDeserSinks(r)).toBe(0);
  });

  it('FP suppress — pyproject.toml PEP 621 array-element form drops the sink', async () => {
    const r = await analyze(CODE_YAML_LOAD_NO_LOADER, 'view.py', 'python', {
      dependencyContext: { python: { pyprojectToml: PYPROJECT_PEP621_PYYAML_6 } },
    });
    expect(countDeserSinks(r)).toBe(0);
  });

  it('FP suppress — pyyaml 6 + yaml.load(payload, Loader=yaml.SafeLoader) also drops (SafeLoader is not in the unsafe list)', async () => {
    const r = await analyze(CODE_YAML_LOAD_SAFE_LOADER, 'view.py', 'python', {
      dependencyContext: { python: { requirementsTxt: REQS_PYYAML_6 } },
    });
    expect(countDeserSinks(r)).toBe(0);
  });

  it('Recall lock — pyyaml 6 + yaml.load(payload, Loader=yaml.Loader): STILL fires (unsafe Loader is exploitable regardless of version)', async () => {
    const r = await analyze(CODE_YAML_LOAD_UNSAFE_LOADER, 'view.py', 'python', {
      dependencyContext: { python: { requirementsTxt: REQS_PYYAML_6 } },
    });
    expect(countDeserSinks(r)).toBeGreaterThanOrEqual(1);
  });

  it('Recall lock — pyyaml 6 + unqualified Loader=Loader import: STILL fires', async () => {
    const r = await analyze(CODE_YAML_LOAD_UNSAFE_LOADER_UNQUALIFIED, 'view.py', 'python', {
      dependencyContext: { python: { requirementsTxt: REQS_PYYAML_6 } },
    });
    expect(countDeserSinks(r)).toBeGreaterThanOrEqual(1);
  });

  it('Recall lock — pyyaml 6 + Loader=yaml.FullLoader: STILL fires (FullLoader accepts arbitrary Python types)', async () => {
    const r = await analyze(CODE_YAML_LOAD_FULL_LOADER, 'view.py', 'python', {
      dependencyContext: { python: { requirementsTxt: REQS_PYYAML_6 } },
    });
    expect(countDeserSinks(r)).toBeGreaterThanOrEqual(1);
  });

  it('Recall lock — pyyaml 6 + multi-line call with Loader=UnsafeLoader on a later line: STILL fires', async () => {
    const r = await analyze(CODE_YAML_LOAD_MULTILINE_UNSAFE, 'view.py', 'python', {
      dependencyContext: { python: { requirementsTxt: REQS_PYYAML_6 } },
    });
    expect(countDeserSinks(r)).toBeGreaterThanOrEqual(1);
  });

  it('Recall lock — pyyaml < 6.0: sink still fires (unsafe default Loader in 5.x)', async () => {
    const r = await analyze(CODE_YAML_LOAD_NO_LOADER, 'view.py', 'python', {
      dependencyContext: { python: { requirementsTxt: REQS_PYYAML_5 } },
    });
    expect(countDeserSinks(r)).toBeGreaterThanOrEqual(1);
  });

  it('Recall lock — pyproject Poetry pyyaml 5.4.1: sink still fires', async () => {
    const r = await analyze(CODE_YAML_LOAD_NO_LOADER, 'view.py', 'python', {
      dependencyContext: { python: { pyprojectToml: PYPROJECT_POETRY_PYYAML_5 } },
    });
    expect(countDeserSinks(r)).toBeGreaterThanOrEqual(1);
  });

  it('Recall lock — no pyyaml in manifest: gate no-ops and sink still fires', async () => {
    const r = await analyze(CODE_YAML_LOAD_NO_LOADER, 'view.py', 'python', {
      dependencyContext: { python: { requirementsTxt: REQS_NO_PYYAML } },
    });
    expect(countDeserSinks(r)).toBeGreaterThanOrEqual(1);
  });

  it('Recall lock — no dependencyContext at all: gate no-ops and sink still fires', async () => {
    const r = await analyze(CODE_YAML_LOAD_NO_LOADER, 'view.py', 'python');
    expect(countDeserSinks(r)).toBeGreaterThanOrEqual(1);
  });

  it('Java files are untouched even with dependencyContext.python present', async () => {
    // Sentinel-shape Fastjson: without pomXml/buildGradle, no Fastjson
    // gate signal — sink should still fire.
    const code = [
      'import com.alibaba.fastjson.JSON;',
      'public class C {',
      '  public Object m(String payload) { return JSON.parseObject(payload); }',
      '}',
    ].join('\n');
    const r = await analyze(code, 'C.java', 'java', {
      dependencyContext: { python: { requirementsTxt: REQS_PYYAML_6 } },
    });
    expect(countDeserSinks(r)).toBeGreaterThanOrEqual(1);
  });
});
