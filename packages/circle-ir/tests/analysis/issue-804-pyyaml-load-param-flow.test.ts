/**
 * cognium-dev#804 — SCA-06: a reachable `yaml.load` on a function parameter
 * must report deserialization without `speculativeParamSources`.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const TP = `import yaml

def parse_config(blob: str):
    return yaml.load(blob)
`;

const SAFE = `import yaml

def dump_config(cfg: dict) -> str:
    return yaml.safe_dump(cfg)
`;

describe('#804 pyyaml yaml.load reachable on parameter', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('parse_config reports deserialization from blob to yaml.load', async () => {
    const ir = await analyze(TP, 'parse_config.py', 'python');
    const flows = (ir.taint.flows ?? []).filter(f => f.sink_type === 'deserialization');
    expect(flows.length).toBeGreaterThanOrEqual(1);
    expect(flows.some(f => f.source_type === 'interprocedural_param' && f.sink_line === 4)).toBe(true);
  });

  it('safe_dump-only helper stays clean', async () => {
    const ir = await analyze(SAFE, 'dump_config.py', 'python');
    expect((ir.taint.flows ?? []).filter(f => f.sink_type === 'deserialization')).toHaveLength(0);
  });
});
