/**
 * Tests for cognium-dev #261 (Rust slice, plumbing) —
 * `resolveDepFromCargoToml`.
 *
 * Parser-only unit tests. No gate consumes this helper today; when a
 * Rust deserialization-safety gate is added (a future ship on #261
 * once a concrete FP-driving use case appears), it will consume this
 * resolver via `AnalyzerOptions.dependencyContext.rust.cargoToml`.
 */

import { describe, it, expect } from 'vitest';
import { resolveDepFromCargoToml } from '../../src/analysis/dependency-versions.js';

describe('#261 Rust slice — resolveDepFromCargoToml', () => {
  it('returns null on empty input', () => {
    expect(resolveDepFromCargoToml('', 'serde')).toBeNull();
  });

  it('returns null on empty crate name', () => {
    expect(resolveDepFromCargoToml('[dependencies]\nserde = "1"\n', '')).toBeNull();
  });

  it('parses bare string form: `pkg = "1.2.3"`', () => {
    const toml = `
[package]
name = "example"

[dependencies]
serde = "1.0.196"
`;
    expect(resolveDepFromCargoToml(toml, 'serde')).toEqual({
      version: '1.0.196',
      features: [],
    });
  });

  it('parses inline-table form with just version', () => {
    const toml = `
[dependencies]
bincode = { version = "2.0.1" }
`;
    expect(resolveDepFromCargoToml(toml, 'bincode')).toEqual({
      version: '2.0.1',
      features: [],
    });
  });

  it('parses inline-table form with version + features', () => {
    const toml = `
[dependencies]
serde = { version = "1.0.196", features = ["derive", "rc"] }
`;
    expect(resolveDepFromCargoToml(toml, 'serde')).toEqual({
      version: '1.0.196',
      features: ['derive', 'rc'],
    });
  });

  it('recognises the target crate among many deps (does not match neighbours)', () => {
    const toml = `
[dependencies]
serde = "1.0.196"
serde_json = "1.0.115"
serde_yaml = "0.9.30"
tokio = { version = "1.36", features = ["full"] }
`;
    expect(resolveDepFromCargoToml(toml, 'serde')).toEqual({
      version: '1.0.196',
      features: [],
    });
    expect(resolveDepFromCargoToml(toml, 'serde_yaml')).toEqual({
      version: '0.9.30',
      features: [],
    });
    expect(resolveDepFromCargoToml(toml, 'tokio')).toEqual({
      version: '1.36',
      features: ['full'],
    });
  });

  it('returns null for a git-source table (no version to compare)', () => {
    const toml = `
[dependencies]
mycrate = { git = "https://github.com/example/mycrate", tag = "v1.0.0" }
`;
    expect(resolveDepFromCargoToml(toml, 'mycrate')).toBeNull();
  });

  it('returns null for a path-source table (no version)', () => {
    const toml = `
[dependencies]
localcrate = { path = "../localcrate" }
`;
    expect(resolveDepFromCargoToml(toml, 'localcrate')).toBeNull();
  });

  it('returns null when the crate is absent', () => {
    const toml = `
[dependencies]
serde = "1"
tokio = "1.36"
`;
    expect(resolveDepFromCargoToml(toml, 'bincode')).toBeNull();
  });

  it('does not confuse a substring name (e.g. `serde` should not match `serde_yaml` when asked for `serde`)', () => {
    // Both are present, we ask for `serde` specifically — regex is
    // line-anchored with `^\s*NAME\s*=`, so `serde_yaml` line does not
    // match. Locking this invariant.
    const toml = `
[dependencies]
serde_yaml = "0.9.30"
serde = "1.0.196"
`;
    expect(resolveDepFromCargoToml(toml, 'serde')).toEqual({
      version: '1.0.196',
      features: [],
    });
  });

  it('handles pre-release version strings like "1.0.0-beta.1"', () => {
    const toml = `
[dependencies]
bincode = "2.0.0-rc.3"
`;
    expect(resolveDepFromCargoToml(toml, 'bincode')).toEqual({
      version: '2.0.0-rc.3',
      features: [],
    });
  });

  it('handles crate names with hyphens (e.g. `serde-something`)', () => {
    const toml = `
[dependencies]
serde-json-lenient = "0.2.1"
`;
    expect(resolveDepFromCargoToml(toml, 'serde-json-lenient')).toEqual({
      version: '0.2.1',
      features: [],
    });
  });
});
