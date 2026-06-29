/**
 * Sprint 69 — #199 bash compromised `.deb` install path
 *
 * CVE-intake batch 3 (FN-CVE-B03): downloading a `.deb` from a tainted URL
 * and running `dpkg -i` produces only `predictable-temp-file` on
 * v3.105.0 — the install step is invisible. `dpkg -i` of an arbitrary
 * `.deb` runs the embedded preinst/postinst maintainer scripts as root,
 * so this shape is RCE-equivalent.
 *
 * Resolution: new pattern rule `unverified-package-install` (CWE-494,
 * Download of Code Without Integrity Check). Fires on:
 *   - `dpkg -i <path>`, `rpm -i <path>` / `rpm -U <path>` / `rpm --install`
 *   - `apt-get install` / `apt install` of a `.deb` PATH
 *   - `yum install` / `dnf install` / `zypper install` of a path
 *   - `pip install` / `npm install` of a downloaded file path
 *
 * FP-guard: suppress when the same script contains a signature-verify
 * (`gpg --verify`, `rpm --checksig`, `dpkg --verify`) OR a checksum
 * verifier (`sha{256,512}sum -c`, `b2sum -c`).
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../../src/analyzer.js';

describe('#199 Sprint 69 — bash unverified-package-install', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('TP — dpkg -i /tmp/pkg.deb after curl download (no verify) fires', async () => {
    const code = [
      '#!/bin/bash',
      'curl -fsSLo /tmp/pkg.deb "${1}"',
      'dpkg -i /tmp/pkg.deb',
    ].join('\n');
    const r = await analyze(code, 'install.sh', 'bash');
    const f = (r.findings ?? []).filter(x => x.rule_id === 'unverified-package-install');
    expect(f.length).toBeGreaterThanOrEqual(1);
  });

  it('TP — rpm -i /tmp/pkg.rpm fires', async () => {
    const code = [
      '#!/bin/bash',
      'curl -O https://example.com/pkg.rpm',
      'rpm -i /tmp/pkg.rpm',
    ].join('\n');
    const r = await analyze(code, 'rpm.sh', 'bash');
    const f = (r.findings ?? []).filter(x => x.rule_id === 'unverified-package-install');
    expect(f.length).toBeGreaterThanOrEqual(1);
  });

  it('TP — apt-get install ./local.deb fires', async () => {
    const code = [
      '#!/bin/bash',
      'apt-get install -y ./local.deb',
    ].join('\n');
    const r = await analyze(code, 'apt.sh', 'bash');
    const f = (r.findings ?? []).filter(x => x.rule_id === 'unverified-package-install');
    expect(f.length).toBeGreaterThanOrEqual(1);
  });

  it('TN — dpkg -i after gpg --verify is suppressed', async () => {
    const code = [
      '#!/bin/bash',
      'curl -fsSLo /tmp/pkg.deb "$URL"',
      'curl -fsSLo /tmp/pkg.deb.sig "$URL.sig"',
      'gpg --verify /tmp/pkg.deb.sig /tmp/pkg.deb',
      'dpkg -i /tmp/pkg.deb',
    ].join('\n');
    const r = await analyze(code, 'verified.sh', 'bash');
    const f = (r.findings ?? []).filter(x => x.rule_id === 'unverified-package-install');
    expect(f.length).toBe(0);
  });

  it('TN — dpkg -i after sha256sum -c is suppressed', async () => {
    const code = [
      '#!/bin/bash',
      'curl -fsSLo /tmp/pkg.deb "$URL"',
      'echo "deadbeef  /tmp/pkg.deb" | sha256sum -c -',
      'dpkg -i /tmp/pkg.deb',
    ].join('\n');
    const r = await analyze(code, 'checksum.sh', 'bash');
    const f = (r.findings ?? []).filter(x => x.rule_id === 'unverified-package-install');
    expect(f.length).toBe(0);
  });

  it('TN — apt-get install <pkgname> (no path / no .deb) does NOT fire', async () => {
    const code = [
      '#!/bin/bash',
      'apt-get update',
      'apt-get install -y curl nginx',
    ].join('\n');
    const r = await analyze(code, 'pkgs.sh', 'bash');
    const f = (r.findings ?? []).filter(x => x.rule_id === 'unverified-package-install');
    expect(f.length).toBe(0);
  });

  it('TN — dpkg -l (list, not install) does NOT fire', async () => {
    const code = [
      '#!/bin/bash',
      'dpkg -l | grep nginx',
    ].join('\n');
    const r = await analyze(code, 'list.sh', 'bash');
    const f = (r.findings ?? []).filter(x => x.rule_id === 'unverified-package-install');
    expect(f.length).toBe(0);
  });
});
