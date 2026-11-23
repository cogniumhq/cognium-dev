/**
 * L2 hermetic E2E: project-profile detection must appear consistently on JSON
 * and SARIF directory scans (cognium-dev#169). Mis-wiring env axes or omitting
 * the summary makes production and test code look equivalent to CI consumers.
 */
import { describe, test, expect, beforeAll, afterAll } from 'bun:test';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

const CLI = join(import.meta.dir, '..', '..', 'src', 'cli.ts');

async function runCli(args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  // Directory scans must run with cwd at the tree root and a relative target (CLI file walk).
  const proc = Bun.spawn(['bun', 'run', CLI, ...args], {
    stdout: 'pipe',
    stderr: 'pipe',
    cwd: projectRoot,
    env: { ...process.env, NO_COLOR: '1' },
  });
  const [stdout, stderr] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()]);
  return { code: await proc.exited, stdout, stderr };
}

function writeMavenSpringTree(root: string): void {
  mkdirSync(join(root, 'src', 'main', 'java', 'app'), { recursive: true });
  mkdirSync(join(root, 'src', 'test', 'java', 'app'), { recursive: true });
  writeFileSync(
    join(root, 'pom.xml'),
    `<project>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>3.2.0</version>
  </parent>
  <artifactId>wire-fixture</artifactId>
</project>`,
  );
  const servlet = `package app;
import java.sql.*;
import javax.servlet.http.*;
public class Lookup extends HttpServlet {
  private Connection conn;
  public void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception {
    String id = req.getParameter("id");
    Statement st = conn.createStatement();
    st.executeQuery("SELECT * FROM t WHERE id = '" + id + "'");
  }
}`;
  writeFileSync(join(root, 'src', 'main', 'java', 'app', 'Lookup.java'), servlet);
  writeFileSync(
    join(root, 'src', 'test', 'java', 'app', 'LookupTest.java'),
    servlet.replace('class Lookup', 'class LookupTest'),
  );
}

let projectRoot: string;

beforeAll(() => {
  projectRoot = mkdtempSync(join(tmpdir(), 'pp-wire-'));
  writeMavenSpringTree(projectRoot);
});

afterAll(() => rmSync(projectRoot, { recursive: true, force: true }));

describe('project-profile scan wire (TA-project-profile-scan-wire)', () => {
  test('TA-project-profile-scan-wire-1: JSON modules distinguish production and test envs', async () => {
    const { stdout, code } = await runCli(['scan', '.', '-f', 'json', '-q', '--category', 'security']);
    const doc = JSON.parse(stdout);
    expect(code).toBe(1);
    expect(doc.project_profile).toBeDefined();
    expect(doc.project_profile.modules.length).toBeGreaterThan(0);
    const findingProfiles = doc.results.flatMap(
      (r: { vulnerabilities: Array<{ profile?: string }> }) => r.vulnerabilities.map(v => v.profile).filter(Boolean),
    );
    expect(findingProfiles.some((p: string) => p.endsWith('/production'))).toBe(true);
    expect(findingProfiles.some((p: string) => p.endsWith('/test'))).toBe(true);
  }, 90_000);

  test('TA-project-profile-scan-wire-2: SARIF run.properties.projectProfile mirrors JSON modules', async () => {
    const jsonRun = await runCli(['scan', '.', '-f', 'json', '-q', '--category', 'security']);
    const sarifRun = await runCli(['scan', '.', '-f', 'sarif', '-q', '--category', 'security']);
    const jsonDoc = JSON.parse(jsonRun.stdout);
    const sarif = JSON.parse(sarifRun.stdout);
    const jsonModules = jsonDoc.project_profile.modules.map((m: { root: string; profile: string }) => `${m.root}:${m.profile}`);
    const sarifModules = sarif.runs[0].properties.projectProfile.modules.map(
      (m: { root: string; profile: string }) => `${m.root}:${m.profile}`,
    );
    expect(sarifModules.sort()).toEqual(jsonModules.sort());
    expect(sarifRun.code).toBe(1);
  }, 120_000);

  test('TA-project-profile-scan-wire-3: SARIF finding properties.profile on main-path vuln', async () => {
    const { stdout, code } = await runCli(['scan', '.', '-f', 'sarif', '-q', '--category', 'security']);
    const sarif = JSON.parse(stdout);
    expect(code).toBe(1);
    const mainResults = (sarif.runs?.[0]?.results ?? []).filter(
      (r: { locations: Array<{ physicalLocation: { artifactLocation: { uri: string } } }> }) =>
        String(r.locations?.[0]?.physicalLocation?.artifactLocation?.uri ?? '').includes('src/main'),
    );
    expect(mainResults.length).toBeGreaterThan(0);
    const withProfile = mainResults.filter((r: { properties?: { profile?: string } }) => r.properties?.profile);
    expect(withProfile.length).toBeGreaterThan(0);
    expect(withProfile[0].properties.profile).toContain('production');
  }, 90_000);

  test('TA-project-profile-scan-wire-4: --no-project-profile omits project_profile on JSON and SARIF', async () => {
    const jsonRun = await runCli(['scan', '.', '-f', 'json', '-q', '--category', 'security', '--no-project-profile']);
    const sarifRun = await runCli(['scan', '.', '-f', 'sarif', '-q', '--category', 'security', '--no-project-profile']);
    const jsonDoc = JSON.parse(jsonRun.stdout);
    expect(jsonDoc.project_profile).toBeUndefined();
    const sarif = JSON.parse(sarifRun.stdout);
    expect(sarif.runs[0].properties?.projectProfile).toBeUndefined();
  }, 120_000);

  test('TA-project-profile-scan-wire-5: --project-profile library/production forces module profiles', async () => {
    const { stdout, code } = await runCli([
      'scan', '.', '-f', 'json', '-q', '--category', 'security',
      '--project-profile', 'library/production',
    ]);
    const doc = JSON.parse(stdout);
    expect(code).toBe(1);
    const vulns = doc.results.flatMap((r: { vulnerabilities: Array<{ profile?: string }> }) => r.vulnerabilities);
    expect(vulns.length).toBeGreaterThan(0);
    expect(vulns.every(v => typeof v.profile === 'string' && v.profile.startsWith('library/'))).toBe(true);
  }, 90_000);
});