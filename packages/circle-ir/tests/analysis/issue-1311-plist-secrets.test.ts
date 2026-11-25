/**
 * cognium-dev#1311 (.plist part): a React Native / Expo app keeps iOS config in
 * XML property lists (`ios/<App>/Info.plist`). They are not source files, so a
 * credential there was never read. `analyzeProject` now scans `*.plist`
 * entries of `AnalyzerOptions.resources` and reports `resource_findings`.
 *
 * Every credential below is fabricated to exercise the matchers.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyzeProject, initAnalyzer } from '../../src/analyzer.js';
import { scanPlistSecrets } from '../../src/analysis/passes/scan-secrets-pass.js';

const infoPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDisplayName</key>
  <string>Expo Demo</string>
  <key>CFBundleIdentifier</key>
  <string>com.example.expodemo</string>
  <key>PaymentsApiKey</key>
  <string>Xk9#mQ2vLp7Rt4Wz</string>
  <key>AwsAccess</key>
  <string>AKIAIOSFODNN7EXAMPLE</string>
  <key>NSCameraUsageDescription</key>
  <string>Allow camera access to scan a QR code</string>
</dict>
</plist>
`;

const app = [{ filePath: 'expo-app/App.tsx', code: 'export default function App() { return null; }\n', language: 'typescript' as const }];

describe('#1311: hardcoded credentials in .plist resources', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('reports a named credential and a provider key in Info.plist, on the <string> line', async () => {
    const path = 'expo-app/ios/ExpoDemo/Info.plist';
    const r = await analyzeProject(app, { resources: new Map([[path, infoPlist]]) });
    const hits = (r.resource_findings ?? []).map((f) => [f.rule_id, f.file, f.line, f.snippet]);
    expect(hits).toEqual([
      ['hardcoded-credential', path, 12, '<string>AKIAIOSFODNN7EXAMPLE</string>'],
      ['hardcoded-credential', path, 10, '<string>Xk9#mQ2vLp7Rt4Wz</string>'],
    ]);
    expect(r.resource_findings?.every((f) => f.cwe === 'CWE-798' && f.pass === 'scan-secrets')).toBe(true);
  });

  it('honours disabledPasses scan-secrets, ignores non-plist resources, and reports nothing for a clean plist', async () => {
    const path = 'expo-app/ios/ExpoDemo/Info.plist';
    const off = await analyzeProject(app, { resources: new Map([[path, infoPlist]]), disabledPasses: ['scan-secrets'] });
    expect(off.resource_findings).toBeUndefined();
    const props = await analyzeProject(app, { resources: new Map([['expo-app/app.properties', infoPlist]]) });
    expect(props.resource_findings).toBeUndefined();
    const clean = infoPlist.replace(/ {2}<key>PaymentsApiKey[\s\S]*?EXAMPLE<\/string>\n/, '');
    const none = await analyzeProject(app, { resources: new Map([[path, clean]]) });
    expect(none.resource_findings).toBeUndefined();
  });

  it('keeps the pass guards: placeholders, test paths and binary plists are not reported', () => {
    const placeholder = '<dict>\n<key>ApiKey</key>\n<string>YOUR_API_KEY_HERE</string>\n</dict>\n';
    expect(scanPlistSecrets('ios/App/Info.plist', placeholder)).toEqual([]);
    expect(scanPlistSecrets('ios/App/__tests__/Info.plist', infoPlist)).toEqual([]);
    expect(scanPlistSecrets('ios/App/Info.plist', 'bplist00' + infoPlist)).toEqual([]);
  });

  it('pairs a key and string written on one line', () => {
    const oneLine = '<dict><key>ClientSecret</key><string>Xk9#mQ2vLp7Rt4Wz</string></dict>\n';
    const f = scanPlistSecrets('ios/App/Config.plist', oneLine);
    expect(f.map((x) => [x.line, x.message])).toEqual([[1, 'Hardcoded credential: `ClientSecret` assigned a literal value']]);
  });
});
