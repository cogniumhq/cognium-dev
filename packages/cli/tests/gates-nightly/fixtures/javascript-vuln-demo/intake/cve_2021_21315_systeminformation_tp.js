// CVE-2021-21315 (systeminformation) — unsanitized parameter reaches a shell command.
/* eslint-disable @typescript-eslint/no-require-imports -- byte-aligned cve-intake corpus */
const cp = require('child_process');

function networkStats(iface) {                 // iface from an HTTP request
  return cp.execSync('netstat -I ' + iface);   // SINK CWE-78 command injection
}
module.exports = { networkStats };
