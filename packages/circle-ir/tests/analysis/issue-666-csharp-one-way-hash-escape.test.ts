/**
 * cognium-dev#666 — a C# value that is only hashed one way, with the digest
 * then stored or sent, was reported as `external_taint_escape` on the hash call
 * and on the call that receives the digest. The input cannot be recovered from
 * a SHA-2 / PBKDF2 / bcrypt digest, so nothing of it leaves the program.
 *
 * The digest calls are credited for the untyped escape fallback only. A raw
 * value sent beside the digest, a reversible encoding (Base64 / hex of the raw
 * bytes) and a hashed name reassigned to the raw value must still escape.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const escapes = async (code: string): Promise<number[]> => {
  const r = await analyze(code, 'Vault.cs', 'csharp');
  return (r.taint?.flows ?? [])
    .filter(f => f.sink_type === 'external_taint_escape')
    .map(f => f.sink_line)
    .sort((a, b) => a - b);
};

describe('#666 C# one-way digest is not an external escape', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('SHA256.HashData digest written to a file is clean', async () => {
    expect(await escapes(`using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
public class PinVault : Controller {
  [HttpPost("/pin")]
  public IActionResult Keep([FromForm] string pin) {
    var digest = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(pin)));
    System.IO.File.WriteAllText("/srv/vault/pin.sha", digest);
    return Ok("stored");
  }
}`)).toEqual([]);
  });

  it('ComputeHash on a hasher instance, then sent, is clean', async () => {
    expect(await escapes(`using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
public class Fingerprints : Controller {
  [HttpPost("/fp")]
  public IActionResult Save([FromForm] string token) {
    using var hasher = SHA512.Create();
    var bytes = hasher.ComputeHash(System.Text.Encoding.UTF8.GetBytes(token));
    AuditLog.Record(Convert.ToBase64String(bytes));
    return Ok();
  }
}`)).toEqual([]);
  });

  it('bcrypt and PBKDF2 digests are clean', async () => {
    expect(await escapes(`using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
public class Accounts : Controller {
  [HttpPost("/signup")]
  public IActionResult Signup([FromForm] string secret) {
    var stored = BCrypt.Net.BCrypt.HashPassword(secret);
    UserRepo.Insert(stored);
    var key = Rfc2898DeriveBytes.Pbkdf2(secret, new byte[16], 100000, HashAlgorithmName.SHA256, 32);
    KeyStore.Put(Convert.ToHexString(key));
    return Ok();
  }
}`)).toEqual([]);
  });

  it('the raw value sent after the digest still escapes', async () => {
    expect(await escapes(`using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
public class Relay : Controller {
  [HttpPost("/relay")]
  public IActionResult Save([FromForm] string pin) {
    var digest = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(pin)));
    PartnerApi.Send(digest);
    PartnerApi.Send(pin);
    return Ok();
  }
}`)).toEqual([8]);
  });

  it('a raw operand beside the digest on the same call still escapes', async () => {
    expect(await escapes(`using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
public class Beside : Controller {
  [HttpPost("/beside")]
  public IActionResult Save([FromForm] string pin) {
    PartnerApi.Send(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(pin)), pin);
    return Ok();
  }
}`)).toEqual([6]);
  });

  it('a reversible encoding is not a digest', async () => {
    expect(await escapes(`using Microsoft.AspNetCore.Mvc;
public class Encoded : Controller {
  [HttpPost("/enc")]
  public IActionResult Save([FromForm] string pin) {
    var enc = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(pin));
    PartnerApi.Send(enc);
    return Ok();
  }
}`)).toEqual([5, 6]);
  });

  it('a digest name reassigned to the raw value escapes', async () => {
    expect(await escapes(`using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
public class Swap : Controller {
  [HttpPost("/swap")]
  public IActionResult Save([FromForm] string pin) {
    var h = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(pin)));
    h = pin;
    PartnerApi.Send(h);
    return Ok();
  }
}`)).toEqual([8]);
  });
});
