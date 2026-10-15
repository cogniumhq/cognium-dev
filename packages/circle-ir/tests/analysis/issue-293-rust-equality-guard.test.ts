/**
 * cognium-dev#293 (Rust cell): a rejecting literal-equality guard credits the
 * guarded variable for the rest of its block.
 *
 *     if tool != "uptime" && tool != "whoami" { return Err(...); }
 *     Command::new(tool).output()      // was command_injection (speculative mode)
 *
 * Past the guard `tool` is one of the listed string literals. Run with
 * `speculativeParamSources: true`: by default a parameter-only flow is dropped.
 *
 * SAST regression fixture — the "fires" handlers are deliberately vulnerable.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { analyze, initAnalyzer } from '../../src/analyzer.js';
import { findRustLiteralEqualityGuardSanitizers } from '../../src/analysis/rust-literal-guard.js';

async function ci(code: string): Promise<number[]> {
  const r = await analyze(code, 'runner.rs', 'rust', { speculativeParamSources: true });
  return (r.taint.flows ?? [])
    .filter((f) => f.sink_type === 'command_injection')
    .map((f) => f.sink_line)
    .sort((a, b) => a - b);
}

const wrap = (body: string, params = 'tool: &str') => `use std::process::Command;

pub fn run(${params}) -> Result<String, String> {
${body}
    Ok(String::new())
}
`;

const RUN = '    let out = Command::new(tool).output().map_err(|e| e.to_string())?;';

describe('cognium-dev#293 — Rust literal-equality reject guard', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  it('the issue fixture: guarded run_known is clean, run_any reports', async () => {
    const code = `use std::process::Command;

pub fn run_known(tool: &str) -> Result<String, String> {
    if tool != "uptime" && tool != "whoami" {
        return Err("not allowed".into());
    }
    let out = Command::new(tool).output().map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

pub fn run_any(tool: &str) -> Result<String, String> {
    if tool.is_empty() {
        return Err("empty".into());
    }
    let out = Command::new(tool).output().map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}
`;
    expect(await ci(code)).toEqual([15]);
  });

  it('single inequality, braces on their own lines', async () => {
    const code = wrap(`    if tool != "uptime"\n    {\n        return Err("no".into());\n    }\n${RUN}`);
    expect(await ci(code)).toEqual([]);
  });

  it('!matches!(x, "a" | "b") is credited', async () => {
    const code = wrap(`    if !matches!(tool, "uptime" | "whoami") {\n        return Err("no".into());\n    }\n${RUN}`);
    expect(await ci(code)).toEqual([]);
  });

  it('![..].contains(&x) is credited', async () => {
    const code = wrap(`    if !["uptime", "whoami"].contains(&tool) {\n        return Err("no".into());\n    }\n${RUN}`);
    expect(await ci(code)).toEqual([]);
  });

  it('panic! as the rejecting body is credited', async () => {
    const code = wrap(`    if tool != "uptime" {\n        panic!("bad tool");\n    }\n${RUN}`);
    expect(await ci(code)).toEqual([]);
  });

  it('credit follows an identity alias of the guarded value', async () => {
    const code = wrap(`    if tool != "uptime" {\n        return Err("no".into());\n    }\n    let t = tool;\n    let out = Command::new(t).output().map_err(|e| e.to_string())?;`);
    expect(await ci(code)).toEqual([]);
  });

  it('still reports: a guard that falls through', async () => {
    const code = wrap(`    if tool != "uptime" && tool != "whoami" {\n        eprintln!("odd tool");\n    }\n${RUN}`);
    expect((await ci(code)).length).toBe(1);
  });

  it('still reports: || of inequalities (always true, rejects everything but proves nothing)', async () => {
    const code = wrap(`    if tool != "uptime" || tool != "whoami" {\n        return Err("no".into());\n    }\n${RUN}`);
    // The block always returns, so the sink is unreachable; the credit is not
    // what is under test, only that a lone `||` guard is not read as an allow-list.
    expect((await ci(code)).length).toBe(1);
  });

  it('still reports: inequality against a non-literal', async () => {
    const code = wrap(`    let other = std::env::var("T").unwrap_or_default();\n    if tool != other {\n        return Err("no".into());\n    }\n${RUN}`);
    expect((await ci(code)).length).toBe(1);
  });

  it('still reports: a guard on a different variable', async () => {
    const code = wrap(`    if mode != "fast" {\n        return Err("no".into());\n    }\n${RUN}`, 'tool: &str, mode: &str');
    expect((await ci(code)).length).toBe(1);
  });

  it('still reports: the rejection is nested in an inner branch', async () => {
    const code = wrap(`    if tool != "uptime" {\n        if tool.len() > 100 {\n            return Err("no".into());\n        }\n    }\n${RUN}`);
    expect((await ci(code)).length).toBe(1);
  });

  it('still reports: a guard with an else branch that does not reject', async () => {
    const code = wrap(`    if tool != "uptime" {\n        return Err("no".into());\n    } else if tool.is_empty() {\n        eprintln!("x");\n    }\n    let tool = std::env::args().nth(1).unwrap_or_default();\n${RUN}`);
    // `let tool` shadows the guarded parameter before the sink.
    expect((await ci(code)).length).toBe(1);
  });

  it('still reports: the name is shadowed by a fresh value after the guard', async () => {
    const code = wrap(`    if tool != "uptime" {\n        return Err("no".into());\n    }\n    let tool = std::env::var("EXTRA").unwrap_or_default();\n    let out = Command::new(&tool).output().map_err(|e| e.to_string())?;`);
    expect((await ci(code)).length).toBe(1);
  });

  it('still reports: a String parameter mutated after the guard', async () => {
    const code = wrap(`    if tool != "uptime" {\n        return Err("no".into());\n    }\n    tool = std::env::var("X").unwrap_or_default();\n${RUN}`, 'mut tool: String');
    expect((await ci(code)).length).toBe(1);
  });

  it('still reports: another function with the same parameter name is not credited', async () => {
    const code = `use std::process::Command;

pub fn checked(tool: &str) -> Result<(), String> {
    if tool != "uptime" {
        return Err("no".into());
    }
    Ok(())
}

pub fn unchecked(tool: &str) -> Result<String, String> {
    let out = Command::new(tool).output().map_err(|e| e.to_string())?;
    Ok(String::new())
}
`;
    expect(await ci(code)).toEqual([11]);
  });

  it('still reports: a guard inside an inner block does not credit code after the block', async () => {
    const code = wrap(`    if std::env::var("STRICT").is_ok() {\n        if tool != "uptime" {\n            return Err("no".into());\n        }\n    }\n${RUN}`);
    expect((await ci(code)).length).toBe(1);
  });

  it('still reports: a raw second operand on the sink line', async () => {
    const code = wrap(`    let extra = std::env::var("EXTRA").unwrap_or_default();\n    if tool != "uptime" {\n        return Err("no".into());\n    }\n    let out = Command::new(tool).arg(extra).output().map_err(|e| e.to_string())?;`);
    // The env value always reports; the guarded parameter shares the line with
    // it, so the line gets no credit and both flows remain.
    expect(await ci(code)).toEqual([8, 8]);
  });

  it('still reports: a literal-set guard whose set holds a non-literal', async () => {
    const code = wrap(`    let extra = std::env::var("EXTRA").unwrap_or_default();\n    if !matches!(tool, "uptime" | _) {\n        return Err("no".into());\n    }\n${RUN}`);
    expect((await ci(code)).length).toBe(1);
  });

  it('still reports: ![..].contains(&x) over a non-literal element', async () => {
    const code = wrap(`    let extra = std::env::var("EXTRA").unwrap_or_default();\n    if !["uptime", extra.as_str()].contains(&tool) {\n        return Err("no".into());\n    }\n${RUN}`);
    expect((await ci(code)).length).toBe(1);
  });

  it('credit ends at the first rebind: the sink before it is clean, the sink after it reports', async () => {
    const code = `use std::process::Command;

pub fn run(mut tool: String) -> Result<(), String> {
    if tool != "uptime" {
        return Err("no".into());
    }
    let _a = Command::new(&tool).output().map_err(|e| e.to_string())?;
    tool = std::env::var("X").unwrap_or_default();
    let _b = Command::new(&tool).output().map_err(|e| e.to_string())?;
    Ok(())
}
`;
    const lines = await ci(code);
    expect(lines).toEqual([9]);
  });

  it('still reports: a loop that rebinds the variable after a use in the same loop body', async () => {
    const code = `use std::process::Command;

pub fn run(mut tool: String) -> Result<(), String> {
    if tool != "uptime" {
        return Err("no".into());
    }
    for _ in 0..2 {
        let _a = Command::new(&tool).output().map_err(|e| e.to_string())?;
        tool = std::env::var("X").unwrap_or_default();
    }
    Ok(())
}
`;
    expect((await ci(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('still reports: the string literals in the guard hold a brace and a comment marker', async () => {
    const code = wrap(`    // if tool != "x" { return Err("no".into()); }\n    let _s = "if tool != \"y\" { return }";\n${RUN}`);
    expect((await ci(code)).length).toBe(1);
  });

  it('credit applies inside an inner block when the guard is in that block', async () => {
    const code = wrap(`    if std::env::var("STRICT").is_ok() {\n        if tool != "uptime" {\n            return Err("no".into());\n        }\n        let _o = Command::new(tool).output().map_err(|e| e.to_string())?;\n    }`);
    expect(await ci(code)).toEqual([]);
  });

  it('still reports: a nested fn or closure that takes its own parameter of the same name', async () => {
    const code = `use std::process::Command;

pub fn run(tool: &str) -> Result<(), String> {
    if tool != "uptime" {
        return Err("no".into());
    }
    let go = |tool: &str| Command::new(tool).output().map_err(|e| e.to_string());
    go(&std::env::var("X").unwrap_or_default())?;
    Ok(())
}
`;
    expect((await ci(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('still reports: a second source joined into the command after the guarded alias', async () => {
    const code = `use std::process::Command;

pub fn run(tool: &str) -> Result<(), String> {
    let user = std::env::var("U").unwrap_or_default();
    if tool != "uptime" {
        return Err("no".into());
    }
    let alias = tool;
    let cmd = format!("{} {}", alias, user);
    Command::new("sh").arg("-c").arg(cmd).status().map_err(|e| e.to_string())?;
    Ok(())
}
`;
    expect((await ci(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('still reports: a second parameter concatenated into the guarded command on one line', async () => {
    const code = `use std::process::Command;

pub fn run(tool: &str, extra: &str) -> Result<(), String> {
    if tool != "uptime" {
        return Err("no".into());
    }
    Command::new(tool.to_string() + extra).status().map_err(|e| e.to_string())?;
    Ok(())
}
`;
    expect((await ci(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('a tail-expression sink after the guard is credited', async () => {
    const code = `use std::process::Command;

pub fn run(tool: &str) -> std::io::Result<std::process::ExitStatus> {
    if tool != "uptime" {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "no"));
    }
    Command::new(tool).status()
}
`;
    expect(await ci(code)).toEqual([]);
  });

  // --- Review feedback on PR #734: pattern rebinds, multi-line reads, mutations, closure return ---

  it('still reports: tuple pattern rebind of the guarded name', async () => {
    const code = wrap(`    let extra = std::env::var("E").unwrap_or_default();\n    if tool != "uptime" {\n        return Err("no".into());\n    }\n    let (tool, _n) = (extra.as_str(), 1);\n    let out = Command::new(tool).output().map_err(|e| e.to_string())?;`);
    expect((await ci(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('still reports: struct pattern rebind of the guarded name', async () => {
    const code = `use std::process::Command;

struct Wrapper<'a> { tool: &'a str }

pub fn run(tool: &str) -> Result<(), String> {
    let extra = std::env::var("E").unwrap_or_default();
    if tool != "uptime" {
        return Err("no".into());
    }
    let Wrapper { tool } = Wrapper { tool: extra.as_str() };
    Command::new(tool).status().map_err(|e| e.to_string())?;
    Ok(())
}
`;
    expect((await ci(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('still reports: let-else Some(tool) pattern rebind', async () => {
    const code = wrap(`    let extra = std::env::var("E").unwrap_or_default();\n    if tool != "uptime" {\n        return Err("no".into());\n    }\n    let Some(tool) = Some(extra.as_str()) else { return Err("x".into()); };\n    let out = Command::new(tool).output().map_err(|e| e.to_string())?;`);
    expect((await ci(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('still reports: if-let Some(tool) pattern rebind', async () => {
    const code = wrap(`    let extra = std::env::var("E").unwrap_or_default();\n    if tool != "uptime" {\n        return Err("no".into());\n    }\n    if let Some(tool) = Some(extra.as_str()) {\n        let out = Command::new(tool).output().map_err(|e| e.to_string())?;\n    }`);
    expect((await ci(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('still reports: for-loop pattern rebind of the guarded name', async () => {
    const code = wrap(`    let extra = std::env::var("E").unwrap_or_default();\n    if tool != "uptime" {\n        return Err("no".into());\n    }\n    for tool in [extra.as_str()] {\n        let out = Command::new(tool).output().map_err(|e| e.to_string())?;\n    }`);
    expect((await ci(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('still reports: while-let pattern rebind of the guarded name', async () => {
    const code = wrap(`    let extra = std::env::var("E").unwrap_or_default();\n    if tool != "uptime" {\n        return Err("no".into());\n    }\n    let mut it = std::iter::once(extra.as_str());\n    while let Some(tool) = it.next() {\n        let out = Command::new(tool).output().map_err(|e| e.to_string())?;\n    }`);
    expect((await ci(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('still reports: match-arm pattern rebind of the guarded name', async () => {
    const code = wrap(`    let extra = std::env::var("E").unwrap_or_default();\n    if tool != "uptime" {\n        return Err("no".into());\n    }\n    match Some(extra.as_str()) {\n        Some(tool) => {\n            let out = Command::new(tool).output().map_err(|e| e.to_string())?;\n        }\n        None => {}\n    }`);
    expect((await ci(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('still reports: raw second operand on a later line of the same statement', async () => {
    const code = `use std::process::Command;

pub fn run(tool: &str) -> Result<(), String> {
    let extra = std::env::var("EXTRA").unwrap_or_default();
    if tool != "uptime" {
        return Err("no".into());
    }
    let cmd = format!("{} {}", tool,
        extra);
    let out = Command::new("sh").arg("-c").arg(cmd).output().map_err(|e| e.to_string())?;
    Ok(())
}
`;
    expect((await ci(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('still reports: insert_str mutates the guarded String after the guard', async () => {
    const code = wrap(`    if tool != "uptime" {\n        return Err("no".into());\n    }\n    let extra = std::env::var("E").unwrap_or_default();\n    tool.insert_str(0, &extra);\n    let out = Command::new(&tool).output().map_err(|e| e.to_string())?;`, 'mut tool: String');
    expect((await ci(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('still reports: write! macro mutates the guarded String after the guard', async () => {
    const code = `use std::process::Command;
use std::fmt::Write;

pub fn run(mut tool: String) -> Result<(), String> {
    if tool != "uptime" {
        return Err("no".into());
    }
    let extra = std::env::var("E").unwrap_or_default();
    write!(tool, "{}", extra).map_err(|e| e.to_string())?;
    let out = Command::new(&tool).output().map_err(|e| e.to_string())?;
    Ok(())
}
`;
    expect((await ci(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('still reports: mem::swap replaces the guarded value after the guard', async () => {
    const code = wrap(`    if tool != "uptime" {\n        return Err("no".into());\n    }\n    let mut extra = std::env::var("E").unwrap_or_default();\n    std::mem::swap(&mut tool, &mut extra);\n    let out = Command::new(&tool).output().map_err(|e| e.to_string())?;`, 'mut tool: String');
    expect((await ci(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('still reports: &mut parameter passed to a free function after the guard', async () => {
    const code = `use std::process::Command;

fn append(dst: &mut String, src: &str) {
    dst.push_str(src);
}

pub fn run(tool: &mut String) -> Result<(), String> {
    if tool != "uptime" {
        return Err("no".into());
    }
    let extra = std::env::var("E").unwrap_or_default();
    append(tool, &extra);
    let out = Command::new(tool.as_str()).output().map_err(|e| e.to_string())?;
    Ok(())
}
`;
    expect((await ci(code)).length).toBeGreaterThanOrEqual(1);
  });

  it('still reports: braceless closure return in the guard body is not a reject', async () => {
    const code = wrap(`    if tool != "a" && tool != "b" {\n        let f = |x: i32| return x;\n        let _ = f(1);\n    }\n${RUN}`);
    expect((await ci(code)).length).toBeGreaterThanOrEqual(1);
  });

  // --- Second review round on PR #734: multi-line pattern heads, renamed
  // struct fields, nested fn pattern params, destructuring assignment and
  // other &mut self methods all end the credit. ---

  describe('review round 2: still reports', () => {
    const PRELUDE = `use std::fmt::Write;
use std::ops::AddAssign;

struct W<'a> { n: i32, tool: &'a str }
struct N<'a> { name: &'a str }
struct P<'a>(&'a str, i32);
struct V<'a> { tool: &'a str }
struct U<'a>(&'a str);
`;
    const GUARD = '    if tool != "uptime" && tool != "whoami" {\n        return Err("no".into());\n    }\n';
    const SINK = '    let _o = Command::new(&tool).output().map_err(|e| e.to_string())?;';
    const SINK8 = '        let _o = Command::new(&tool).output().map_err(|e| e.to_string())?;';
    const src = (body: string, params = 'tool: &str, extra: &str') => `use std::process::Command;
${PRELUDE}
pub fn run(${params}) -> Result<String, String> {
${GUARD}${body}
    Ok(String::new())
}
`;
    const OWNED = 'mut tool: String, extra: &str';
    const MUTREF = 'mut tool: &str, extra: &str';

    const cases: Array<[string, string, string?]> = [
      // Item 1: rustfmt-wrapped pattern heads and nested fn parameter lists.
      ['let tuple pattern over several lines', `    let (\n        tool,\n        n,\n    ) = (extra, 1);\n    let _ = n;\n${SINK}`],
      ['if-let Some pattern over several lines', `    if let Some(\n        tool,\n    ) = Some(extra) {\n${SINK8}\n    }`],
      ['for tuple pattern over several lines', `    for (\n        _i,\n        tool,\n    ) in [extra].iter().enumerate() {\n${SINK8}\n    }`],
      ['match-arm tuple pattern over several lines', `    match (extra, 1) {\n        (\n            tool,\n            _,\n        ) => {\n    ${SINK8}\n        }\n    }`],
      ['let struct pattern over several lines', `    let W {\n        n: _,\n        tool,\n    } = W { n: 1, tool: extra };\n${SINK}`],
      ['nested fn whose parameter list spans lines', `    fn inner(\n        tool: &str,\n        n: i32,\n    ) -> Result<String, String> {\n        let _ = n;\n${SINK8}\n        Ok(String::new())\n    }\n    inner(extra, 1)?;`],
      // Item 2: renamed struct-field patterns.
      ['let renamed struct field', `    let N { name: tool } = N { name: extra };\n${SINK}`],
      ['let renamed struct field with mut', `    let N { name: mut tool } = N { name: extra };\n${SINK}`],
      ['if-let renamed struct field', `    if let N { name: tool } = (N { name: extra }) {\n${SINK8}\n    }`],
      ['let renamed struct field over several lines', `    let N {\n        name: tool,\n    } = N { name: extra };\n${SINK}`],
      ['match-arm renamed struct field', `    match (N { name: extra }) {\n        N { name: tool } => {\n    ${SINK8}\n        }\n    }`],
      // Item 3: nested fn with a pattern parameter.
      ['nested fn tuple-pattern parameter', `    fn inner((tool, _n): (&str, i32)) -> Result<String, String> {\n${SINK8}\n        Ok(String::new())\n    }\n    inner((extra, 1))?;`],
      ['nested fn struct-pattern parameter', `    fn inner(V { tool }: V) -> Result<String, String> {\n${SINK8}\n        Ok(String::new())\n    }\n    inner(V { tool: extra })?;`],
      ['nested fn tuple-struct parameter', `    fn inner(U(tool): U) -> Result<String, String> {\n${SINK8}\n        Ok(String::new())\n    }\n    inner(U(extra))?;`],
      ['nested fn tuple-pattern parameter over several lines', `    fn inner(\n        (tool, _n): (&str, i32),\n    ) -> Result<String, String> {\n${SINK8}\n        Ok(String::new())\n    }\n    inner((extra, 1))?;`],
      ['nested generic fn with a pattern parameter', `    fn inner<'a>(U(tool): U<'a>) -> Result<String, String> {\n${SINK8}\n        Ok(String::new())\n    }\n    inner(U(extra))?;`],
      // Item 4: destructuring assignment to a \`mut tool: &str\` parameter.
      ['tuple destructuring assignment', `    let n;\n    (tool, n) = (extra, 1);\n    let _ = n;\n${SINK}`, MUTREF],
      ['tuple destructuring assignment over several lines', `    let n;\n    (\n        tool,\n        n,\n    ) = (extra, 1);\n    let _ = n;\n${SINK}`, MUTREF],
      ['struct destructuring assignment', `    W { tool, .. } = W { tool: extra, n: 1 };\n${SINK}`, MUTREF],
      ['struct destructuring assignment over several lines', `    W {\n        tool,\n        ..\n    } = W { tool: extra, n: 1 };\n${SINK}`, MUTREF],
      ['tuple-struct destructuring assignment', `    P(tool, _) = P(extra, 1);\n${SINK}`, MUTREF],
      ['tuple-struct destructuring assignment over several lines', `    P(\n        tool,\n        _,\n    ) = P(extra, 1);\n${SINK}`, MUTREF],
      // Item 5: other &mut self methods on an owned \`mut tool: String\`.
      ['clone_from', `    tool.clone_from(&extra.to_string());\n${SINK}`, OWNED],
      ['clone_from over several lines', `    tool.clone_from(\n        &extra.to_string(),\n    );\n${SINK}`, OWNED],
      ['write_fmt', `    tool.write_fmt(format_args!("{}", extra)).map_err(|e| e.to_string())?;\n${SINK}`, OWNED],
      ['write_char', `    tool.write_char(extra.chars().next().unwrap_or('x')).map_err(|e| e.to_string())?;\n${SINK}`, OWNED],
      ['write_str', `    tool.write_str(extra).map_err(|e| e.to_string())?;\n${SINK}`, OWNED],
      ['write_str with the call on the next line', `    tool\n        .write_str(extra)\n        .map_err(|e| e.to_string())?;\n${SINK}`, OWNED],
      ['add_assign', `    tool.add_assign(extra);\n${SINK}`, OWNED],
      ['a method that is not on any list (as_mut_vec)', `    unsafe { tool.as_mut_vec() }.extend_from_slice(extra.as_bytes());\n${SINK}`, OWNED],
      // Non-blocking note from the review.
      ['two statements on one line: a credited sink then a raw sink', `    let _a = Command::new(&tool).output().map_err(|e| e.to_string())?; let _b = Command::new(extra).output().map_err(|e| e.to_string())?;`],
    ];

    for (const [title, body, params] of cases) {
      it(title, async () => {
        expect((await ci(src(body, params))).length).toBeGreaterThanOrEqual(1);
      });
    }
  });

  // The engine does not carry a flow through a closure whose parameter list
  // is wrapped over lines even without a guard, so this one is checked on the
  // credit lines directly: the sink line must get no credit.
  it('review round 2: a closure whose parameter list spans lines gets no credit', () => {
    const code = `use std::process::Command;

pub fn run(tool: &str, extra: &str) -> Result<(), String> {
    if tool != "uptime" && tool != "whoami" {
        return Err("no".into());
    }
    let go = |
        tool: &str,
    | {
        Command::new(tool).output().map_err(|e| e.to_string())
    };
    go(extra)?;
    Ok(())
}
`;
    const lines = findRustLiteralEqualityGuardSanitizers(code).map((s) => s.line);
    expect(lines).not.toContain(10);
  });

  describe('review round 2: credit still applies', () => {
    const GUARD = '    if tool != "uptime" && tool != "whoami" {\n        return Err("no".into());\n    }\n';
    const SINK = '    let _o = Command::new(&tool).output().map_err(|e| e.to_string())?;';
    const src = (body: string, params = 'tool: &str') => `use std::process::Command;

pub fn run(${params}) -> Result<String, String> {
${GUARD}${body}
    Ok(String::new())
}
`;
    it('a multi-line let that binds other names', async () => {
      expect(await ci(src(`    let (\n        a,\n        b,\n    ) = (1, 2);\n    let _ = a + b;\n${SINK}`))).toEqual([]);
    });
    it('a nested fn with other parameter names', async () => {
      expect(await ci(src(`    fn helper(\n        x: i32,\n    ) -> i32 {\n        x\n    }\n    let _ = helper(1);\n${SINK}`))).toEqual([]);
    });
    it('read-only methods on an owned mut String', async () => {
      expect(await ci(src(`    if tool.is_empty() || tool.len() > 10 {\n        return Err("x".into());\n    }\n    let _o = Command::new(tool.as_str()).output().map_err(|e| e.to_string())?;`, 'mut tool: String'))).toEqual([]);
    });
  });
});
