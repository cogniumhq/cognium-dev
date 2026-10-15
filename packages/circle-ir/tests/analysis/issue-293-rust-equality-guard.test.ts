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
});
