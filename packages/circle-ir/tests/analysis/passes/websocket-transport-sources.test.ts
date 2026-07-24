/**
 * Tests for cognium-dev #213 — WebSocket transport-channel sources.
 *
 * Second slice of the #213 transport-channel matrix. Extends the Lambda
 * event-shape coverage from the first slice with WebSocket handler
 * payload sources across the four languages that ship WS-handler idioms:
 *
 *   - Python — FastAPI / Starlette / Django Channels: `WebSocket.receive_*`
 *   - Go     — gorilla/websocket, nhooyr.io/websocket: `Conn.ReadMessage`
 *   - Java   — Jakarta WebSocket + Spring STOMP: `@OnMessage`,
 *              `@MessageMapping`, `@SubscribeMapping`
 *
 *   - JS/TS  — ws / Socket.IO callback-param shape: `.on('message', cb)`
 *              extracts the callback's first parameter name and treats
 *              it as `network_input`. Event allowlist: message / text /
 *              binary.
 */

import { describe, it, beforeAll, expect } from 'vitest';
import { analyze, initAnalyzer } from '../../../src/index.js';

const hasFlow = (r: Awaited<ReturnType<typeof analyze>>) =>
  (r.taint.flows?.length ?? 0) > 0;

describe('cognium-dev #213 — WebSocket transport-channel sources', () => {
  beforeAll(async () => {
    await initAnalyzer();
  });

  // ── Python ────────────────────────────────────────────────────────────

  it('TP — FastAPI `WebSocket.receive_text()` flows to command exec', async () => {
    const code = `from fastapi import WebSocket
import subprocess

async def endpoint(websocket: WebSocket):
    await websocket.accept()
    data = await websocket.receive_text()
    subprocess.run(data, shell=True)
`;
    const r = await analyze(code, 'ws-text.py', 'python');
    expect(hasFlow(r)).toBe(true);
  });

  it('TP — FastAPI `WebSocket.receive_json()` field flows to command exec', async () => {
    const code = `from fastapi import WebSocket
import subprocess

async def endpoint(websocket: WebSocket):
    await websocket.accept()
    payload = await websocket.receive_json()
    subprocess.run("echo " + payload["cmd"], shell=True)
`;
    const r = await analyze(code, 'ws-json.py', 'python');
    expect(hasFlow(r)).toBe(true);
  });

  it('TP — inline `await websocket.receive_text()` at sink call site flows', async () => {
    const code = `from fastapi import WebSocket
import subprocess

async def endpoint(websocket: WebSocket):
    subprocess.run(await websocket.receive_text(), shell=True)
`;
    const r = await analyze(code, 'ws-inline.py', 'python');
    expect(hasFlow(r)).toBe(true);
  });

  it('FP-guard — bare `queue.receive()` does not fire (not WebSocket-scoped)', async () => {
    // We deliberately did not add a bare `.receive\s*\(` regex; only
    // `receive_text` / `receive_bytes` / `receive_json` are broad, and
    // `receive` is class-scoped to `WebSocket`. Verify a synthetic queue
    // pattern with a bare `receive()` doesn't emit a WS-typed source.
    const code = `import subprocess

def handler(queue):
    data = queue.receive()
    subprocess.run(data, shell=True)
`;
    const r = await analyze(code, 'queue.py', 'python');
    const wsTyped = r.taint.sources.filter(
      s => s.type === 'network_input' || s.type === 'http_body',
    );
    expect(wsTyped.length).toBe(0);
  });

  // ── Go ────────────────────────────────────────────────────────────────

  it('TP — Go gorilla/websocket `Conn.ReadMessage()` flows to SQL sink', async () => {
    const code = `package main
import (
  "database/sql"
  "github.com/gorilla/websocket"
)

func handler(conn *websocket.Conn, db *sql.DB) {
  _, message, _ := conn.ReadMessage()
  db.Query("SELECT * FROM t WHERE x = " + string(message))
}
`;
    const r = await analyze(code, 'ws.go', 'go');
    expect(hasFlow(r)).toBe(true);
  });

  // ── Java ──────────────────────────────────────────────────────────────

  it('TP — Java `@OnMessage` param flows to SQL sink', async () => {
    const code = `import javax.websocket.OnMessage;
import java.sql.Statement;

public class Ws {
  Statement st;
  @OnMessage
  public void onMessage(String msg) throws Exception {
    st.execute("SELECT * FROM t WHERE x = '" + msg + "'");
  }
}
`;
    const r = await analyze(code, 'Ws.java', 'java');
    expect(hasFlow(r)).toBe(true);
  });

  // ── JavaScript / TypeScript ──────────────────────────────────────────

  it('TP — Node ws `.on("message", (data) => …)` arrow callback flows', async () => {
    const code = `const WebSocket = require('ws');
const wss = new WebSocket.Server({ port: 8080 });
const { exec } = require('child_process');
wss.on('connection', (ws) => {
  ws.on('message', (data) => {
    exec('echo ' + data);
  });
});`;
    const r = await analyze(code, 'ws-arrow.js', 'javascript');
    expect(hasFlow(r)).toBe(true);
  });

  it('TP — Node ws `.on("message", function(data){…})` function-expr callback flows', async () => {
    const code = `const WebSocket = require('ws');
const wss = new WebSocket.Server({ port: 8080 });
const { exec } = require('child_process');
wss.on('connection', function (ws) {
  ws.on('message', function (data) {
    exec('echo ' + data);
  });
});`;
    const r = await analyze(code, 'ws-fn.js', 'javascript');
    expect(hasFlow(r)).toBe(true);
  });

  it('TP — Socket.IO `socket.on("message", (payload) => …)` flows', async () => {
    const code = `const io = require('socket.io')(3000);
const { exec } = require('child_process');
io.on('connection', (socket) => {
  socket.on('message', (payload) => {
    exec('echo ' + payload);
  });
});`;
    const r = await analyze(code, 'socketio.js', 'javascript');
    expect(hasFlow(r)).toBe(true);
  });

  it('TP — TypeScript typed callback param flows', async () => {
    const code = `import WebSocket from 'ws';
const wss = new WebSocket.Server({ port: 8080 });
const { exec } = require('child_process');
wss.on('connection', (ws: WebSocket) => {
  ws.on('message', (data: string) => {
    exec('echo ' + data);
  });
});`;
    const r = await analyze(code, 'ws.ts', 'typescript');
    expect(hasFlow(r)).toBe(true);
  });

  it('FP-guard — `.on("drain", cb)` and other lifecycle events do NOT fire', async () => {
    // Only the message-payload events (message / text / binary) are on
    // the allowlist. Lifecycle events (drain, close, error, connection)
    // carry non-user-input args (metadata, socket handles).
    const code = `const q = new Queue();
const { exec } = require('child_process');
q.on('drain', (info) => {
  exec('echo ' + info);
});
q.on('close', (code) => {
  console.log(code);
});`;
    const r = await analyze(code, 'queue.js', 'javascript');
    const wsSources = r.taint.sources.filter(
      s => s.type === 'network_input' && (s.variable === 'info' || s.variable === 'code'),
    );
    expect(wsSources.length).toBe(0);
  });

  it('FP-guard — `err` / `error` callback param is excluded even on message events', async () => {
    // Rare shape: `.on('message', (err, data) => ...)` where the first
    // arg is Node-style error. We currently take the first param only;
    // if it's named `err` or `error` we skip to avoid poisoning
    // downstream scans. Real WS APIs place data first anyway.
    const code = `ws.on('message', (err) => {
  console.log(err);
});`;
    const r = await analyze(code, 'err.js', 'javascript');
    const errSources = r.taint.sources.filter(s => s.variable === 'err');
    expect(errSources.length).toBe(0);
  });

  it('TP — Spring STOMP `@MessageMapping` param flows to SQL sink', async () => {
    const code = `import org.springframework.messaging.handler.annotation.MessageMapping;
import java.sql.Statement;

public class StompCtrl {
  Statement st;
  @MessageMapping("/greet")
  public void greet(String body) throws Exception {
    st.execute("SELECT * FROM t WHERE x = '" + body + "'");
  }
}
`;
    const r = await analyze(code, 'StompCtrl.java', 'java');
    expect(hasFlow(r)).toBe(true);
  });
});
