/**
 * #394 — Go gRPC request messages are remote input.
 *
 * Scoped by the PARAMETER of a canonical unary server handler, never by the
 * getter name: `GetX()` is on every protobuf-generated type, so a blanket
 * "getter is a source" rule would repeat the classless-entry mistake removed in
 * #387/#390. The negative fixtures pin each boundary of that scope.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const file = (...body: string[]) =>
  ['package server', 'import ("context"; "encoding/json"; "io/ioutil"; "path/filepath"; "strconv")', '', ...body].join('\n');
const HANDLER = 'func (s *Server) Mount(ctx context.Context, req *v1alpha1.MountRequest) (*v1alpha1.MountResponse, error) {';

const run = async (code: string) => {
  const r = await analyze(code, 'server.go', 'go');
  return {
    grpc: r.taint.sources.filter((s) => /gRPC request message/.test(s.location ?? '')),
    flows: (r.taint.flows ?? []).map((f) => `${f.sink_type}:${f.source_line}->${f.sink_line}`),
  };
};

describe('#394 — Go gRPC request sources', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('binds the Unmarshal out-argument and reaches the path sink (the secrets-store-csi shape)', async () => {
    const { grpc, flows } = await run(file(
      HANDLER,
      '  var attrib map[string]string',
      '  err := json.Unmarshal([]byte(req.GetAttributes()), &attrib)',
      '  _ = err',
      '  name := attrib["objectName"]',
      '  ioutil.WriteFile(filepath.Join("/mnt", name), []byte("x"), 0644)',
      '  return nil, nil',
      '}',
    ));
    expect(grpc.map((s) => [s.type, s.variable])).toEqual([['http_body', 'attrib']]);
    expect(flows).toContain('path_traversal:6->9');
  });

  it('binds the LHS of a direct read, through conversions, chained getters and field reads', async () => {
    const { grpc } = await run(file(
      HANDLER,
      '  a := req.GetTargetPath()',
      '  b := []byte(req.GetAttributes())',
      '  c := req.GetSpec().GetName()',
      '  d := req.TargetPath',
      '  _, _, _, _ = a, b, c, d',
      '  return nil, nil',
      '}',
    ));
    expect(grpc.map((s) => s.variable)).toEqual(['a', 'b', 'c', 'd']);
  });

  it('does not bind the LHS when the read is only an argument to another call', async () => {
    const { grpc } = await run(file(
      HANDLER,
      '  out, err := provider.Mount(ctx, req.GetTargetPath())',
      '  _, _ = out, err',
      '  return nil, nil',
      '}',
    ));
    // `out` is the callee's return value, not the request string.
    expect(grpc.map((s) => s.variable)).toEqual(['req']);
  });

  it('ignores a read that is parsed to a number on the spot', async () => {
    const { grpc } = await run(file(
      HANDLER,
      '  p, err := strconv.ParseUint(req.GetPermission(), 10, 32)',
      '  _, _ = p, err',
      '  return nil, nil',
      '}',
    ));
    expect(grpc).toEqual([]);
  });

  it('ignores a read that only feeds a condition', async () => {
    const { grpc } = await run(file(
      HANDLER,
      '  if len(req.GetName()) == 0 {',
      '    return nil, nil',
      '  }',
      '  return nil, nil',
      '}',
    ));
    expect(grpc).toEqual([]);
  });

  it.each([
    ['a plain function with no receiver', 'func Mount(ctx context.Context, req *v1alpha1.MountRequest) (*v1alpha1.MountResponse, error) {'],
    ['an unexported method', 'func (s *Server) mount(ctx context.Context, req *v1alpha1.MountRequest) (*v1alpha1.MountResponse, error) {'],
    ['a message type not named *Request', 'func (s *Server) Mount(ctx context.Context, req *v1alpha1.MountParams) (*v1alpha1.MountResponse, error) {'],
    ['no context.Context first parameter', 'func (s *Server) Mount(req *v1alpha1.MountRequest) (*v1alpha1.MountResponse, error) {'],
    ['a non-(*T, error) return', 'func (s *Server) Mount(ctx context.Context, req *v1alpha1.MountRequest) error {'],
  ])('is not a handler: %s', async (_n, sig) => {
    const { grpc } = await run(file(sig as string, '  a := req.GetTargetPath()', '  _ = a', '  return nil, nil', '}'));
    expect(grpc).toEqual([]);
  });

  it('never treats GetX() on anything but the request parameter as a source', async () => {
    const { grpc } = await run(file(
      HANDLER,
      '  cfg := s.loader.GetConfig()',
      '  name := cfg.GetName()',
      '  _ = name',
      '  return nil, nil',
      '}',
    ));
    expect(grpc).toEqual([]);
  });

  it('stops at the end of the handler', async () => {
    const { grpc } = await run(file(
      HANDLER,
      '  return nil, nil',
      '}',
      '',
      'func (s *Server) helper(req *other.Thing) {',
      '  a := req.GetTargetPath()',
      '  _ = a',
      '}',
    ));
    expect(grpc).toEqual([]);
  });
});
