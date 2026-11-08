/**
 * cognium-dev #1172: the legacy MongoDB / MarsDB / NeDB collection methods
 * `update`, `remove` and `findAndModify` are nosql_injection sinks on their
 * filter argument. Class-scoped to `Collection`, so `hash.update(x)` is not.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initAnalyzer, analyze } from '../../src/analyzer.js';

const handler = (call: string) => `import express from 'express';
const app = express();
app.patch('/r', (req: express.Request, res: express.Response) => {
  ${call}
  res.json({})
})
`;
async function nosql(call: string) {
  const ir = await analyze(handler(call), 'r.ts', 'typescript');
  return ir.taint.flows.filter(f => f.sink_type === 'nosql_injection');
}

describe('#1172: legacy collection update/remove/findAndModify', () => {
  beforeAll(async () => { await initAnalyzer(); });

  it('update with a request-controlled filter (Juice Shop noSqlReviews shape)', async () => {
    expect(await nosql('db.reviewsCollection.update({ _id: req.body.id }, { $set: { message: req.body.message } }, { multi: true })')).not.toHaveLength(0);
  });
  it('remove', async () => {
    expect(await nosql('db.reviewsCollection.remove({ _id: req.body.id })')).not.toHaveLength(0);
  });
  it('findAndModify', async () => {
    expect(await nosql('db.ordersCollection.findAndModify({ query: req.body.q })')).not.toHaveLength(0);
  });
  it('a literal filter is not a flow', async () => {
    expect(await nosql("db.reviewsCollection.update({ _id: 'x' }, {})")).toHaveLength(0);
  });
  for (const call of ["crypto.createHash('sha256').update(req.body.id)", 'hmac.update(req.body.id)', 'cache.update(req.body.id, 1)']) {
    it(`not a sink: ${call}`, async () => {
      const ir = await analyze(handler(call), 'r.ts', 'typescript');
      expect(ir.taint.sinks.filter(s => s.type === 'nosql_injection')).toHaveLength(0);
    });
  }
});
