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

  // Juice Shop's publisher-correct fix (noSqlReviewsChallenge_3_correct):
  // a string type reject-guard rules out an operator object in the filter.
  describe('string type reject-guard (Stage 15h2)', () => {
    const guarded = (guard: string) => `${guard}
  db.reviewsCollection.update(
    { _id: req.body.id },
    { $set: { message: req.body.message } }
  )`;
    it('typeof !== string with a block return drops the sink', async () => {
      expect(await nosql(guarded(`if (typeof req.body.id !== 'string') {
    res.status(400).send()
    return
  }`))).toHaveLength(0);
    });
    it('one-line throw and an || of checks', async () => {
      expect(await nosql(guarded(`if (!req.body.id || typeof req.body.id !== 'string') throw new Error('bad id')`))).toHaveLength(0);
    });
    it('the $ne-only check (a publisher-wrong fix) keeps the sink', async () => {
      expect(await nosql(guarded(`if (req.body.id['$ne'] !== undefined) {
    res.status(400).send()
    return
  }`))).not.toHaveLength(0);
    });
    it('&& does not guard the reference on its own', async () => {
      expect(await nosql(guarded(`if (typeof req.body.id !== 'string' && req.body.strict) return`))).not.toHaveLength(0);
    });
    it('a guard on another field keeps the sink', async () => {
      expect(await nosql(guarded(`if (typeof req.body.message !== 'string') return`))).not.toHaveLength(0);
    });
    it('a guard with no reject keeps the sink', async () => {
      expect(await nosql(guarded(`if (typeof req.body.id !== 'string') {
    console.warn('odd id')
  }`))).not.toHaveLength(0);
    });
  });
});
