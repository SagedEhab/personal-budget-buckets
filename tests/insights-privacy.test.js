// Tests for the Insights service's part of "download my data" / "delete my data" (enhancement 5f).
// Owner: Omar. Test IDs: IN-01 ... IN-04.
// Run: node --test tests/insights-privacy.test.js
// The Auth and Transactions services are replaced by a fake Lambda invoker (no Docker needed).
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');

process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
process.env.SERVICE_TRANSPORT = 'lambda';
process.env.ACCOUNT_CHECK_CACHE_MS = '0';
Object.assign(process.env, { AUTH_FUNCTION: 'pb-auth-api', BUCKETS_FUNCTION: 'pb-buckets-api', TRANSACTIONS_FUNCTION: 'pb-transactions-api' });
delete process.env.REPORTS_TABLE;
delete process.env.REPORTS_BUCKET;
delete process.env.JWT_SECRET_ID;

const { setInvoker, issueToken } = require('../services/insights-service/node_modules/pb-common');
const app = require('../services/insights-service/app');

setInvoker(async (fn, event) => {
  if (fn === 'pb-auth-api') return { statusCode: 200, body: JSON.stringify({ status: 'active', role: 'user' }) };
  // Transactions: two rows for the CSV report
  return { statusCode: 200, body: JSON.stringify({ baseCurrency: 'EGP', total: 2, items: [
    { date: '2026-11-02', type: 'expense', amount: 120, currency: 'EGP', amountBase: 120, bucketName: 'Food', paymentMethod: 'cash', note: 'groceries' },
    { date: '2026-11-03', type: 'income', amount: 5000, currency: 'EGP', amountBase: 5000, bucketName: '', paymentMethod: 'bank', note: 'salary' }
  ] }) };
});

let base;
let server;
test.before(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}/api/insights`;
});
test.after(() => server.close());

const tokenFor = (id) => issueToken({ id, role: 'user', baseCurrency: 'EGP', name: 'Insights Test' });
async function call(method, path, body, token) {
  const res = await fetch(base + path, {
    method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  return { status: res.status, body: res.status === 204 ? null : await res.json() };
}
const makeReport = (t) => call('POST', '/reports', { type: 'transactions', from: '2026-11-01', to: '2026-11-30' }, t);

test('IN-01 export holds the user\'s reports with their CSV text, and no storage keys', async () => {
  const t = await tokenFor(crypto.randomUUID());
  assert.equal((await makeReport(t)).status, 201);
  const r = await call('GET', '/me/export', undefined, t);
  assert.equal(r.status, 200);
  assert.equal(r.body.service, 'insights');
  assert.equal(r.body.count, 1);
  assert.match(r.body.reports[0].csv, /groceries/);
  for (const f of ['pk', 'sk', 's3Key', 'content']) assert.equal(f in r.body.reports[0], false, `${f} leaked`);
});

test('IN-02 a user only ever exports their own reports', async () => {
  const a = await tokenFor(crypto.randomUUID());
  const b = await tokenFor(crypto.randomUUID());
  await makeReport(a);
  const r = await call('GET', '/me/export', undefined, b);
  assert.equal(r.body.count, 0);
});

test('IN-03 delete my data needs {"confirm": true} (400 otherwise)', async () => {
  const t = await tokenFor(crypto.randomUUID());
  assert.equal((await call('DELETE', '/me', {}, t)).status, 400);
  assert.equal((await call('DELETE', '/me', { confirm: false }, t)).status, 400);
  assert.equal((await call('DELETE', '/me', { confirm: 'yes' }, t)).status, 400);
});

test('IN-04 delete my data removes every report of that user only', async () => {
  const a = await tokenFor(crypto.randomUUID());
  const b = await tokenFor(crypto.randomUUID());
  await makeReport(a); await makeReport(a); await makeReport(b);
  const r = await call('DELETE', '/me', { confirm: true }, a);
  assert.equal(r.status, 200);
  assert.equal(r.body.deletedReports, 2);
  assert.equal((await call('GET', '/reports', undefined, a)).body.count, 0);
  assert.equal((await call('GET', '/reports', undefined, b)).body.count, 1, 'other user untouched');
});
