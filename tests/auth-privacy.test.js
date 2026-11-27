// Tests for "download my data" and "delete my account" (enhancement 5f), the flow run by the
// Auth service. Owner: Omar. Test IDs: AU-18 ... AU-24.
// Run: node --test tests/auth-privacy.test.js
// The other three services are replaced by a fake Lambda invoker, so the tests can check exactly
// which calls Auth makes, in which order, and with whose token.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');

process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
process.env.SERVICE_TRANSPORT = 'lambda';
Object.assign(process.env, { AUTH_FUNCTION: 'pb-auth-api', BUCKETS_FUNCTION: 'pb-buckets-api', TRANSACTIONS_FUNCTION: 'pb-transactions-api', INSIGHTS_FUNCTION: 'pb-insights-api' });
delete process.env.USERS_TABLE;
delete process.env.JWT_SECRET_ID;

require('../services/auth-service/lib/breachedPasswords').setFetch(async () => ({ ok: true, text: async () => '' }));
const { setInvoker } = require('../services/auth-service/node_modules/pb-common');
const totp = require('../services/auth-service/lib/totp');
const app = require('../services/auth-service/app');

let calls = [];
let failing = null; // name of a service that answers 500
setInvoker(async (fn, event) => {
  const service = fn.replace(/^pb-|-api$/g, '');
  calls.push({ service, method: event.requestContext.http.method, path: event.rawPath, auth: event.headers.authorization, body: event.body && JSON.parse(event.body) });
  if (service === failing) return { statusCode: 500, body: JSON.stringify({ error: { code: 'BOOM' } }) };
  const body = event.requestContext.http.method === 'GET'
    ? { service, count: 1, items: [`${service}-item`] }
    : { service, deleted: 1 };
  return { statusCode: 200, body: JSON.stringify(body) };
});

let base;
let server;
test.before(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}/api/auth`;
});
test.after(() => server.close());
test.beforeEach(() => { calls = []; failing = null; });

async function call(method, path, body, token) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  return { status: res.status, body: await res.json().catch(() => null), headers: res.headers };
}
const PASSWORD = 'Privacy-check-2026';
async function newUser() {
  const email = `p${crypto.randomUUID()}@example.com`;
  const r = await call('POST', '/register', { name: 'Privacy Test', email, password: PASSWORD });
  assert.equal(r.status, 201);
  return { email, token: r.body.token, id: r.body.user.id };
}

test('AU-18 download my data: profile plus every service export, with the user\'s own token', async () => {
  const u = await newUser();
  const r = await call('GET', '/me/export', undefined, u.token);
  assert.equal(r.status, 200);
  assert.match(r.headers.get('content-disposition'), /attachment/);
  assert.equal(r.body.account.email, u.email);
  for (const s of ['insights', 'transactions', 'buckets']) assert.deepEqual(r.body[s].items, [`${s}-item`]);
  assert.deepEqual(calls.map((c) => c.path).sort(), ['/api/buckets/me/export', '/api/insights/me/export', '/api/transactions/me/export']);
  for (const c of calls) assert.equal(c.auth, `Bearer ${u.token}`, 'no shared credential: the user\'s token is forwarded');
  const text = JSON.stringify(r.body);
  for (const f of ['passwordHash', 'mfaSecret', 'mfaRecoveryHashes']) assert.equal(text.includes(f), false, `${f} leaked`);
});

test('AU-19 the export is refused (503) rather than given incomplete when a service is down', async () => {
  const u = await newUser();
  failing = 'buckets';
  const r = await call('GET', '/me/export', undefined, u.token);
  assert.equal(r.status, 503);
  assert.equal(r.body.error.code, 'EXPORT_INCOMPLETE');
});

test('AU-20 delete my account needs confirm, the password, and a token (400 / 422 / 401)', async () => {
  const u = await newUser();
  assert.equal((await call('DELETE', '/me', { password: PASSWORD }, u.token)).status, 400);
  assert.equal((await call('DELETE', '/me', { confirm: false, password: PASSWORD }, u.token)).status, 400);
  assert.equal((await call('DELETE', '/me', { confirm: true, password: 'Wrong-password-9' }, u.token)).status, 422);
  assert.equal((await call('DELETE', '/me', { confirm: true, password: PASSWORD })).status, 401);
  assert.equal(calls.length, 0, 'nothing was deleted anywhere');
});

test('AU-21 delete my account: every service first, the account last; then the token stops working', async () => {
  const u = await newUser();
  const r = await call('DELETE', '/me', { confirm: true, password: PASSWORD }, u.token);
  assert.equal(r.status, 200);
  assert.equal(r.body.deleted, true);
  assert.deepEqual(calls.map((c) => `${c.method} ${c.path}`), ['DELETE /api/insights/me', 'DELETE /api/transactions/me', 'DELETE /api/buckets/me']);
  for (const c of calls) assert.deepEqual(c.body, { confirm: true });
  assert.equal((await call('GET', '/me', undefined, u.token)).status, 401);
  assert.equal((await call('POST', '/login', { email: u.email, password: PASSWORD })).status, 401);
  assert.equal((await call('POST', '/register', { name: 'Again', email: u.email, password: PASSWORD })).status, 201, 'the e-mail is free again');
});

test('AU-22 if a service cannot delete, the account is kept (503) and a retry finishes the job', async () => {
  const u = await newUser();
  failing = 'transactions';
  const r = await call('DELETE', '/me', { confirm: true, password: PASSWORD }, u.token);
  assert.equal(r.status, 503);
  assert.equal(r.body.error.code, 'DELETE_INCOMPLETE');
  assert.deepEqual(calls.map((c) => c.service), ['insights', 'transactions'], 'stops at the failure');
  assert.equal((await call('GET', '/me', undefined, u.token)).status, 200, 'account still there');
  failing = null;
  assert.equal((await call('DELETE', '/me', { confirm: true, password: PASSWORD }, u.token)).status, 200);
});

test('AU-23 with MFA on, deleting the account also needs a current code', async () => {
  const u = await newUser();
  const setup = await call('POST', '/mfa/setup', {}, u.token);
  await call('POST', '/mfa/enable', { code: totp.codeAt(setup.body.secret) }, u.token);
  assert.equal((await call('DELETE', '/me', { confirm: true, password: PASSWORD }, u.token)).status, 422);
  assert.equal((await call('DELETE', '/me', { confirm: true, password: PASSWORD, code: '000000' }, u.token)).status, 422);
  const code = totp.codeAt(setup.body.secret, Date.now() + 30000);
  assert.equal((await call('DELETE', '/me', { confirm: true, password: PASSWORD, code }, u.token)).status, 200);
});

test('AU-24 an admin account cannot be deleted from the app (403 ADMIN_ACCOUNT)', async () => {
  const email = `a${crypto.randomUUID()}@example.com`;
  await app.locals.createUser({ name: 'Admin', email, password: PASSWORD, role: 'admin' });
  const ticket = (await call('POST', '/login', { email, password: PASSWORD })).body.mfaToken;
  const setup = await call('POST', '/mfa/setup', {}, ticket);
  const { token } = (await call('POST', '/mfa/enable', { code: totp.codeAt(setup.body.secret) }, ticket)).body;
  const r = await call('DELETE', '/me', { confirm: true, password: PASSWORD, code: totp.codeAt(setup.body.secret, Date.now() + 30000) }, token);
  assert.equal(r.status, 403);
  assert.equal(r.body.error.code, 'ADMIN_ACCOUNT');
  assert.equal(calls.filter((c) => c.method === 'DELETE').length, 0);
});
