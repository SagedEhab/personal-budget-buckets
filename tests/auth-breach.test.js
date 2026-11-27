// Tests for the breached-password check (enhancement 5c, Have I Been Pwned k-anonymity API)
// in the Auth service. Owner: Omar. Test IDs: AU-13 ... AU-17.
// Run: node --test tests/auth-breach.test.js
// The API is replaced by a fake, so the tests need no internet and record exactly what was sent.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');

process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
delete process.env.USERS_TABLE;
delete process.env.JWT_SECRET_ID;

const breached = require('../services/auth-service/lib/breachedPasswords');
const app = require('../services/auth-service/app');

// SHA-1("password") = 5BAA6 1E4C9B93F3F0682250B6CF8331B7EE68FD8 (a well-known breached password)
const PASSWORD_SUFFIX = '1E4C9B93F3F0682250B6CF8331B7EE68FD8';
let sent = [];
function fakeApi(body, { status = 200, fail } = {}) {
  breached.setFetch(async (url, opts) => {
    sent.push({ url, headers: opts.headers });
    if (fail) { const e = new Error('down'); e.name = fail; throw e; }
    return { ok: status === 200, status, text: async () => body };
  });
}

let base;
let server;
test.before(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}/api/auth`;
});
test.after(() => { server.close(); breached.setFetch(null); });
test.beforeEach(() => { sent = []; });

const register = async (password) => {
  const res = await fetch(`${base}/register`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'Breach Test', email: `b${crypto.randomUUID()}@example.com`, password })
  });
  return { status: res.status, body: await res.json() };
};

test('AU-13 only the first 5 characters of the SHA-1 hash are sent, never the password', async () => {
  fakeApi('');
  const { prefix, suffix } = breached.sha1Parts('password');
  assert.equal(prefix, '5BAA6');
  assert.equal(suffix, PASSWORD_SUFFIX);
  await breached.checkPassword('Secret-password-77');
  assert.equal(sent.length, 1);
  const url = sent[0].url;
  assert.match(url, /^https:\/\/api\.pwnedpasswords\.com\/range\/[0-9A-F]{5}$/);
  assert.equal(url.includes('Secret-password-77'), false);
  assert.equal(sent[0].headers['Add-Padding'], 'true');
});

test('AU-14 a password found in breaches is rejected at registration with 422 PASSWORD_BREACHED', async () => {
  const hit = breached.sha1Parts('Password1234').suffix;
  fakeApi(`0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n${hit}:5120\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0`);
  const r = await register('Password1234');
  assert.equal(r.status, 422);
  assert.equal(r.body.error.code, 'PASSWORD_BREACHED');
});

test('AU-15 a password not in the list (or only in padding rows with count 0) is accepted', async () => {
  const pad = breached.sha1Parts('Unseen-river-2026').suffix;
  fakeApi(`${pad}:0\r\n0018A45C4D1DEF81644B54AB7F969B88D65:3`);
  assert.equal((await register('Unseen-river-2026')).status, 201);
});

test('AU-16 if the API is down or slow, registration still works (fail open)', async () => {
  fakeApi('', { status: 503 });
  assert.equal((await register('Quiet-harbour-31')).status, 201);
  fakeApi('', { fail: 'TimeoutError' });
  assert.deepEqual(await breached.checkPassword('x'), { checked: false, reason: 'timeout' });
  assert.equal((await register('Quiet-harbour-32')).status, 201);
});

test('AU-17 the normal password rules still apply before the API is asked', async () => {
  fakeApi('');
  const r = await register('short1');
  assert.equal(r.status, 400);
  assert.equal(sent.length, 0, 'invalid input never reaches the external API');
});
