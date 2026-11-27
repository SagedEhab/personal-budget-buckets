// Tests for two-step login with authenticator-app codes (enhancement 5a) in the Auth service.
// Owner: Omar. Test IDs: AU-01 ... AU-12.
// Run: node --test tests/auth-mfa.test.js
// The service runs in-process with its in-memory store (no USERS_TABLE), so no Docker is needed.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');

process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
delete process.env.USERS_TABLE;
delete process.env.JWT_SECRET_ID;

const totp = require('../services/auth-service/lib/totp');
const mfaSecrets = require('../services/auth-service/lib/mfaSecrets');
// No internet in these tests: the breached-password API (5c) answers "not found".
require('../services/auth-service/lib/breachedPasswords').setFetch(async () => ({ ok: true, text: async () => '' }));
const app = require('../services/auth-service/app');

let base;
let server;
test.before(async () => {
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}/api/auth`;
});
test.after(() => server.close());

async function call(method, path, body, token) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  return { status: res.status, body: await res.json().catch(() => null) };
}
const PASSWORD = 'Correct-horse-42';
let n = 0;
async function newUser(role = 'user') {
  n += 1;
  const email = `mfa${n}-${Date.now()}@example.com`;
  if (role === 'admin') await app.locals.createUser({ name: 'Admin Test', email, password: PASSWORD, role: 'admin' });
  else assert.equal((await call('POST', '/register', { name: 'Mfa Test', email, password: PASSWORD })).status, 201);
  return email;
}
// The next 30-second step: a code that has not been used yet (the window accepts +1 step).
const nextCode = (secret) => totp.codeAt(secret, Date.now() + 30000);

async function userWithMfa() {
  const email = await newUser();
  const login = await call('POST', '/login', { email, password: PASSWORD });
  const setup = await call('POST', '/mfa/setup', {}, login.body.token);
  const enable = await call('POST', '/mfa/enable', { code: totp.codeAt(setup.body.secret) }, login.body.token);
  assert.equal(enable.status, 200);
  return { email, secret: setup.body.secret, recoveryCodes: enable.body.recoveryCodes, token: login.body.token };
}

test('AU-01 TOTP codes match the RFC 6238 test vectors', () => {
  const secret = totp.base32Encode(Buffer.from('12345678901234567890'));
  assert.equal(totp.codeAt(secret, 59 * 1000), '287082');
  assert.equal(totp.codeAt(secret, 1111111109 * 1000), '081804');
  assert.equal(totp.codeAt(secret, 2000000000 * 1000), '279037');
});

test('AU-02 a code is accepted once: the same time step cannot be replayed', () => {
  const secret = totp.generateSecret();
  const code = totp.codeAt(secret);
  const step = totp.verifyCode(secret, code);
  assert.notEqual(step, null);
  assert.equal(totp.verifyCode(secret, code, { afterStep: step }), null);
  assert.equal(totp.verifyCode(secret, '12345'), null, 'wrong length');
  assert.equal(totp.verifyCode(secret, totp.codeAt(secret, Date.now() - 5 * 60000)), null, 'old code');
});

test('AU-03 the authenticator secret is stored encrypted and bound to its user', async () => {
  const secret = totp.generateSecret();
  const stored = await mfaSecrets.encryptSecret(secret, 'user-a');
  assert.equal(stored.includes(secret), false);
  assert.match(stored, /^v1\./);
  assert.equal(await mfaSecrets.decryptSecret(stored, 'user-a'), secret);
  await assert.rejects(() => mfaSecrets.decryptSecret(stored, 'user-b'), 'copied to another user must fail');
});

test('AU-04 recovery codes: 10 codes, only hashes kept, each works once', () => {
  const { codes, hashes } = mfaSecrets.newRecoveryCodes();
  assert.equal(codes.length, 10);
  assert.equal(new Set(codes).size, 10);
  for (const h of hashes) assert.equal(codes.includes(h), false);
  const left = mfaSecrets.useRecoveryCode(hashes, codes[3].toUpperCase());
  assert.equal(left.length, 9);
  assert.equal(mfaSecrets.useRecoveryCode(left, codes[3]), null, 'second use refused');
  assert.equal(mfaSecrets.useRecoveryCode(hashes, 'aaaaa-bbbbb'), null);
});

test('AU-05 a user without MFA logs in as before and gets a token', async () => {
  const email = await newUser();
  const r = await call('POST', '/login', { email, password: PASSWORD });
  assert.equal(r.status, 200);
  assert.ok(r.body.token);
  assert.equal(r.body.user.mfaEnabled, false);
});

test('AU-06 with MFA on, the password alone gives no token, and the MFA ticket is not an access token', async () => {
  const { email } = await userWithMfa();
  const r = await call('POST', '/login', { email, password: PASSWORD });
  assert.equal(r.status, 200);
  assert.equal(r.body.mfaRequired, true);
  assert.equal(r.body.token, undefined);
  assert.equal((await call('GET', '/me', undefined, r.body.mfaToken)).status, 401);
});

test('AU-07 the right code finishes the login; the same code cannot be used twice', async () => {
  const { email, secret } = await userWithMfa();
  const t1 = (await call('POST', '/login', { email, password: PASSWORD })).body.mfaToken;
  const code = nextCode(secret);
  const ok = await call('POST', '/mfa/verify', { mfaToken: t1, code });
  assert.equal(ok.status, 200);
  assert.equal((await call('GET', '/me', undefined, ok.body.token)).status, 200);
  const t2 = (await call('POST', '/login', { email, password: PASSWORD })).body.mfaToken;
  assert.equal((await call('POST', '/mfa/verify', { mfaToken: t2, code })).status, 401);
});

test('AU-08 five wrong codes lock the account (429), even with the right code afterwards', async () => {
  const { email, secret } = await userWithMfa();
  const t = (await call('POST', '/login', { email, password: PASSWORD })).body.mfaToken;
  for (let i = 0; i < 5; i += 1) {
    assert.equal((await call('POST', '/mfa/verify', { mfaToken: t, code: '000000' })).status, 401);
  }
  assert.equal((await call('POST', '/mfa/verify', { mfaToken: t, code: nextCode(secret) })).status, 429);
  assert.equal((await call('POST', '/login', { email, password: PASSWORD })).status, 429);
});

test('AU-09 an admin must set MFA up before getting a token; the setup ticket cannot reach admin routes', async () => {
  const email = await newUser('admin');
  const r = await call('POST', '/login', { email, password: PASSWORD });
  assert.equal(r.status, 200);
  assert.equal(r.body.mfaSetupRequired, true);
  assert.equal(r.body.token, undefined);
  assert.equal((await call('GET', '/users', undefined, r.body.mfaToken)).status, 401);

  const setup = await call('POST', '/mfa/setup', {}, r.body.mfaToken);
  assert.equal(setup.status, 200);
  assert.match(setup.body.qrDataUrl, /^data:image\/png;base64,/);
  assert.match(setup.body.otpauthUrl, /^otpauth:\/\/totp\//);
  assert.equal((await call('POST', '/mfa/enable', { code: '000000' }, r.body.mfaToken)).status, 422);
  const enable = await call('POST', '/mfa/enable', { code: totp.codeAt(setup.body.secret) }, r.body.mfaToken);
  assert.equal(enable.status, 200);
  assert.equal(enable.body.recoveryCodes.length, 10);
  assert.equal((await call('GET', '/users', undefined, enable.body.token)).status, 200);

  const again = await call('POST', '/login', { email, password: PASSWORD });
  assert.equal(again.body.mfaRequired, true);
});

test('AU-10 admins cannot turn MFA off (403); a user can, with password and code', async () => {
  const email = await newUser('admin');
  const ticket = (await call('POST', '/login', { email, password: PASSWORD })).body.mfaToken;
  const setup = await call('POST', '/mfa/setup', {}, ticket);
  const { token } = (await call('POST', '/mfa/enable', { code: totp.codeAt(setup.body.secret) }, ticket)).body;
  const refused = await call('POST', '/mfa/disable', { password: PASSWORD, code: nextCode(setup.body.secret) }, token);
  assert.equal(refused.status, 403);
  assert.equal(refused.body.error.code, 'MFA_REQUIRED_FOR_ADMIN');

  const u = await userWithMfa();
  assert.equal((await call('POST', '/mfa/disable', { password: 'Wrong-password-1', code: nextCode(u.secret) }, u.token)).status, 422);
  const off = await call('POST', '/mfa/disable', { password: PASSWORD, code: nextCode(u.secret) }, u.token);
  assert.equal(off.status, 200);
  assert.equal(off.body.mfaEnabled, false);
});

test('AU-11 a recovery code finishes the login once', async () => {
  const { email, recoveryCodes } = await userWithMfa();
  const t1 = (await call('POST', '/login', { email, password: PASSWORD })).body.mfaToken;
  const ok = await call('POST', '/mfa/verify', { mfaToken: t1, recoveryCode: recoveryCodes[0] });
  assert.equal(ok.status, 200);
  assert.equal(ok.body.recoveryCodesLeft, 9);
  const t2 = (await call('POST', '/login', { email, password: PASSWORD })).body.mfaToken;
  assert.equal((await call('POST', '/mfa/verify', { mfaToken: t2, recoveryCode: recoveryCodes[0] })).status, 401);
});

test('AU-12 no MFA secret, recovery hash or counter ever leaves the service', async () => {
  const { token } = await userWithMfa();
  const me = await call('GET', '/me', undefined, token);
  assert.equal(me.body.mfaEnabled, true);
  const text = JSON.stringify(me.body);
  for (const f of ['mfaSecret', 'mfaPendingSecret', 'mfaRecoveryHashes', 'mfaLastStep', 'failedMfa', 'passwordHash']) {
    assert.equal(text.includes(f), false, `${f} leaked`);
  }
  assert.equal((await call('POST', '/mfa/setup', {}, token)).status, 409, 'already on');
});
