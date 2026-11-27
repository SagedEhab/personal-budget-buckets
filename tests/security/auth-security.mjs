// Security and end-to-end tests for the Auth and Insights services, run against the app deployed on Floci.
// Owner: Omar. Security tests (report §12): ST-03, ST-04, ST-09, ST-10, ST-15.
// End-to-end tests (report §13): IT-01 (account), IT-10 (dashboard across services), IT-12 (CSV report in S3).
// Each test prints expected vs actual and PASS/FAIL. Results are also written to evidence/security-omar.md.
// No token, password, key or MFA secret is ever printed or saved: test passwords are random and kept in memory.
//
// Run (Floci running, app deployed):
//   node tests/security/auth-security.mjs
//   API=http://<api-id>.execute-api.localhost.floci.io:4566 node tests/security/auth-security.mjs
// The admin for ST-15 is created with services/auth-service/scripts/seed-admin.js (admins cannot register).
import { execSync } from 'node:child_process';
import { writeFileSync, mkdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import crypto from 'node:crypto';

const require = createRequire(import.meta.url);
const AWS_ENV = { ...process.env, AWS_PROFILE: process.env.AWS_PROFILE || 'floci', AWS_PAGER: '', MSYS_NO_PATHCONV: '1' };
const sh = (cmd, env = AWS_ENV) => execSync(cmd, { encoding: 'utf8', env, stdio: ['ignore', 'pipe', 'pipe'] }).trim();
const API = process.env.API || `http://${sh("aws apigatewayv2 get-apis --query \"Items[?Name=='pb-http-api'].ApiId | [0]\" --output text")}.execute-api.localhost.floci.io:4566`;
const { jwt, ISSUER, AUDIENCE } = require('../../services/auth-service/node_modules/pb-common');
const totp = require('../../services/auth-service/lib/totp');
const results = [];

async function call(method, path, { token, body } = {}) {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(API + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(90000) });
  const text = await res.text();
  let data = null;
  try { data = JSON.parse(text); } catch { data = text; }
  return { status: res.status, data };
}
const code = (r) => (r.data && r.data.error ? `${r.status} ${r.data.error.code}` : `${r.status}`);
function record(id, category, scenario, expected, actual, pass) {
  results.push({ id, category, scenario, expected, actual, pass });
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${id}  ${scenario}\n      expected: ${expected}\n      actual:   ${actual}\n`);
}
const newPassword = () => `TestPass${crypto.randomBytes(5).toString('hex')}9`;
async function newUser(label) {
  const email = `st-omar-${label}-${Date.now()}@example.com`;
  const password = newPassword();
  const reg = await call('POST', '/api/auth/register', { body: { name: `Omar Test ${label}`, email, password } });
  return { email, password, reg, token: reg.data && reg.data.token, id: reg.data && reg.data.user && reg.data.user.id };
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

console.log(`Auth + Insights tests against ${API}\n`);

// ---------- IT-01 account: register, log in, profile, change currency ----------
const u = await newUser('it01');
{
  const login = await call('POST', '/api/auth/login', { body: { email: u.email, password: u.password } });
  const me = await call('GET', '/api/auth/me', { token: login.data.token });
  const patch = await call('PATCH', '/api/auth/me', { token: login.data.token, body: { baseCurrency: 'USD' } });
  const claims = patch.data && patch.data.token ? JSON.parse(Buffer.from(patch.data.token.split('.')[1], 'base64url')) : {};
  const actual = `register ${u.reg.status}; login ${login.status}; me ${me.status} role=${me.data.role} email matches=${me.data.email === u.email}; ` +
    `patch ${patch.status} baseCurrency=${patch.data.user && patch.data.user.baseCurrency}, new token cur=${claims.cur}; hash returned=${JSON.stringify(me.data).includes('passwordHash')}`;
  const pass = u.reg.status === 201 && login.status === 200 && me.status === 200 && me.data.role === 'user' && me.data.email === u.email &&
    patch.status === 200 && claims.cur === 'USD' && !JSON.stringify(me.data).includes('passwordHash');
  record('IT-01', 'End-to-end: account', 'Register, log in, read own profile, change base currency (new token issued)',
    '201; 200; 200 role user, no password hash; 200 and token claim cur=USD', actual, pass);
  await call('PATCH', '/api/auth/me', { token: patch.data.token, body: { baseCurrency: 'EGP' } });
  u.token = (await call('POST', '/api/auth/login', { body: { email: u.email, password: u.password } })).data.token;
}

// ---------- ST-03 expired token ----------
{
  // A REAL expired token: signed with the deployed key (read into memory, never printed), exp 1 hour ago.
  const secret = sh('aws secretsmanager get-secret-value --secret-id pb/jwt-secret --query SecretString --output text');
  const claims = JSON.parse(Buffer.from(u.token.split('.')[1], 'base64url'));
  const expired = jwt.sign({ sub: claims.sub, role: claims.role, cur: claims.cur, name: claims.name }, secret,
    { expiresInSec: -3600, issuer: ISSUER, audience: AUDIENCE });
  // The same token with exp edited by hand (signature no longer matches)
  const [h, p, s] = u.token.split('.');
  const edited = `${h}.${Buffer.from(JSON.stringify({ ...claims, exp: claims.exp + 86400 * 365 })).toString('base64url')}.${s}`;
  const a = await call('GET', '/api/auth/me', { token: expired });
  const b = await call('GET', '/api/buckets', { token: expired });
  const c = await call('GET', '/api/insights/dashboard', { token: expired });
  const d = await call('GET', '/api/auth/me', { token: edited });
  const actual = `auth ${a.status} "${a.data.error && a.data.error.message}"; buckets ${b.status}; insights ${c.status}; exp extended by hand ${d.status}`;
  const pass = a.status === 401 && /expired/i.test(a.data.error.message) && b.status === 401 && c.status === 401 && d.status === 401;
  record('ST-03', 'Authentication', 'Correctly signed token that expired 1 hour ago, on three services; token with exp extended by hand',
    '401 "Session expired" on auth, buckets, insights; 401', actual, pass);
}

// ---------- ST-04 normal user on admin endpoints (+ burst for the AccessDenied alarm) ----------
{
  const users = await call('GET', '/api/auth/users', { token: u.token });
  const status = await call('PATCH', `/api/auth/users/${u.id}/status`, { token: u.token, body: { status: 'disabled' } });
  const overview = await call('GET', '/api/insights/admin/overview', { token: u.token });
  const tpl = await call('POST', '/api/buckets/templates', { token: u.token, body: { name: 'Hack', suggestedLimit: 1 } });
  const burst = [];
  for (let i = 0; i < 12; i += 1) burst.push((await call('GET', '/api/auth/users', { token: u.token })).status);
  const actual = `list users ${code(users)}; change status ${code(status)}; admin overview ${code(overview)}; add template ${code(tpl)}; burst of 12: ${burst.join(' ')}`;
  const pass = [users, status, overview, tpl].every((r) => r.status === 403) && burst.every((s) => s === 403);
  record('ST-04', 'Authorization (roles)', 'Normal user calls 4 admin endpoints on 3 services, then 12 more times (feeds the 403 alarm)',
    '403 on all; 12 x 403', actual, pass);
}

// ---------- ST-09 self-registration as admin ----------
{
  const email = `st-omar-eve-${Date.now()}@example.com`;
  const r = await call('POST', '/api/auth/register', { body: { name: 'Eve', email, password: newPassword(), role: 'admin' } });
  // If the first request had created an account, the same e-mail would now be taken (409).
  const again = await call('POST', '/api/auth/register', { body: { name: 'Eve', email, password: newPassword() } });
  const actual = `register ${code(r)} "${r.data.error && r.data.error.message}"; same e-mail without role: ${again.status} role=${again.data.user && again.data.user.role} (so no account had been created)`;
  const pass = r.status === 400 && /role is not an allowed field/.test(r.data.error.message) && again.status === 201 && again.data.user.role === 'user';
  record('ST-09', 'Mass assignment / privilege escalation', 'Register with "role": "admin" in the body',
    '400 "role is not an allowed field"; then 201 with role user (nothing was created by the first request)', actual, pass);
}

// ---------- ST-10 lockout after 5 wrong passwords ----------
{
  const v = await newUser('st10');
  const statuses = [];
  for (let i = 0; i < 5; i += 1) statuses.push((await call('POST', '/api/auth/login', { body: { email: v.email, password: 'wrong-pass-1' } })).status);
  const locked = await call('POST', '/api/auth/login', { body: { email: v.email, password: 'wrong-pass-1' } });
  const right = await call('POST', '/api/auth/login', { body: { email: v.email, password: v.password } });
  const unknown = await call('POST', '/api/auth/login', { body: { email: `nobody-${Date.now()}@example.com`, password: 'wrong-pass-1' } });
  const sameMsg = unknown.data.error.message === 'E-mail or password is incorrect.';
  const actual = `5 wrong: ${statuses.join(' ')}; 6th ${code(locked)}; correct password while locked ${code(right)}; unknown e-mail ${unknown.status} same message=${sameMsg}`;
  const pass = statuses.every((s) => s === 401) && locked.status === 429 && right.status === 429 && unknown.status === 401 && sameMsg;
  record('ST-10', 'Brute force', '5 wrong passwords, a 6th, then the correct password; unknown e-mail for comparison',
    '401 x5; 429 ACCOUNT_LOCKED; 429 (locked for 15 min); 401 with the same message', actual, pass);
}

// ---------- ST-15 disabled account blocked even with a valid token ----------
{
  // Seed a test admin straight into the Floci users table (the only way to create an admin).
  const admin = { email: `st-omar-admin-${Date.now()}@example.com`, password: newPassword() };
  sh('node services/auth-service/scripts/seed-admin.js', {
    ...AWS_ENV, USERS_TABLE: 'PBUsers', AWS_REGION: 'us-east-1', AWS_ENDPOINT_URL: 'http://localhost:4566',
    ADMIN_EMAIL: admin.email, ADMIN_PASSWORD: admin.password
  });
  // Admins must set up two-step login (5a) before they get a token.
  const first = await call('POST', '/api/auth/login', { body: admin });
  const setup = await call('POST', '/api/auth/mfa/setup', { token: first.data.mfaToken });
  const enable = await call('POST', '/api/auth/mfa/enable', { token: first.data.mfaToken, body: { code: totp.codeAt(setup.data.secret) } });
  const adminToken = enable.data.token;

  const w = await newUser('st15');
  const before = await call('GET', '/api/buckets', { token: w.token });
  const disable = await call('PATCH', `/api/auth/users/${w.id}/status`, { token: adminToken, body: { status: 'disabled' } });
  const meNow = await call('GET', '/api/auth/me', { token: w.token });
  const loginNow = await call('POST', '/api/auth/login', { body: { email: w.email, password: w.password } });
  console.log('      (ST-15: waiting 61 s, the longest time another service may reuse an account check)');
  await sleep(61000);
  const bucketsLater = await call('GET', '/api/buckets', { token: w.token });
  const dashLater = await call('GET', '/api/insights/dashboard', { token: w.token });
  const enableBack = await call('PATCH', `/api/auth/users/${w.id}/status`, { token: adminToken, body: { status: 'active' } });
  const after = await call('GET', '/api/auth/me', { token: w.token });
  const actual = `admin setup forced=${first.data.mfaSetupRequired === true}, admin token ${enable.status}; before ${before.status}; disable ${disable.status}; ` +
    `same token: auth/me ${code(meNow)}, login ${code(loginNow)}, after 61 s buckets ${code(bucketsLater)}, insights ${code(dashLater)}; re-enabled ${enableBack.status} -> ${after.status}`;
  const pass = enable.status === 200 && before.status === 200 && disable.status === 200 && meNow.status === 403 && loginNow.status === 403 &&
    bucketsLater.status === 403 && dashLater.status === 403 && after.status === 200;
  record('ST-15', 'Account status', 'Admin disables a user whose token is still valid; the user keeps calling three services; admin re-enables',
    '200 before; 403 on auth at once and on login; 403 on buckets and insights within 60 s; 200 after re-enabling', actual, pass);
}

// ---------- IT-10 dashboard across services ----------
{
  const bucket = await call('POST', '/api/buckets', { token: u.token, body: { name: 'Food', monthlyLimit: 1000 } });
  const bucketId = bucket.data && (bucket.data.id || (bucket.data.bucket && bucket.data.bucket.id));
  const today = new Date().toISOString().slice(0, 10);
  const exp = await call('POST', '/api/transactions', { token: u.token, body: { type: 'expense', amount: 900, date: today, bucketId, paymentMethod: 'cash', note: 'groceries IT-10' } });
  const inc = await call('POST', '/api/transactions', { token: u.token, body: { type: 'income', amount: 5000, date: today, paymentMethod: 'bank_transfer', note: 'salary IT-10' } });
  const d = await call('GET', '/api/insights/dashboard', { token: u.token });
  const row = d.data.buckets && d.data.buckets.find((b) => b.id === bucketId);
  const actual = `bucket ${bucket.status}, expense ${exp.status}, income ${inc.status}; dashboard ${d.status}: income=${d.data.income} expense=${d.data.expense} net=${d.data.net} ` +
    `savingsRate=${d.data.savingsRate}%; Food ${row && row.percentUsed}% ${row && row.state}; nearLimit=${d.data.budgetHealth && d.data.budgetHealth.nearLimit}`;
  const pass = d.status === 200 && d.data.income === 5000 && d.data.expense === 900 && d.data.net === 4100 && row && row.percentUsed === 90 && row.state === 'NEAR_LIMIT';
  record('IT-10', 'End-to-end: dashboard', 'Bucket 1,000 EGP; expense 900 and income 5,000; Insights builds the dashboard from Transactions + Buckets',
    '200; income 5000, expense 900, net 4100; Food 90% NEAR_LIMIT', actual, pass);
}

// ---------- IT-12 CSV report through S3 ----------
{
  const day = new Date().toISOString().slice(0, 10);
  const make = await call('POST', '/api/insights/reports', { token: u.token, body: { type: 'transactions', from: `${day.slice(0, 8)}01`, to: day } });
  const id = make.data.id;
  const list = await call('GET', '/api/insights/reports', { token: u.token });
  const dl = await call('GET', `/api/insights/reports/${id}/download`, { token: u.token });
  let file = { status: 0, text: '' };
  if (dl.data.downloadUrl) {
    const r = await fetch(dl.data.downloadUrl);
    file = { status: r.status, text: await r.text() };
  }
  const other = await newUser('it12');
  const stranger = await call('GET', `/api/insights/reports/${id}/download`, { token: other.token });
  const del = await call('DELETE', `/api/insights/reports/${id}`, { token: u.token });
  const gone = await call('GET', `/api/insights/reports/${id}/download`, { token: u.token });
  const actual = `generate ${make.status} rows=${make.data.rows}; list ${list.status} count=${list.data.count}; download link ${dl.status} expires in ${dl.data.expiresIn}s; ` +
    `S3 file ${file.status} has the expense=${file.text.includes('groceries IT-10')}; other user ${code(stranger)}; delete ${del.status}; after delete ${code(gone)}`;
  const pass = make.status === 201 && make.data.rows >= 2 && dl.status === 200 && dl.data.expiresIn === 300 && file.status === 200 &&
    file.text.includes('groceries IT-10') && stranger.status === 404 && del.status === 204 && gone.status === 404;
  record('IT-12', 'End-to-end: reports', 'Generate a CSV report, list it, download it through a 5-minute S3 link, another user tries it, delete it',
    '201; 200; 200 link (300 s); S3 200 with the expense; 404; 204; 404', actual, pass);
}

// ---------- summary + evidence file ----------
const passed = results.filter((r) => r.pass).length;
console.log(`${passed} of ${results.length} tests passed`);
mkdirSync('evidence', { recursive: true });
const md = [
  '# Security and end-to-end tests: Auth and Insights services (Omar), run on Floci',
  '',
  `Run: ${new Date().toISOString()} against ${API}. Script: tests/security/auth-security.mjs`,
  '',
  '| Test ID | Category | Scenario | Expected | Actual | Pass/Fail |',
  '|---|---|---|---|---|---|',
  ...results.map((r) => `| ${r.id} | ${r.category} | ${r.scenario} | ${r.expected} | ${r.actual} | ${r.pass ? 'Pass' : 'Fail'} |`),
  '',
  `${passed} of ${results.length} passed.`
].join('\n');
writeFileSync('evidence/security-omar.md', `${md}\n`);
console.log('Results saved to evidence/security-omar.md');
process.exit(passed === results.length ? 0 : 1);
