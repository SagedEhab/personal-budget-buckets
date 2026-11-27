// Log and monitoring evidence for report §11 (Auth service, Omar), collected from Floci.
//   1. triggers the two security alarms: 6 wrong logins (lockout) and a burst of 12 forbidden calls
//   2. waits until pb-failed-logins-spike and pb-access-denied-spike are in ALARM (up to 6 minutes)
//   3. saves the metric filters, alarm states, metric sums, sample log lines, and a check that the
//      logs contain no token or password, to evidence/monitoring-omar.md
// No token or password is printed or saved: the test user's password is random and kept in memory.
// Run (Floci running, app deployed):  node tests/security/auth-monitoring.mjs
import { execSync } from 'node:child_process';
import { writeFileSync, mkdirSync } from 'node:fs';
import crypto from 'node:crypto';

const ENV = { ...process.env, AWS_PROFILE: process.env.AWS_PROFILE || 'floci', AWS_PAGER: '', MSYS_NO_PATHCONV: '1' };
const sh = (cmd) => { try { return execSync(cmd, { encoding: 'utf8', env: ENV, stdio: ['ignore', 'pipe', 'pipe'] }).trim(); } catch (e) { return (e.stdout || '').trim(); } };
const API = process.env.API || `http://${sh("aws apigatewayv2 get-apis --query \"Items[?Name=='pb-http-api'].ApiId | [0]\" --output text")}.execute-api.localhost.floci.io:4566`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function call(method, path, { token, body } = {}) {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body) headers['Content-Type'] = 'application/json';
  const r = await fetch(API + path, { method, headers, body: body && JSON.stringify(body), signal: AbortSignal.timeout(90000) });
  return { status: r.status, data: await r.json().catch(() => null) };
}

const started = Date.now();
console.log(`Monitoring evidence against ${API}\n`);

// ---------- 1. trigger ----------
const email = `mon-omar-${Date.now()}@example.com`;
const password = `TestPass${crypto.randomBytes(5).toString('hex')}9`;
const reg = await call('POST', '/api/auth/register', { body: { name: 'Monitoring Test', email, password } });
const token = reg.data.token;
const logins = [];
for (let i = 0; i < 6; i += 1) logins.push((await call('POST', '/api/auth/login', { body: { email, password: 'wrong-pass-1' } })).status);
const denied = [];
for (let i = 0; i < 12; i += 1) denied.push((await call('GET', '/api/auth/users', { token })).status);
const triggered = new Date().toISOString();
console.log(`6 wrong logins: ${logins.join(' ')}\n12 admin calls as a normal user: ${denied.join(' ')}\n`);

// ---------- 2. wait for the alarms ----------
const ALARMS = ['pb-failed-logins-spike', 'pb-access-denied-spike'];
const alarmState = () => JSON.parse(sh(`aws cloudwatch describe-alarms --alarm-names ${ALARMS.join(' ')} --query "MetricAlarms[].{name:AlarmName,metric:MetricName,stat:Statistic,period:Period,threshold:Threshold,op:ComparisonOperator,state:StateValue,reason:StateReason,since:StateUpdatedTimestamp,actions:AlarmActions}" --output json`) || '[]');
let alarms = alarmState();
for (let waited = 0; waited < 360 && !alarms.every((a) => a.state === 'ALARM'); waited += 15) {
  console.log(`  waiting for alarms (${waited} s): ${alarms.map((a) => `${a.name}=${a.state}`).join(', ')}`);
  await sleep(15000);
  alarms = alarmState();
}
console.log(`Alarms: ${alarms.map((a) => `${a.name}=${a.state}`).join(', ')}\n`);

// ---------- 3. collect ----------
const filters = sh('aws logs describe-metric-filters --log-group-name /aws/lambda/pb-auth-api --query "metricFilters[].[filterName,filterPattern,metricTransformations[0].metricNamespace,metricTransformations[0].metricName]" --output text');
const startIso = new Date(started - 60000).toISOString();
const endIso = new Date(Date.now() + 60000).toISOString();
const sums = ['FailedLogins', 'AccessDenied'].map((m) => `${m}: ${sh(`aws cloudwatch get-metric-statistics --namespace PersonalBudget --metric-name ${m} --start-time ${startIso} --end-time ${endIso} --period 300 --statistics Sum --query "Datapoints[].Sum" --output text`) || 'no datapoints'}`);
const since = started - 60000;
const events = (pattern) => sh(`aws logs filter-log-events --log-group-name /aws/lambda/pb-auth-api --start-time ${since} --filter-pattern "${pattern}" --query "events[].message" --output json`);
const parse = (json) => { try { return JSON.parse(json || '[]').map((m) => m.trim()).filter((m) => m.startsWith('{')); } catch { return []; } };
const failed = parse(events('LOGIN_FAILED'));
const locked = parse(events('ACCOUNT_LOCKED'));
const denials = parse(events('ACCESS_DENIED'));
const allLogs = sh('aws logs tail /aws/lambda/pb-auth-api --since 30m');
const leaks = [];
if (/eyJ[A-Za-z0-9_-]{10,}\.eyJ/.test(allLogs)) leaks.push('a JWT');
if (/Bearer\s+\S/.test(allLogs)) leaks.push('an Authorization header');
if (allLogs.includes(password) || allLogs.includes('wrong-pass-1')) leaks.push('a password');
if (/"password"\s*:/.test(allLogs)) leaks.push('a password field');

const pick = (list, n) => list.slice(0, n).map((l) => `    ${l}`).join('\n') || '    (none found)';
const md = [
  '# Log and monitoring evidence: Auth service (Omar), Floci',
  '',
  `Run: ${new Date(started).toISOString()} against ${API}. Script: tests/security/auth-monitoring.mjs`,
  '',
  '## 1. What was done',
  `- 6 wrong logins for one test account: ${logins.join(' ')} (5 x 401, then 429 locked)`,
  `- 12 calls to the admin route GET /api/auth/users as a normal user: ${denied.join(' ')}`,
  `- finished at ${triggered}`,
  '',
  '## 2. Metric filters on /aws/lambda/pb-auth-api (structured JSON logs -> CloudWatch metrics)',
  '```', filters, '```',
  '',
  '## 3. Alarms',
  '| Alarm | Metric | Rule | State | Since | Reason |',
  '|---|---|---|---|---|---|',
  ...alarms.map((a) => `| ${a.name} | PersonalBudget/${a.metric} | ${a.stat} ${a.op.replace('GreaterThanOrEqualToThreshold', '>=')} ${a.threshold} in ${a.period} s | **${a.state}** | ${a.since} | ${String(a.reason).replace(/\|/g, '/')} |`),
  '',
  `Alarm actions (SNS): ${[...new Set(alarms.flatMap((a) => a.actions || []))].join(', ') || 'none'}`,
  '',
  '## 4. Metric sums in this run (5-minute periods)',
  ...sums.map((s) => `- ${s}`),
  '',
  `## 5. Sample log lines (CloudWatch Logs, /aws/lambda/pb-auth-api): ${failed.length} LOGIN_FAILED, ${locked.length} ACCOUNT_LOCKED, ${denials.length} ACCESS_DENIED`,
  '```', pick(failed, 2), pick(locked, 1), pick(denials, 2), '```',
  'Each line is JSON with a requestId (followed across services), the event name, the user id and the IP. No e-mail, password or token is written.',
  '',
  '## 6. Leak check of the last 30 minutes of Auth logs',
  leaks.length ? `FOUND: ${leaks.join(', ')}` : `Nothing found: no JWT, Authorization header, password or password field in ${allLogs.split('\n').length} log lines.`,
  ''
].join('\n');
mkdirSync('evidence', { recursive: true });
writeFileSync('evidence/monitoring-omar.md', md);
console.log(md);
const ok = alarms.length === 2 && alarms.every((a) => a.state === 'ALARM') && failed.length && denials.length && !leaks.length;
console.log(ok ? 'Evidence complete. Saved to evidence/monitoring-omar.md' : 'Evidence INCOMPLETE (see above). Saved to evidence/monitoring-omar.md');
process.exit(ok ? 0 : 1);
