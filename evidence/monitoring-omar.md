# Log and monitoring evidence: Auth service (Omar), Floci

Run: 2026-11-27T18:42:04.696Z against http://31284765bb.execute-api.localhost.floci.io:4566. Script: tests/security/auth-monitoring.mjs

## 1. What was done
- 6 wrong logins for one test account: 401 401 401 401 401 429 (5 x 401, then 429 locked)
- 12 calls to the admin route GET /api/auth/users as a normal user: 403 403 403 403 403 403 403 403 403 403 403 403
- finished at 2026-11-27T18:42:10.312Z

## 2. Metric filters on /aws/lambda/pb-auth-api (structured JSON logs -> CloudWatch metrics)
```
pb-auth-403	{ $.status = 403 }	PersonalBudget	AccessDenied
pb-auth-5xx	{ $.status >= 500 }	PersonalBudget	ServerErrors
pb-failed-logins	{ ($.event = "LOGIN_FAILED") || ($.event = "ACCOUNT_LOCKED") }	PersonalBudget	FailedLogins
```

## 3. Alarms
| Alarm | Metric | Rule | State | Since | Reason |
|---|---|---|---|---|---|
| pb-access-denied-spike | PersonalBudget/AccessDenied | Sum >= 10 in 300 s | **ALARM** | 2026-11-27T20:45:05+02:00 | Threshold Crossed: 1 datapoint(s) breaching the threshold. |
| pb-failed-logins-spike | PersonalBudget/FailedLogins | Sum >= 5 in 300 s | **ALARM** | 2026-11-27T20:45:05+02:00 | Threshold Crossed: 1 datapoint(s) breaching the threshold. |

Alarm actions (SNS): arn:aws:sns:us-east-1:000000000000:pb-ops-alarms

## 4. Metric sums in this run (5-minute periods)
- FailedLogins: 5.0
- AccessDenied: 12.0

## 5. Sample log lines (CloudWatch Logs, /aws/lambda/pb-auth-api): 4 LOGIN_FAILED, 1 ACCOUNT_LOCKED, 12 ACCESS_DENIED
```
    {"ts":"2026-11-27T18:42:09.738Z","level":"warn","service":"auth","event":"LOGIN_FAILED","requestId":"3bed2fb2-e9ed-4bcc-9909-2e09bc1da3fa","userId":"f160b60f-0ec3-4ba1-b34f-2371d2d85cdc","attempt":1,"ip":"127.0.0.1"}
    {"ts":"2026-11-27T18:42:09.856Z","level":"warn","service":"auth","event":"LOGIN_FAILED","requestId":"f4bd30ba-47b2-4aa8-a621-067bfad7b7d6","userId":"f160b60f-0ec3-4ba1-b34f-2371d2d85cdc","attempt":2,"ip":"127.0.0.1"}
    {"ts":"2026-11-27T18:42:10.067Z","level":"warn","service":"auth","event":"ACCOUNT_LOCKED","requestId":"fae5b99d-4c68-42cb-9686-ccebfa593504","userId":"f160b60f-0ec3-4ba1-b34f-2371d2d85cdc","attempt":5,"ip":"127.0.0.1"}
    {"ts":"2026-11-27T18:42:10.107Z","level":"warn","service":"auth","event":"ACCESS_DENIED","requestId":"143abe11-2690-4a28-aeee-25cbf2f6658d","userId":"f160b60f-0ec3-4ba1-b34f-2371d2d85cdc","role":"user","requiredRole":"admin","method":"GET","path":"/users"}
    {"ts":"2026-11-27T18:42:10.127Z","level":"warn","service":"auth","event":"ACCESS_DENIED","requestId":"ea458473-2806-4d87-821f-5e6b235426c4","userId":"f160b60f-0ec3-4ba1-b34f-2371d2d85cdc","role":"user","requiredRole":"admin","method":"GET","path":"/users"}
```
Each line is JSON with a requestId (followed across services), the event name, the user id and the IP. No e-mail, password or token is written.

## 6. Leak check of the last 30 minutes of Auth logs
Nothing found: no JWT, Authorization header, password or password field in 43 log lines.
