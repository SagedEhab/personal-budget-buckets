# Enhancements: scaling to 1 million users

The course asked us to design the app as if **1 million users** will use it. The current design
already scales (serverless: API Gateway, Lambda, DynamoDB on-demand). The items below make that
story stronger. Each item has a reason, an owner suggestion and the work involved, so we can divide
them. Pick one, write your name next to it, and do it on your own branch.

**Sizing we design for:** 1,000,000 users with about 10% active per day is 100,000 daily users. At
about 20 requests each, that is 2 million requests a day: on average about 25 requests per second,
with peaks of about 250 per second.

---

## 1. Three databases, each with one clear job

Using three databases is only impressive if each one does what it is best at. That pattern is called
**polyglot persistence**.

| Database | Type | Job in our app |
|---|---|---|
| DynamoDB (have it) | NoSQL key-value | Main user data: buckets, transactions, reports |
| Neon Postgres (new) | Relational SQL | Security audit log and admin analytics |
| Redis / ElastiCache (new) | In-memory cache | Shared caching and rate limiting |

### 1a. Keep DynamoDB as the main database (no work, report only)
**Why it is a good option:**
- This is what large AWS apps use for high-volume data. Reads and writes stay fast however big the
  table gets.
- On-demand mode needs no capacity planning, and Global Tables can copy the data to several regions.
- Replacing it would weaken the scaling story, so we justify it instead.

**Report:** §3 data model, §6 deployment, §14 cost.

### 1b. Neon Postgres for the audit log and admin analytics
**Suggested owner:** Omar (Auth service and admin pages)

**Why it is a good option:**
- **The instructor recommended it:** "adding an external database service such as Neon or Supabase
  with Floci is recommended".
- An audit log needs SQL questions that DynamoDB is bad at, for example "failed logins per day",
  "most-blocked users" or "all admin actions last week".
- It also settles our open question about an admin security-log page.
- Neon is serverless Postgres: it scales to zero when idle, which matches Lambda.

**Work (about 2–3 hours):**
1. Create a free Neon project (Frankfurt region).
2. Store the connection string in **Secrets Manager** as `pb/neon-url`, never in the code.
3. Create the table `audit_events` (who, what, when, IP, result).
4. Make the Auth service write an event on login, lockout, admin action and 403. If Neon is down, the
   app keeps working.
5. Build an admin "Security log" page with filters and two SQL charts.
6. Add the IAM permission for `pb/neon-url` only, and write tests.

**Report:** §2 diagram, §3 data model, §5 external integration, §8 secrets, §16 (it depends on the
internet).

### 1c. Redis (ElastiCache) for shared caching and rate limiting
**Suggested owner:** Salma for the exchange-rate cache (Transactions owns currency conversion), and
Saged for the shared client in `pb-common` and the infra.

**Why it is a good option:**
- **It runs on Floci:** no account and no internet needed.
- **It fixes a real problem at scale.** Each Lambda copy keeps its own memory, so with thousands of
  copies, each one calls the exchange-rate API and keeps its own login-attempt counter. Redis gives
  every copy one shared cache and one shared counter.
- **It is the textbook high-scale pattern:** API Gateway → Lambda → cache → database.

**Work (about 2–3 hours):**
1. Create the Redis cluster in the deploy script.
2. Add a Redis client in `pb-common`, with a fallback so the app still works if Redis is down.
3. Cache exchange rates for 1 hour (Salma).
4. Cache dashboard results for 30–60 seconds (Omar, optional).
5. Move the per-user rate limit and the lockout counters to Redis (Saged).
6. Write tests.

**Report:** §2 diagram, §6, §14 cost and load.

---

## 2. Front door: CDN, firewall and global routing

### 2a. CloudFront CDN in front of the website
**Suggested owner:** Saged (infra)

**Why it is a good option:**
- The website files are served from locations near each user instead of from one S3 bucket. Pages
  load faster worldwide.
- S3 gets fewer requests, which keeps the cost down.
- It is the standard front door for a site with millions of users.

**Work:** about 1 hour (deploy script, diagram). It exists on Floci.

### 2b. AWS WAF (web application firewall)
**Suggested owner:** Saged (infra)

**Why it is a good option:**
- It adds a rate limit per IP address. Our current API Gateway throttling is per stage, not per user.
- It blocks common attacks (SQL injection and XSS patterns, known bad bots) before they reach Lambda.
- It closes the "No WAF" row in our §16 limitations.

**Work:** about 1 hour. It exists on Floci; check that rules attach.

### 2c. Route 53 latency routing to two regions (report only)
**Why it is a good option:**
- Users reach the nearest region.
- If a whole AWS region goes down, traffic moves to the other one. With DynamoDB Global Tables the
  data is already there.

**Work:** describe it in the report. Building it needs real multi-region AWS.

---

## 3. Background work and the "multiple servers" question

### 3a. SQS queues for budget alerts and CSV reports
**Suggested owners:** Saged (alerts, Buckets) and Omar (CSV reports, Insights)

**Why it is a good option:**
- Heavy or slow work leaves the user's request: the request finishes at once and a worker does the
  rest.
- Traffic spikes wait in the queue instead of overloading the services.
- If a worker fails, the message is retried and nothing is lost; a dead-letter queue keeps failed
  messages.

**Work:** about 2 hours each (queue, worker Lambda, deploy script, tests). It exists on Floci.

### 3b. Lambda concurrency settings (report and small config)
**Why it is a good option:**
- Lambda already runs thousands of copies in parallel. Those are our "multiple servers", and
  API Gateway acts as the load balancer.
- **Reserved concurrency** stops one service from using all the capacity.
- **Provisioned concurrency** removes cold starts, which we measured at over 30 s on Floci.

**Work:** about 30 minutes, plus the report.

### 3c. Alternative: load balancer and containers (report only, as a comparison)
**Why it is a good option to describe:**
- It answers "load balancers and multiple servers" directly: an **Application Load Balancer** in
  front of **ECS Fargate** containers, with auto scaling across Availability Zones.
- Explaining why we chose serverless instead (no idle servers, no patching, cheaper at our load)
  shows we compared the trade-offs.

**Work:** one paragraph and a small table in §6 and §14.

---

## 4. Seeing it work at scale

### 4a. CloudWatch dashboard and X-Ray tracing
**Suggested owner:** Omar (monitoring screenshots)

**Why it is a good option:**
- One dashboard shows requests, errors, latency and Lambda concurrency per service.
- X-Ray traces show where the time goes when one request crosses three services.

**Work:** about 1 hour.

### 4b. Raise the throttle to match the sizing
**Suggested owner:** Saged (infra)

**Why it is a good option:**
- Today's limit of 10 requests per second (burst 20) is a safe demo value.
- For 1 million users we need about 1,000 per second with a burst of 2,000, matched to the WAF
  limit per IP.

**Work:** 10 minutes, plus a sentence in the report.

### 4c. Load test (optional)
**Why it is a good option:**
- It gives real numbers (requests per second, errors, latency) instead of claims.
- A short test with a tool like k6 or autocannon against Floci is enough for coursework.

**Work:** about 1 hour, with the results in §13 and §14.

---

## 5. Security additions

What we **already have**:
- **Login and roles:**
  - JWT signed with a key in Secrets Manager; scrypt passwords; lockout after 5 failures;
  - user/admin roles checked in the backend; disabled accounts blocked even with a valid token.
- **Data protection:** ownership checks, strict input validation, CSP and safe rendering, CSV injection
  protection, CORS, security headers (HSTS, nosniff, X-Frame-Options).
- **AWS side:**
  - one least-privilege IAM role per Lambda;
  - private, encrypted S3 buckets with 5-minute links;
  - throttling, plus CloudWatch metrics and alarms.
- **Pipeline:** CI with tests, `npm audit` and gitleaks.

### 5a. Multi-factor authentication (authenticator-app codes)
**Suggested owner:** Omar (Auth)

**Why it is a good option:**
- Passwords alone fail against phishing and reused passwords, which is threat T1 in our model.
- A 6-digit code from an authenticator app (Google Authenticator, Microsoft Authenticator) stops an
  attacker who has the password.
- Real systems require it for admins, so we make it **mandatory for the admin role** and optional for
  users.
- It closes the "No MFA" row in §16 and is a strong moment in the demo video.

**Work:** about 3 hours:
1. Generate a TOTP secret and show it as a QR code.
2. Store the secret encrypted.
3. Ask for the code at login.
4. Provide one-time recovery codes.
5. Write tests.

### 5b. Short access tokens, refresh tokens and real logout
**Suggested owner:** Omar (Auth); the list of revoked tokens can live in Redis (item 1c) or DynamoDB

**Why it is a good option:**
- Today a stolen token keeps working until it expires.
- With **15-minute access tokens** and a **refresh token that can be revoked**, a stolen token is only
  useful for minutes.
- "Log out" and "log out everywhere" actually end the session, because revoked tokens are refused.

**Work:** about 2–3 hours (refresh endpoint, revocation list, frontend refresh, tests).

### 5c. Breached-password check (Have I Been Pwned)
**Suggested owner:** Omar (Auth)

**Why it is a good option:**
- At registration and password change, we reject passwords that appear in known data breaches.
  Attackers try those first.
- It uses the k-anonymity API: only the first 5 characters of the password's SHA-1 hash leave the
  server, never the password itself.
- It is a **second external API that does a real security job**, which the brief values.

**Work:** about 1 hour, plus a test. If the API is down, registration still works, and the skipped
check is logged.

### 5e. Safe receipt uploads
**Suggested owner:** Salma (Transactions, receipts)

The backend already has receipt upload and download links (`POST/GET /api/transactions/:id/receipt`,
pre-signed S3 URLs), but **the page has no upload field yet**. This item adds the field and makes it
safe.

**Why it is a good option:**
- File uploads are a classic attack route: huge files, or a program disguised as an image.
- **Size cap:** a pre-signed POST with a content-length-range (for example, at most 5 MB) is enforced
  by S3 itself.
- **Type check:** the file's real type is checked from its first bytes, so only JPEG, PNG or PDF are
  accepted.
- It closes the "cannot cap file size" row in §16, and receipts become a visible feature in the demo.

**Work:** about 2–3 hours:
1. Add the upload field and a "view receipt" link on the Transactions page.
2. Switch to a pre-signed POST with a size limit.
3. Check the file type.
4. Write tests.

### 5f. Privacy rights: download my data and delete my account (Egypt PDPL)
**Suggested owners:** each member for their own service (Saged: Buckets, Salma: Transactions and
receipts, Omar: Auth and Insights)

**Why it is a good option:**
- Egypt's Personal Data Protection Law (151/2020) gives users the right to access and erase their
  data.
- **"Download my data"** returns everything we hold as JSON/CSV.
- **"Delete my account"** removes the user's records in all four services and their files in S3.
- It turns the compliance paragraph in §8 into working features, and every member gets a piece of it.

**Work:** about 2 hours in total:
1. Each service adds export and delete endpoints for its own data.
2. Auth runs the whole flow (it asks every service, then deletes the account last).
3. Add two buttons on a profile page.
4. Write tests.

### 5h. Audit trail and threat detection (CloudTrail, GuardDuty, Security Hub, Config)
**Suggested owner:** Saged (infra); screenshots in §11 by Omar

**Why it is a good option:**
- **CloudTrail** records every change to the AWS setup: who changed a policy, deleted a table or read
  a secret. Today no trail is configured.
- **GuardDuty** flags suspicious activity in the account, such as stolen keys used from an unusual
  place.
- **Config rules** check settings continuously ("all buckets block public access", "all tables are
  encrypted").
- **Security Hub** gathers it all on one score page.
- This is the "cloud security posture" part of the module, and all four exist on Floci.

**Work:** about 2 hours: enable them in the deploy script, then screenshot them. Check which ones
Floci actually evaluates, and record the answer in §16.

### 5j. Backups and recovery (DynamoDB point-in-time recovery, AWS Backup)
**Suggested owner:** Saged (infra)

**Why it is a good option:**
- Report §15 asks how we recover after accidental deletion, misconfiguration or a compromise.
- **Point-in-time recovery** restores a table to any second in the last 35 days. S3 versioning
  (already on) covers the files.
- A daily **AWS Backup** plan keeps copies that even an attacker with app access cannot delete.
- A restore drill (delete a record, restore the table, screenshot) turns §15 from a promise into
  evidence.

**Work:** about 1 hour, plus the restore drill.

### 5k. Our own encryption key (AWS KMS customer-managed key)
**Owner:** Saged (infra) · **Done 26 Nov**, `infra/security/setup-kms.sh`

**Why it is a good option:**
- Before, AWS-owned keys encrypted our data. Now one key **we** own, `alias/pb-data-key`, encrypts the
  4 tables, the receipts and reports buckets, the JWT secret, both SNS topics and the Lambda logs.
- The key rotates itself every year; every use is a CloudTrail event; switching it off makes all data
  unreadable at once (an incident "kill switch").
- Two locks: the key policy and IAM. The Lambdas may only use the key *through* DynamoDB, S3, Secrets
  Manager and SNS (`kms:ViaService`), never to decrypt data directly.

### 5l. JWT signing-key rotation
**Owner:** Saged (infra + shared auth code) · **Done 26 Nov**, `infra/security/setup-rotation.sh`

**Why it is a good option:**
- Anyone with the signing key can make a valid token for any user, even an admin. Changing it every
  30 days limits how long a leaked key is useful.
- A rotation Lambda makes the new key; the services sign with the new key and still accept the previous
  one, so **nobody is logged out**. Test ST-19 and a live drill on Floci.

### 5m. Tamper-proof audit logs (S3 Object Lock)
**Owner:** Saged (infra) · **Done 26 Nov**, in `infra/security/setup-audit.sh`

**Why it is a good option:**
- The first thing an attacker does is delete the logs. With Object Lock, a log file cannot be deleted
  or changed before its retention date, even by an admin (COMPLIANCE, 365 days on AWS).
- Floci enforces it: deleting a locked log file returned **AccessDenied**.

### 5n. Security alerts by e-mail (Amazon EventBridge)
**Owner:** Saged (infra) · **Done 26 Nov**, `infra/security/setup-alerts.sh`

**Why it is a good option:**
- GuardDuty and Security Hub only help if someone sees the findings. Five rules send the dangerous
  events to the `pb-ops-alarms` topic (e-mail): GuardDuty findings (medium+), Security Hub HIGH/CRITICAL,
  root sign-in, IAM changes, and attempts to switch off logging, the key, Config or GuardDuty.
- Each rule was checked against a dangerous and a harmless sample event, and a test alert was delivered.

### Supply chain: Dependabot + CodeQL
**Owner:** Saged · **Done 26 Nov** (config), `.github/dependabot.yml`, `.github/workflows/codeql.yml`
- Dependabot opens pull requests for vulnerable npm libraries and GitHub Actions every week.
- CodeQL scans our JavaScript for security bugs on every push and pull request (security-extended rules).
- Turn on "Dependabot alerts" and "Dependabot security updates" in the repo settings once.

---

## 6. Common attacks and how we handle them

Each row says what the attack is, what already protects us (checked in the code), and what is left
to do. We can reuse this table for report §7 (threat model) and §8 (security controls).

| Attack | What it is | How we are protected now | Gap / what to add |
|---|---|---|---|
| **Injection** (SQL/NoSQL) | Sending code inside input to run database commands | DynamoDB queries use keys and parameters only, never strings built from input; strict validation rejects unknown fields and wrong types | Covered. If Neon is added (1b), use parameterised SQL only |
| **XSS** (cross-site scripting) | Planting a script in a note so it runs in another user's browser | Text is shown with `textContent`, never as HTML; a strict Content-Security-Policy blocks inline scripts | Covered (test ST-13) |
| **IDOR / broken access control** | Changing an ID in the URL to see someone else's data | Every record is looked up under the logged-in user's key; another user's ID returns 404 (tested on Floci) | Covered |
| **Privilege escalation** | A normal user making themselves admin | The role is checked in the backend on every admin route and re-read from the database; sending `role: "admin"` is rejected with 400 | Covered |
| **Brute force / credential stuffing** | Trying many passwords, or e-mail/password pairs leaked from other sites | scrypt hashing, lockout after 5 failures (429), the same error for a wrong e-mail or a wrong password, failed-login metric and alarm | **5a** MFA, **5c** breached-password check, **2b** WAF limit per IP |
| **Token / session theft** | Stealing the login token and reusing it | Token kept in `sessionStorage` (gone when the tab closes), signed with a secret key, `alg:none` and tampered tokens rejected, HTTPS on AWS | **5b** short access tokens + revocable refresh tokens |
| **CSRF** (cross-site request forgery) | A malicious site making the user's browser send requests to our API | The token is sent in a header, not a cookie, so the browser never adds it on its own; CORS allows only our origin | Covered by design |
| **Clickjacking** | Showing our app in an invisible frame on another site to trick clicks | `X-Frame-Options: DENY` and CSP | Covered |
| **DoS / request floods** | Overloading the API, or running up the bill | API Gateway throttling, 20 KB body limit, query limits (at most 500 rows, 12 months, 10 reports) | **2b** WAF limit per IP, **3a** SQS queues for heavy jobs |
| **Malicious file upload** | Uploading huge files, or a program disguised as an image | Private S3 bucket, 5-minute signed links, uploaded files are never executed | **5e** upload field with a 5 MB cap and a real file-type check |
| **SSRF** (server-side request forgery) | Tricking the server into calling internal addresses | The only outgoing call is the exchange-rate API, at a fixed URL, with the currency checked against an allow-list | Covered |
| **Secrets leakage** | Keys or passwords in the code, the Git history or the logs | Signing key in Secrets Manager, `.env` git-ignored, the logger removes password/token fields, gitleaks scans every push | Covered |
| **Vulnerable libraries** (supply chain) | A library we use has a known security hole | `npm audit` in CI fails on high/critical issues (0 found), lockfiles pinned | Dependabot + CodeQL (**added 26 Nov**) |
| **Cloud misconfiguration** | A public bucket, IAM that is too wide, no audit trail | Block Public Access, encryption at rest, one least-privilege role per Lambda | **5h** CloudTrail, GuardDuty, Config rules, Security Hub |
| **Data loss / ransomware** | Data deleted or corrupted by mistake or by an attacker | S3 versioning | **5j** point-in-time recovery, AWS Backup, a restore drill |
| **Prototype pollution** (Node.js) | Sending `__proto__` fields to corrupt objects in the server | The validator only accepts fields defined in each schema, so `__proto__` is rejected | Covered |
| **CSV formula injection** | A report cell starting with `=` runs a formula when opened in Excel | Cells starting with `= + - @` are escaped | Covered (test UT-08) |

**Summary:** the classic web attacks are already covered and tested: injection, XSS, IDOR, CSRF,
clickjacking, SSRF and prototype pollution. What is left:
- **stolen credentials and tokens:** 5a, 5b, 5c;
- **floods from one user:** 2b;
- **uploads:** 5e;
- **detecting and recovering from attacks:** 5h, 5j, plus 5m (logs nobody can erase) and 5n (alerts);
- **stolen signing key / data at rest:** 5l (key rotation), 5k (our own encryption key).

---

## Division (fill in)

Each person gets about 5 hours of enhancements, one visible demo moment, and only work inside their
own service. These come **after** the required work (own service on own branch, security tests,
report sections, video). If time runs out, drop enhancements, not required work.

| Item | Owner | Status |
|---|---|---|
| 1b Neon audit log | Omar | Report only (§16 future work): new account + internet, too much for tonight |
| 1c Redis cache and rate limiting | — | Report only: ElastiCache did not answer on our Floci (tested 25 Nov) |
| 2a CloudFront | — | Report only: CloudFront did not answer on our Floci (tested 25 Nov) |
| 2b WAF | Saged | **Done 26 Nov**: web ACL with per-IP limit + 3 AWS rule groups. Not attached: needs CloudFront (§16) |
| 3a SQS alerts / CSV reports | Saged (alerts) | Stretch, only if time is left |
| 3b Lambda concurrency | Saged | **Done 26 Nov**: Floci enforces it (503 over the cap) |
| 4a Dashboard and X-Ray | Omar | Stretch, only if time is left |
| 4b Throttle values | Saged | **Done 26 Nov**: `SCALE=aws` 1,000/s burst 2,000 |
| 4c Load test | Salma | Planned (1 h) |
| Report: 1a, 2c, 3c scaling write-up | Salma | Planned (1 h), also covers 1c and 2a as "what we would add on real AWS" |
| 5a MFA (admins required) | Omar | Planned (3 h) |
| 5b Refresh tokens and real logout | Omar | Stretch, only if time is left |
| 5c Breached-password check | Omar | Planned (1 h) |
| 5e Receipt upload field + safe uploads | Salma | Planned (2.5 h) |
| 5f Download my data / delete my account | All: Salma (transactions + receipts, 45 min), Saged (buckets, 30 min, **done 26 Nov**: ST-18), Omar (account + the flow that calls every service, 1.25 h) | Planned |
| 5h CloudTrail, GuardDuty, Security Hub, Config | Saged | **Done 26 Nov** (set-up); Floci creates them but produces no events (§16); screenshots for §11 by Omar |
| 5j Backups and recovery drill | Saged | **Done 26 Nov**: restore drill PASS |
| 5k KMS customer-managed key | Saged | **Done 26 Nov** |
| 5l JWT key rotation | Saged | **Done 26 Nov**: ST-19 + live drill |
| 5m Object Lock on audit logs | Saged | **Done 26 Nov**: AccessDenied on delete |
| 5n Security alerts (EventBridge) | Saged | **Done 26 Nov**: 5/5 rules + delivery checked |
| Dependabot + CodeQL | Saged | **Done 26 Nov** (config files); turn on alerts in repo settings |

**Totals:** Salma ≈ 5.25 h (5e, 4c, 5f part, scaling write-up) · Omar ≈ 5.25 h (5a, 5c, 5f part) ·
Saged ≈ 5.2 h (5h, 5j, 2b, 4b, 3b, 5f part).

**Demo moments:** Salma, a fake "photo" upload blocked live · Omar, login asking for the 6-digit code ·
Saged, rewinding a deleted table.
