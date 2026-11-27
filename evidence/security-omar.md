# Security and end-to-end tests: Auth and Insights services (Omar), run on Floci

Run: 2026-11-27T18:00:41.944Z against http://31284765bb.execute-api.localhost.floci.io:4566. Script: tests/security/auth-security.mjs

| Test ID | Category | Scenario | Expected | Actual | Pass/Fail |
|---|---|---|---|---|---|
| IT-01 | End-to-end: account | Register, log in, read own profile, change base currency (new token issued) | 201; 200; 200 role user, no password hash; 200 and token claim cur=USD | register 201; login 200; me 200 role=user email matches=true; patch 200 baseCurrency=USD, new token cur=USD; hash returned=false | Pass |
| ST-03 | Authentication | Correctly signed token that expired 1 hour ago, on three services; token with exp extended by hand | 401 "Session expired" on auth, buckets, insights; 401 | auth 401 "Session expired. Please log in again."; buckets 401; insights 401; exp extended by hand 401 | Pass |
| ST-04 | Authorization (roles) | Normal user calls 4 admin endpoints on 3 services, then 12 more times (feeds the 403 alarm) | 403 on all; 12 x 403 | list users 403 FORBIDDEN; change status 403 FORBIDDEN; admin overview 403 FORBIDDEN; add template 403 FORBIDDEN; burst of 12: 403 403 403 403 403 403 403 403 403 403 403 403 | Pass |
| ST-09 | Mass assignment / privilege escalation | Register with "role": "admin" in the body | 400 "role is not an allowed field"; then 201 with role user (nothing was created by the first request) | register 400 VALIDATION_ERROR "role is not an allowed field."; same e-mail without role: 201 role=user (so no account had been created) | Pass |
| ST-10 | Brute force | 5 wrong passwords, a 6th, then the correct password; unknown e-mail for comparison | 401 x5; 429 ACCOUNT_LOCKED; 429 (locked for 15 min); 401 with the same message | 5 wrong: 401 401 401 401 401; 6th 429 ACCOUNT_LOCKED; correct password while locked 429 ACCOUNT_LOCKED; unknown e-mail 401 same message=true | Pass |
| ST-15 | Account status | Admin disables a user whose token is still valid; the user keeps calling three services; admin re-enables | 200 before; 403 on auth at once and on login; 403 on buckets and insights within 60 s; 200 after re-enabling | admin setup forced=true, admin token 200; before 200; disable 200; same token: auth/me 403 FORBIDDEN, login 403 FORBIDDEN, after 61 s buckets 403 FORBIDDEN, insights 403 FORBIDDEN; re-enabled 200 -> 200 | Pass |
| IT-10 | End-to-end: dashboard | Bucket 1,000 EGP; expense 900 and income 5,000; Insights builds the dashboard from Transactions + Buckets | 200; income 5000, expense 900, net 4100; Food 90% NEAR_LIMIT | bucket 201, expense 201, income 201; dashboard 200: income=5000 expense=900 net=4100 savingsRate=82%; Food 90% NEAR_LIMIT; nearLimit=1 | Pass |
| IT-12 | End-to-end: reports | Generate a CSV report, list it, download it through a 5-minute S3 link, another user tries it, delete it | 201; 200; 200 link (300 s); S3 200 with the expense; 404; 204; 404 | generate 201 rows=2; list 200 count=1; download link 200 expires in 300s; S3 file 200 has the expense=true; other user 404 NOT_FOUND; delete 204; after delete 404 NOT_FOUND | Pass |

8 of 8 passed.
