// Breached-password check with the Have I Been Pwned "Pwned Passwords" API (enhancement 5c).
// Owner: Omar (Auth service). Second external API: it does a real security job at registration.
//
// k-anonymity: the password itself never leaves the server, and neither does its full hash.
//   1. SHA-1 of the password, in upper-case hex (40 characters)
//   2. send only the FIRST 5 characters:  GET https://api.pwnedpasswords.com/range/ABCDE
//   3. the API returns every hash suffix starting with those 5 characters (hundreds of them)
//      with how often each one appeared in breaches; we look for our own suffix locally.
// "Add-Padding: true" adds fake rows, so even the response size reveals nothing.
// If the API is slow or down, registration still works (fail open) and the skipped check is logged:
// availability matters more here, and the other password rules still apply.
const crypto = require('crypto');

const API = 'https://api.pwnedpasswords.com/range/'; // fixed URL: no SSRF, only the 5-character prefix varies
const TIMEOUT_MS = 2500;

let fetchImpl = (...args) => fetch(...args);
// Tests replace the network call with a fake (no internet needed).
function setFetch(fn) { fetchImpl = fn || ((...args) => fetch(...args)); }

function sha1Parts(password) {
  const hash = crypto.createHash('sha1').update(String(password), 'utf8').digest('hex').toUpperCase();
  return { prefix: hash.slice(0, 5), suffix: hash.slice(5) };
}

// Returns { checked: true, breached: boolean, count } or { checked: false, reason }.
async function checkPassword(password) {
  const { prefix, suffix } = sha1Parts(password);
  let res;
  try {
    res = await fetchImpl(API + prefix, {
      headers: { 'Add-Padding': 'true', 'User-Agent': 'personal-budget-buckets-auth' },
      signal: AbortSignal.timeout(TIMEOUT_MS)
    });
  } catch (error) {
    return { checked: false, reason: error.name === 'TimeoutError' ? 'timeout' : 'network' };
  }
  if (!res.ok) return { checked: false, reason: `http_${res.status}` };
  const text = await res.text();
  for (const line of text.split('\n')) {
    const [s, c] = line.trim().split(':');
    if (s === suffix) {
      const count = Number(c) || 0;
      return { checked: true, breached: count > 0, count }; // padding rows have count 0
    }
  }
  return { checked: true, breached: false, count: 0 };
}

module.exports = { checkPassword, sha1Parts, setFetch };
