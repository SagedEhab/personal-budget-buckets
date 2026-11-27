// Time-based one-time passwords (TOTP, RFC 6238), the 6-digit codes shown by authenticator apps
// such as Google Authenticator or Microsoft Authenticator. Written with Node's crypto module only.
//   code = last 6 digits of HMAC-SHA1(secret, floor(unixTime / 30))   (RFC 4226 "dynamic truncation")
// Owner: Omar (Auth service, enhancement 5a).
const crypto = require('crypto');

const STEP_SEC = 30;
const DIGITS = 6;
const WINDOW = 1; // accept the previous and the next 30-second step too (phone clock drift)
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; // base32 (RFC 4648), what authenticator apps expect

function base32Encode(buf) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

function base32Decode(text) {
  const clean = String(text).toUpperCase().replace(/[\s=-]/g, '');
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of clean) {
    const i = ALPHABET.indexOf(ch);
    if (i < 0) throw new Error('Invalid base32 character.');
    value = (value << 5) | i;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

// 20 random bytes = 160 bits, the size RFC 4226 recommends for HMAC-SHA1.
function generateSecret() {
  return base32Encode(crypto.randomBytes(20));
}

function hotp(secretBuf, counter, digits = DIGITS) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const mac = crypto.createHmac('sha1', secretBuf).update(msg).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const bin = ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return String(bin % 10 ** digits).padStart(digits, '0');
}

const stepAt = (timeMs = Date.now()) => Math.floor(timeMs / 1000 / STEP_SEC);

function codeAt(secretBase32, timeMs = Date.now()) {
  return hotp(base32Decode(secretBase32), stepAt(timeMs));
}

// Returns the matching time step (a number), or null. The caller stores the step that was used
// and refuses any step that is not newer, so the same code cannot be replayed within its window.
function verifyCode(secretBase32, code, { timeMs = Date.now(), afterStep = -1 } = {}) {
  if (typeof code !== 'string' || !/^\d{6}$/.test(code)) return null;
  const key = base32Decode(secretBase32);
  const now = stepAt(timeMs);
  for (let step = now - WINDOW; step <= now + WINDOW; step += 1) {
    if (step <= afterStep) continue;
    const expected = Buffer.from(hotp(key, step));
    if (crypto.timingSafeEqual(expected, Buffer.from(code))) return step;
  }
  return null;
}

// The link encoded in the QR code. Authenticator apps read the issuer, account name and secret from it.
function otpauthUrl(secretBase32, accountName, issuer = 'Personal Budget Buckets') {
  const label = encodeURIComponent(`${issuer}:${accountName}`);
  const params = new URLSearchParams({ secret: secretBase32, issuer, algorithm: 'SHA1', digits: String(DIGITS), period: String(STEP_SEC) });
  return `otpauth://totp/${label}?${params.toString()}`;
}

module.exports = { generateSecret, verifyCode, codeAt, hotp, otpauthUrl, base32Encode, base32Decode, STEP_SEC };
