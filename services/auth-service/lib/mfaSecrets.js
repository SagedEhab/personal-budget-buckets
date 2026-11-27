// Protects the MFA data stored in the users table. Owner: Omar (Auth service, enhancement 5a).
//
// 1. The authenticator secret is stored ENCRYPTED with AES-256-GCM, never in plain text.
//    The 256-bit key is derived (HKDF-SHA256) from the signing secret that is already kept in
//    AWS Secrets Manager, with its own label, so no new secret and no new IAM permission are needed.
//    The user id is bound in as "additional authenticated data": a ciphertext copied onto another
//    user's record fails to decrypt.
//    Trade-off (report §16): rotating that Secrets Manager secret makes stored MFA secrets unreadable,
//    so users would sign in with a recovery code and set MFA up again.
// 2. Recovery codes are random (10 characters, about 49 bits each) and only their SHA-256 hashes
//    are stored. A fast hash is enough here because the codes are random, not chosen by people.
//    Each code works once.
const crypto = require('crypto');
const { secrets } = require('pb-common');

const VERSION = 'v1';
const RECOVERY_COUNT = 10;
const RECOVERY_ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789'; // no 0/o, 1/l/i: easy to type

async function encryptionKey() {
  const master = await secrets.getJwtSecret();
  return Buffer.from(crypto.hkdfSync('sha256', master, 'pb-auth-mfa', 'totp-secret-encryption-v1', 32));
}

async function encryptSecret(plain, userId) {
  const key = await encryptionKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(`user:${userId}`));
  const data = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  return [VERSION, iv.toString('base64url'), cipher.getAuthTag().toString('base64url'), data.toString('base64url')].join('.');
}

async function decryptSecret(stored, userId) {
  const [version, iv, tag, data] = String(stored || '').split('.');
  if (version !== VERSION || !iv || !tag || !data) throw new Error('Unknown MFA secret format.');
  const key = await encryptionKey();
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64url'));
  decipher.setAAD(Buffer.from(`user:${userId}`));
  decipher.setAuthTag(Buffer.from(tag, 'base64url'));
  return Buffer.concat([decipher.update(Buffer.from(data, 'base64url')), decipher.final()]).toString('utf8');
}

const normaliseRecovery = (code) => String(code || '').toLowerCase().replace(/[^a-z0-9]/g, '');
const hashRecovery = (code) => crypto.createHash('sha256').update(`pb-recovery:${normaliseRecovery(code)}`).digest('hex');

function newRecoveryCodes(count = RECOVERY_COUNT) {
  const codes = [];
  for (let n = 0; n < count; n += 1) {
    let c = '';
    for (const b of crypto.randomBytes(10)) c += RECOVERY_ALPHABET[b % RECOVERY_ALPHABET.length];
    codes.push(`${c.slice(0, 5)}-${c.slice(5)}`);
  }
  return { codes, hashes: codes.map(hashRecovery) };
}

// Returns the list of hashes left after using `code`, or null if the code is not valid.
function useRecoveryCode(hashes, code) {
  const list = Array.isArray(hashes) ? hashes : [];
  const given = Buffer.from(hashRecovery(code));
  const index = list.findIndex((h) => typeof h === 'string' && h.length === given.length && crypto.timingSafeEqual(Buffer.from(h), given));
  if (index < 0 || normaliseRecovery(code).length !== 10) return null;
  return list.filter((_, i) => i !== index);
}

module.exports = { encryptSecret, decryptSecret, newRecoveryCodes, useRecoveryCode, RECOVERY_COUNT };
