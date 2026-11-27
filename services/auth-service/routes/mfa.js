// Multi-factor authentication with authenticator-app codes (enhancement 5a). Owner: Omar.
// Mandatory for the admin role, optional for normal users.
//
// Login with MFA is two steps:
//   1. POST /api/auth/login (e-mail + password)  -> 200 { mfaRequired: true, mfaToken }      MFA on
//                                                -> 200 { mfaSetupRequired: true, mfaToken } admin without MFA yet
//   2. POST /api/auth/mfa/verify { mfaToken, code | recoveryCode } -> 200 { token, user }
// The mfaToken is a 5-minute "half-logged-in" ticket. It has its own audience ("pb-auth-mfa"), so
// requireAuth in every service rejects it: it cannot be used as an access token.
//
// Stored on the user's PROFILE item in PBUsers:
//   mfaEnabled, mfaSecret (AES-GCM encrypted), mfaPendingSecret + mfaPendingAt (during setup),
//   mfaRecoveryHashes (SHA-256), mfaLastStep (replay protection), failedMfa (lockout counter)
const crypto = require('crypto');
const express = require('express');
const { validate, wrap, errors, jwt, secrets, ISSUER } = require('pb-common');
const QRCode = require('qrcode');
const totp = require('../lib/totp');
const mfaSecrets = require('../lib/mfaSecrets');

const CHALLENGE_AUDIENCE = 'pb-auth-mfa';
const CHALLENGE_TTL_SEC = 300;
const SETUP_TTL_MS = 10 * 60 * 1000;
const MAX_FAILED_CODES = 5;

const codeSchema = { code: { type: 'string', required: true, pattern: /^\d{6}$/, patternMessage: 'code must be the 6 digits shown in your authenticator app.' } };
const verifySchema = {
  mfaToken: { type: 'string', required: true, maxLength: 2000 },
  code: { type: 'string', pattern: /^\d{6}$/, patternMessage: 'code must be 6 digits.' },
  recoveryCode: { type: 'string', maxLength: 20, pattern: /^[A-Za-z0-9-\s]{10,20}$/, patternMessage: 'recoveryCode has an invalid format.' }
};
const disableSchema = {
  password: { type: 'string', required: true, trim: false, maxLength: 128 },
  code: codeSchema.code
};

function createMfa({ users, logger, requireAuth, issueToken, publicUser, verifyPassword, tokenTtlSec, lockMinutes }) {
  const router = express.Router();
  const profileKey = (id) => [`USER#${id}`, 'PROFILE'];

  async function challengeToken(user, purpose) {
    const secret = await secrets.getJwtSecret();
    return jwt.sign({ sub: user.id, purpose, jti: crypto.randomUUID() }, secret,
      { expiresInSec: CHALLENGE_TTL_SEC, issuer: ISSUER, audience: CHALLENGE_AUDIENCE });
  }

  async function readChallenge(token, purpose) {
    const secret = await secrets.getJwtSecret();
    const r = jwt.verify(token, secret, { issuer: ISSUER, audience: CHALLENGE_AUDIENCE });
    return r.ok && r.claims.purpose === purpose && typeof r.claims.sub === 'string' ? r.claims : null;
  }

  // Called by POST /login after the password is correct and the account is active.
  // Returns the response body when a second step is needed, or null for a normal login.
  async function loginStep(user, req) {
    if (user.mfaEnabled) {
      logger.info('MFA_CHALLENGE_ISSUED', { requestId: req.requestId, userId: user.id });
      return { mfaRequired: true, mfaToken: await challengeToken(user, 'mfa-login'), expiresIn: CHALLENGE_TTL_SEC };
    }
    if (user.role === 'admin') {
      logger.warn('MFA_SETUP_REQUIRED', { requestId: req.requestId, userId: user.id });
      return { mfaSetupRequired: true, mfaToken: await challengeToken(user, 'mfa-setup'), expiresIn: CHALLENGE_TTL_SEC };
    }
    return null;
  }

  // Setup may be done with a normal access token (any user, from the Security page) or with the
  // short setup ticket that an admin without MFA receives at login.
  async function requireUserOrSetupTicket(req, res, next) {
    try {
      const m = /^Bearer ([A-Za-z0-9_\-.]+)$/.exec(req.get('authorization') || '');
      const ticket = m ? await readChallenge(m[1], 'mfa-setup') : null;
      if (!ticket) return requireAuth(req, res, next);
      const user = await users.get(...profileKey(ticket.sub));
      if (!user || user.status !== 'active') throw errors.unauthorized('Invalid authentication token.');
      req.user = { id: user.id, role: user.role };
      req.viaSetupTicket = true;
      return next();
    } catch (error) {
      return next(error);
    }
  }

  async function finishLogin(user, req) {
    const updated = await users.update(user.pk, user.sk, { failedLogins: 0, failedMfa: 0, lockedUntil: null, lastLoginAt: new Date().toISOString() });
    logger.info('LOGIN_SUCCEEDED', { requestId: req.requestId, userId: user.id, role: user.role, mfa: true });
    return { token: await issueToken(updated, { expiresInSec: tokenTtlSec }), expiresIn: tokenTtlSec, user: publicUser(updated) };
  }

  const isLocked = (u) => u.lockedUntil && Date.parse(u.lockedUntil) > Date.now();
  const lockedError = () => {
    const e = errors.unprocessable('ACCOUNT_LOCKED', `Too many failed attempts. Try again after ${lockMinutes} minutes.`);
    e.status = 429;
    return e;
  };

  // A wrong code counts like a wrong password: 5 in a row lock the account for 15 minutes.
  async function recordFailedCode(user, req, reason) {
    const failedMfa = (user.failedMfa || 0) + 1;
    const lock = failedMfa >= MAX_FAILED_CODES;
    await users.update(user.pk, user.sk, {
      failedMfa: lock ? 0 : failedMfa,
      ...(lock ? { lockedUntil: new Date(Date.now() + lockMinutes * 60000).toISOString() } : {})
    });
    logger.warn(lock ? 'ACCOUNT_LOCKED' : 'MFA_CODE_FAILED', { requestId: req.requestId, userId: user.id, attempt: failedMfa, reason, ip: req.ip });
    logger.metric('FailedLogins', 1);
  }

  // 1. Start setup: new secret, shown as a QR code (and as text for manual entry). Nothing is
  //    switched on until the user proves the app works by sending a code to /mfa/enable.
  router.post('/setup', requireUserOrSetupTicket, wrap(async (req, res) => {
    const user = await users.get(...profileKey(req.user.id));
    if (!user) throw errors.notFound('User');
    if (user.mfaEnabled) throw errors.conflict('MFA_ALREADY_ENABLED', 'Two-step login is already on for this account.');
    const secret = totp.generateSecret();
    await users.update(user.pk, user.sk, {
      mfaPendingSecret: await mfaSecrets.encryptSecret(secret, user.id),
      mfaPendingAt: new Date().toISOString()
    });
    const url = totp.otpauthUrl(secret, user.email);
    logger.info('MFA_SETUP_STARTED', { requestId: req.requestId, userId: user.id });
    res.status(200).json({ secret, otpauthUrl: url, qrDataUrl: await QRCode.toDataURL(url, { margin: 1, width: 220 }) });
  }));

  // 2. Confirm setup with the first code -> MFA on, 10 one-time recovery codes shown ONCE.
  router.post('/enable', requireUserOrSetupTicket, wrap(async (req, res) => {
    const { code } = validate(req.body, codeSchema);
    const user = await users.get(...profileKey(req.user.id));
    if (!user) throw errors.notFound('User');
    if (user.mfaEnabled) throw errors.conflict('MFA_ALREADY_ENABLED', 'Two-step login is already on for this account.');
    if (!user.mfaPendingSecret || Date.now() - Date.parse(user.mfaPendingAt) > SETUP_TTL_MS) {
      throw errors.conflict('MFA_SETUP_EXPIRED', 'Start the setup again: the QR code is older than 10 minutes.');
    }
    const secret = await mfaSecrets.decryptSecret(user.mfaPendingSecret, user.id);
    const step = totp.verifyCode(secret, code);
    if (step === null) {
      logger.warn('MFA_SETUP_CODE_FAILED', { requestId: req.requestId, userId: user.id });
      throw errors.unprocessable('MFA_CODE_INVALID', 'That code is not correct. Check the time on your phone and try again.');
    }
    const { codes, hashes } = mfaSecrets.newRecoveryCodes();
    const updated = await users.update(user.pk, user.sk, {
      mfaEnabled: true, mfaSecret: user.mfaPendingSecret, mfaPendingSecret: null, mfaPendingAt: null,
      mfaRecoveryHashes: hashes, mfaLastStep: step, mfaEnabledAt: new Date().toISOString(), failedMfa: 0
    });
    logger.info('MFA_ENABLED', { requestId: req.requestId, userId: user.id, role: user.role });
    const body = { mfaEnabled: true, recoveryCodes: codes };
    // An admin who was made to set MFA up at login is now fully logged in.
    if (req.viaSetupTicket) Object.assign(body, await finishLogin(updated, req));
    res.status(200).json(body);
  }));

  // 3. Second login step: a code from the app, or one of the recovery codes.
  router.post('/verify', wrap(async (req, res) => {
    const input = validate(req.body, verifySchema);
    if (!input.code === !input.recoveryCode) throw errors.badRequest('Send either code or recoveryCode.');
    const ticket = await readChallenge(input.mfaToken, 'mfa-login');
    if (!ticket) {
      logger.warn('MFA_TICKET_REJECTED', { requestId: req.requestId, ip: req.ip });
      throw errors.unauthorized('This login step has expired. Log in again.');
    }
    const user = await users.get(...profileKey(ticket.sub));
    if (!user || !user.mfaEnabled) throw errors.unauthorized('This login step has expired. Log in again.');
    if (isLocked(user)) {
      logger.warn('LOGIN_BLOCKED_LOCKED', { requestId: req.requestId, userId: user.id, ip: req.ip, step: 'mfa' });
      throw lockedError();
    }
    if (user.status !== 'active') throw errors.forbidden('This account has been disabled. Contact the administrator.');

    if (input.code) {
      const secret = await mfaSecrets.decryptSecret(user.mfaSecret, user.id);
      const step = totp.verifyCode(secret, input.code, { afterStep: user.mfaLastStep ?? -1 });
      if (step === null) {
        await recordFailedCode(user, req, 'totp');
        throw errors.unauthorized('The code is not correct.');
      }
      await users.update(user.pk, user.sk, { mfaLastStep: step });
      return res.status(200).json(await finishLogin(user, req));
    }

    const left = mfaSecrets.useRecoveryCode(user.mfaRecoveryHashes, input.recoveryCode);
    if (!left) {
      await recordFailedCode(user, req, 'recovery');
      throw errors.unauthorized('The recovery code is not correct.');
    }
    await users.update(user.pk, user.sk, { mfaRecoveryHashes: left });
    logger.warn('MFA_RECOVERY_CODE_USED', { requestId: req.requestId, userId: user.id, remaining: left.length });
    return res.status(200).json({ ...(await finishLogin(user, req)), recoveryCodesLeft: left.length });
  }));

  // 4. Turn MFA off (normal users only). Needs the password AND a current code.
  router.post('/disable', requireAuth, wrap(async (req, res) => {
    const { password, code } = validate(req.body, disableSchema);
    const user = await users.get(...profileKey(req.user.id));
    if (!user) throw errors.notFound('User');
    if (user.role === 'admin') {
      logger.warn('MFA_DISABLE_REFUSED_ADMIN', { requestId: req.requestId, userId: user.id });
      const e = errors.forbidden('Two-step login is required for administrators and cannot be turned off.');
      e.code = 'MFA_REQUIRED_FOR_ADMIN';
      throw e;
    }
    if (!user.mfaEnabled) throw errors.conflict('MFA_NOT_ENABLED', 'Two-step login is not on for this account.');
    const secret = await mfaSecrets.decryptSecret(user.mfaSecret, user.id);
    const step = totp.verifyCode(secret, code, { afterStep: user.mfaLastStep ?? -1 });
    if (!(await verifyPassword(password, user.passwordHash)) || step === null) {
      await recordFailedCode(user, req, 'disable');
      throw errors.unprocessable('INVALID_CONFIRMATION', 'Password or code is not correct.');
    }
    const updated = await users.update(user.pk, user.sk, {
      mfaEnabled: false, mfaSecret: null, mfaRecoveryHashes: null, mfaLastStep: null, mfaEnabledAt: null
    });
    logger.warn('MFA_DISABLED', { requestId: req.requestId, userId: user.id });
    res.status(200).json(publicUser(updated));
  }));

  return { router, loginStep };
}

module.exports = { createMfa, CHALLENGE_AUDIENCE, CHALLENGE_TTL_SEC, MAX_FAILED_CODES };
