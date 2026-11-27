// Privacy rights (enhancement 5f, Egypt PDPL 151/2020: right of access and right to erasure).
// Owner: Omar. The Auth service runs the whole flow, because it owns the account:
//   GET    /api/auth/me/export  -> profile + every service's own export, as one JSON file
//   DELETE /api/auth/me         -> { confirm: true, password, code? }
//       1. re-check the password (and the MFA code when MFA is on)
//       2. ask Insights, Transactions and Buckets to delete this user's data
//          (each one with the USER'S OWN token, so each applies its own ownership checks)
//       3. only if all three succeed: delete the account itself, LAST.
//   If a service fails, the account is kept and 503 is returned, so the user can simply try
//   again: every step is safe to repeat, and no data is left behind without an account to
//   reach it with.
const express = require('express');
const { validate, wrap, errors, callService } = require('pb-common');
const totp = require('../lib/totp');
const mfaSecrets = require('../lib/mfaSecrets');

// Each service keeps its own data and exposes the same two endpoints for it.
const SERVICES = [
  { name: 'insights', base: '/api/insights' },
  { name: 'transactions', base: '/api/transactions' },
  { name: 'buckets', base: '/api/buckets' }
];

const deleteSchema = {
  confirm: { type: 'boolean', required: true },
  password: { type: 'string', required: true, trim: false, maxLength: 128 },
  code: { type: 'string', pattern: /^\d{6}$/, patternMessage: 'code must be the 6 digits shown in your authenticator app.' }
};

function createPrivacy({ users, logger, requireAuth, publicUser, verifyPassword }) {
  const router = express.Router();

  async function ask(req, service, method, path, body) {
    const r = await callService(service, { method, path, body, authHeader: req.authHeader, requestId: req.requestId })
      .catch(() => ({ status: 503, body: null }));
    if (r.status !== 200) logger.error('PRIVACY_DEPENDENCY_ERROR', { requestId: req.requestId, service, method, path, status: r.status });
    return r;
  }

  // 1. Download my data
  router.get('/me/export', requireAuth, wrap(async (req, res) => {
    const user = await users.get(`USER#${req.user.id}`, 'PROFILE');
    if (!user) throw errors.notFound('User');
    const parts = await Promise.all(SERVICES.map((s) => ask(req, s.name, 'GET', `${s.base}/me/export`)));
    const failed = SERVICES.filter((s, i) => parts[i].status !== 200).map((s) => s.name);
    if (failed.length) {
      // A partial file would look complete to the user, so none is given.
      throw errors.unavailable('EXPORT_INCOMPLETE', `Your data could not be collected from: ${failed.join(', ')}. Please try again later.`);
    }
    logger.info('PRIVACY_EXPORT', { requestId: req.requestId, userId: user.id, service: 'auth' });
    res.set('Content-Disposition', 'attachment; filename="my-budget-data.json"');
    res.status(200).json({
      exportedAt: new Date().toISOString(),
      about: 'All personal data Personal Budget Buckets holds about you (Egypt PDPL 151/2020, right of access).',
      account: {
        ...publicUser(user),
        security: {
          mfaEnabled: Boolean(user.mfaEnabled), mfaEnabledAt: user.mfaEnabledAt || null,
          recoveryCodesLeft: Array.isArray(user.mfaRecoveryHashes) ? user.mfaRecoveryHashes.length : 0,
          note: 'Your password hash and authenticator secret are kept only in protected form and are not exported.'
        }
      },
      ...Object.fromEntries(SERVICES.map((s, i) => [s.name, parts[i].body]))
    });
  }));

  // 2. Delete my account
  router.delete('/me', requireAuth, wrap(async (req, res) => {
    const input = validate(req.body || {}, deleteSchema);
    if (input.confirm !== true) throw errors.badRequest('Send "confirm": true to delete your account.');
    const user = await users.get(`USER#${req.user.id}`, 'PROFILE');
    if (!user) throw errors.notFound('User');
    if (user.role === 'admin') {
      const e = errors.forbidden('Administrator accounts cannot be deleted from the app. Ask the system owner.');
      e.code = 'ADMIN_ACCOUNT';
      throw e;
    }

    // Re-authenticate: a stolen session alone must not be able to erase the account.
    let codeOk = true;
    if (user.mfaEnabled) {
      const step = input.code ? totp.verifyCode(await mfaSecrets.decryptSecret(user.mfaSecret, user.id), input.code, { afterStep: user.mfaLastStep ?? -1 }) : null;
      codeOk = step !== null;
      if (codeOk) await users.update(user.pk, user.sk, { mfaLastStep: step });
    }
    if (!(await verifyPassword(input.password, user.passwordHash)) || !codeOk) {
      logger.warn('ACCOUNT_DELETE_REFUSED', { requestId: req.requestId, userId: user.id, ip: req.ip });
      throw errors.unprocessable('INVALID_CONFIRMATION', user.mfaEnabled ? 'Password or code is not correct.' : 'Password is not correct.');
    }

    logger.warn('ACCOUNT_DELETE_STARTED', { requestId: req.requestId, userId: user.id });
    const results = {};
    for (const s of SERVICES) {
      const r = await ask(req, s.name, 'DELETE', `${s.base}/me`, { confirm: true });
      results[s.name] = r.status === 200 ? r.body : { error: r.status };
      if (r.status !== 200) {
        throw errors.unavailable('DELETE_INCOMPLETE',
          `Your ${s.name} data could not be deleted right now, so your account was kept. Please try again later.`);
      }
    }
    // Last step: the account. E-mail index first, so the address can be registered again.
    await users.remove(`EMAIL#${user.email}`, 'EMAIL');
    await users.remove(user.pk, user.sk);
    logger.warn('ACCOUNT_DELETED', { requestId: req.requestId, userId: user.id, results });
    res.status(200).json({ deleted: true, services: results });
  }));

  return { router };
}

module.exports = { createPrivacy, SERVICES };
