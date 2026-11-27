// Login / registration screen and the Security page. Owner: Omar (Auth service).
// Two-step login (enhancement 5a): after a correct password the server may answer
//   { mfaRequired: true, mfaToken }       -> ask for the 6-digit code from the authenticator app
//   { mfaSetupRequired: true, mfaToken }  -> admins must set two-step login up before they get in
// The extra screens are built here with UI.el (textContent only, no innerHTML), so the shared
// index.html does not need to change. The backend enforces every rule; these screens only guide.

// Shows the QR code, checks the first code, then shows the recovery codes once.
const MfaSetup = {
  async render(box, { intro, onDone, onCancel }) {
    UI.clear(box);
    const err = UI.el('p', { class: 'error', role: 'alert' });
    box.append(UI.el('p', { class: 'muted', text: intro }), err);
    let setup;
    try { setup = await Api.post('/api/auth/mfa/setup'); } catch (e) { err.textContent = e.message; return; }

    const form = UI.el('form', { novalidate: true },
      UI.el('label', {}, '6-digit code from the app ',
        UI.el('input', { name: 'code', inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: '6', pattern: '\\d{6}', required: true })),
      UI.el('button', { class: 'primary', type: 'submit', text: 'Turn on two-step login' }),
      onCancel ? UI.el('button', { class: 'link', type: 'button', text: 'Cancel', onclick: onCancel }) : null);
    box.append(
      UI.el('ol', {},
        UI.el('li', { text: 'Open Google Authenticator or Microsoft Authenticator on your phone.' }),
        UI.el('li', { text: 'Scan this QR code (or type the key below).' }),
        UI.el('li', { text: 'Enter the 6-digit code the app shows.' })),
      UI.el('img', { src: setup.qrDataUrl, alt: 'QR code for your authenticator app', width: '220', height: '220' }),
      UI.el('p', { class: 'muted small' }, 'Key: ', UI.el('code', { text: setup.secret.replace(/(.{4})/g, '$1 ').trim() })),
      form);

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      err.textContent = '';
      const { code } = UI.formData(form);
      if (!/^\d{6}$/.test(code || '')) { err.textContent = 'Enter the 6 digits shown in the app.'; return; }
      try {
        const res = await Api.post('/api/auth/mfa/enable', { code });
        MfaSetup.showRecovery(box, res.recoveryCodes, () => onDone(res));
      } catch (error) { err.textContent = error.message; }
    });
  },

  showRecovery(box, codes, next) {
    UI.clear(box).append(
      UI.el('h2', { text: 'Save your recovery codes' }),
      UI.el('p', { class: 'muted', text: 'If you lose your phone, each code below lets you log in once. They are shown only now: write them down or keep them in a password manager.' }),
      UI.el('ul', { class: 'recovery-codes' }, codes.map((c) => UI.el('li', {}, UI.el('code', { text: c })))),
      UI.el('button', { class: 'primary', type: 'button', text: 'I have saved them', onclick: next }));
  }
};

const AuthView = {
  init() {
    const loginForm = document.getElementById('form-login');
    const registerForm = document.getElementById('form-register');
    const err = document.getElementById('auth-error');
    const tabLogin = document.getElementById('tab-login');
    const tabRegister = document.getElementById('tab-register');
    this.err = err;
    this.loginForm = loginForm;
    // Box for the second login step, placed just above the error line of the login card.
    this.stepBox = UI.el('div', { id: 'mfa-step', class: 'hidden' });
    err.before(this.stepBox);

    const showTab = (login) => {
      this.resetStep();
      tabLogin.classList.toggle('active', login);
      tabRegister.classList.toggle('active', !login);
      loginForm.classList.toggle('hidden', !login);
      registerForm.classList.toggle('hidden', login);
      err.textContent = '';
    };
    tabLogin.addEventListener('click', () => showTab(true));
    tabRegister.addEventListener('click', () => showTab(false));

    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      err.textContent = '';
      const data = UI.formData(loginForm);
      if (!data.email || !data.password) { err.textContent = 'Enter your e-mail and password.'; return; }
      try {
        const res = await Api.post('/api/auth/login', { email: data.email, password: data.password });
        loginForm.reset();
        if (res.mfaRequired) this.askCode(res.mfaToken);
        else if (res.mfaSetupRequired) this.forceSetup(res.mfaToken);
        else AuthView.start(res);
      } catch (error) { err.textContent = error.message; }
    });

    registerForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      err.textContent = '';
      const data = UI.formData(registerForm);
      if (!/^(?=.*[A-Za-z])(?=.*\d).{10,}$/.test(data.password || '')) {
        err.textContent = 'Password must be at least 10 characters with a letter and a digit.';
        return;
      }
      try {
        const res = await Api.post('/api/auth/register', data);
        AuthView.start(res);
        registerForm.reset();
        UI.toast('Account created. Start by adding a bucket.');
      } catch (error) { err.textContent = error.message; }
    });

    document.getElementById('logout').addEventListener('click', () => AuthView.logout());
    window.addEventListener('pb:logout', () => AuthView.logout('Your session ended. Please log in again.'));
    AccountView.init();

    Api.get('/api/auth/health')
      .then((h) => { document.getElementById('api-status').textContent = `API online (${h.runtime}).`; })
      .catch(() => { document.getElementById('api-status').textContent = 'API not reachable.'; });
  },

  resetStep() {
    if (!this.stepBox) return;
    UI.clear(this.stepBox).classList.add('hidden');
    this.loginForm.classList.remove('hidden');
  },

  // Step 2 of login: the code from the app, or a recovery code.
  askCode(mfaToken) {
    this.loginForm.classList.add('hidden');
    const box = UI.clear(this.stepBox);
    box.classList.remove('hidden');
    let useRecovery = false;
    const input = UI.el('input', { name: 'code', inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: '6', required: true });
    const label = UI.el('label', {}, UI.el('span', { text: '6-digit code from your authenticator app ' }), input);
    const switchLink = UI.el('button', { class: 'link', type: 'button', text: 'Use a recovery code instead' });
    const form = UI.el('form', { novalidate: true }, label,
      UI.el('button', { class: 'primary', type: 'submit', text: 'Verify' }), switchLink,
      UI.el('button', { class: 'link', type: 'button', text: 'Back', onclick: () => this.resetStep() }));
    switchLink.addEventListener('click', () => {
      useRecovery = !useRecovery;
      label.firstChild.textContent = useRecovery ? 'Recovery code (xxxxx-xxxxx) ' : '6-digit code from your authenticator app ';
      input.setAttribute('maxlength', useRecovery ? '11' : '6');
      input.setAttribute('inputmode', useRecovery ? 'text' : 'numeric');
      switchLink.textContent = useRecovery ? 'Use the app code instead' : 'Use a recovery code instead';
      input.value = '';
      input.focus();
    });
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      this.err.textContent = '';
      const value = input.value.trim();
      const body = useRecovery ? { mfaToken, recoveryCode: value } : { mfaToken, code: value };
      if (!useRecovery && !/^\d{6}$/.test(value)) { this.err.textContent = 'Enter the 6 digits shown in the app.'; return; }
      try {
        const res = await Api.post('/api/auth/mfa/verify', body);
        this.resetStep();
        AuthView.start(res);
        if (res.recoveryCodesLeft !== undefined) UI.toast(`Recovery code used. ${res.recoveryCodesLeft} left: set up a new app soon if your phone is lost.`, true);
      } catch (error) {
        this.err.textContent = error.message;
        if (error.status === 429 || /expired/i.test(error.message)) this.resetStep();
      }
    });
    box.append(UI.el('h2', { text: 'Two-step login' }), form);
    input.focus();
  },

  // Admins without two-step login: set it up now, then they are logged in.
  forceSetup(mfaToken) {
    this.loginForm.classList.add('hidden');
    const box = UI.clear(this.stepBox);
    box.classList.remove('hidden');
    Api.token = mfaToken; // the short setup ticket: only /mfa/setup and /mfa/enable accept it
    const cancel = () => { Api.token = null; this.resetStep(); };
    MfaSetup.render(box, {
      intro: 'Administrators must use two-step login. Set it up now to continue.',
      onCancel: cancel,
      onDone: (res) => { this.resetStep(); AuthView.start(res); UI.toast('Two-step login is on.'); }
    });
  },

  start({ token, user }) {
    Api.token = token;
    sessionStorage.setItem('pb_user', JSON.stringify(user));
    App.enter();
  },

  logout(message) {
    Api.token = null;
    sessionStorage.removeItem('pb_user');
    this.resetStep();
    App.leave();
    if (message) UI.toast(message, true);
  }
};

// Security page: two-step login on/off. Opened from the "Security" link next to "Log out".
const AccountView = {
  init() {
    this.view = UI.el('main', { id: 'view-account', class: 'view hidden' },
      UI.el('div', { class: 'view-head' }, UI.el('h1', { text: 'Security' })),
      UI.el('section', { class: 'card' }, UI.el('h2', { text: 'Two-step login' }), UI.el('div', { id: 'mfa-panel' })));
    const views = document.querySelectorAll('main.view');
    views[views.length - 1].after(this.view);
    document.getElementById('logout').before(UI.el('button', {
      id: 'open-account', class: 'link', type: 'button', text: 'Security',
      onclick: () => { App.show('account'); this.load(); }
    }));
  },

  async load() {
    const panel = UI.clear(document.getElementById('mfa-panel'));
    let me;
    try { me = await Api.get('/api/auth/me'); } catch (e) { UI.fail(e); return; }
    sessionStorage.setItem('pb_user', JSON.stringify(me));

    if (!me.mfaEnabled) {
      panel.append(
        UI.el('p', { text: 'Off. With two-step login, a stolen password is not enough to get into your account.' }),
        UI.el('button', { class: 'primary', type: 'button', text: 'Turn on', onclick: () => MfaSetup.render(panel, {
          intro: 'Link an authenticator app to your account.',
          onCancel: () => this.load(),
          onDone: () => { UI.toast('Two-step login is on.'); this.load(); }
        }) }));
      return;
    }
    panel.append(UI.el('p', { text: 'On. You are asked for a code from your authenticator app at every login.' }));
    if (me.role === 'admin') {
      panel.append(UI.el('p', { class: 'muted', text: 'Two-step login is required for administrators and cannot be turned off.' }));
      return;
    }
    const err = UI.el('p', { class: 'error', role: 'alert' });
    const form = UI.el('form', { novalidate: true },
      UI.el('label', {}, 'Password ', UI.el('input', { name: 'password', type: 'password', autocomplete: 'current-password', required: true, maxlength: '128' })),
      UI.el('label', {}, 'Code from the app ', UI.el('input', { name: 'code', inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: '6', required: true })),
      UI.el('button', { class: 'danger', type: 'submit', text: 'Turn off two-step login' }), err);
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      err.textContent = '';
      const d = UI.formData(form);
      try {
        await Api.post('/api/auth/mfa/disable', { password: d.password, code: d.code });
        UI.toast('Two-step login is off.');
        this.load();
      } catch (error) { err.textContent = error.message; }
    });
    panel.append(form);
  }
};
