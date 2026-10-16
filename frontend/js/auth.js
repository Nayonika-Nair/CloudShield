// ============================================================
// CloudShield Auth
// ============================================================
// Real sign-in / sign-up against the API, plus view toggling
// between the login screen and the application shell.

import { API_BASE, ApiError, api, get, getToken, setToken } from './api.js';
import { registerActions, registerForms, state, refreshEnv, refreshStale } from './state.js';
import { toast } from './utils.js';

let signup = false;

function showLoginError(msg) {
  const box = document.getElementById('login-error');
  box.textContent = msg;
  box.classList.toggle('hidden', !msg);
}

function showApp(show) {
  document.getElementById('view-login').classList.toggle('hidden', show);
  document.getElementById('view-app').classList.toggle('hidden', !show);
}

function setSignup(on) {
  signup = on;
  document.getElementById('login-heading').textContent = on ? 'Create account' : 'Sign in';
  document.getElementById('login-sub').textContent = on
    ? 'New accounts are read-only viewers until an administrator changes their role.'
    : 'Access your cloud security & cost console';
  document.getElementById('login-submit').textContent = on ? 'Create account' : 'Sign in';
  document.getElementById('toggle-text').textContent = on ? 'Already registered?' : 'No account?';
  document.getElementById('toggle-signup').textContent = on ? 'Sign in' : 'Create one';
  document.getElementById('password-hint').classList.toggle('hidden', !on);
  document.getElementById('login-password').autocomplete = on ? 'new-password' : 'current-password';
  showLoginError('');
}

export async function loadUser() {
  state.user = await get('/api/auth/me');
  return state.user;
}

export async function enterApp(onReady) {
  await loadUser();
  showApp(true);
  await refreshEnv();
  await refreshStale();
  if (onReady) await onReady();
}

export function leaveApp(message) {
  setToken(null);
  state.user = null;
  state.env = null;
  showApp(false);
  if (message) showLoginError(message);
}

export function initAuth(onReady) {
  document.getElementById('api-note').textContent = 'API: ' + (API_BASE || window.location.origin);

  registerActions({
    'toggle-signup': () => setSignup(!signup),
    logout: () => { leaveApp(''); toast('Signed out', 'info'); },
  });

  registerForms({
    login: async (form) => {
      const email = form.email.value.trim();
      const password = form.password.value;
      if (!email || !password) { showLoginError('Enter your email address and password.'); return; }
      const btn = document.getElementById('login-submit');
      btn.disabled = true;
      showLoginError('');
      try {
        if (signup) {
          await api('/api/auth/register', { method: 'POST', body: { email, password }, auth: false });
        }
        const tok = await api('/api/auth/login', { method: 'POST', body: { email, password }, auth: false });
        setToken(tok.access_token);
        form.password.value = '';
        await enterApp(onReady);
      } catch (e) {
        showLoginError(e instanceof ApiError ? e.message : 'Sign-in failed.');
      } finally {
        btn.disabled = false;
      }
    },
  });

  window.addEventListener('cloudshield:session-expired', () => leaveApp('Your session expired. Please sign in again.'));
  return getToken();
}
