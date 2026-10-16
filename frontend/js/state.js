// ============================================================
// CloudShield shared client state and action registry
// ============================================================

import { get } from './api.js';
import { esc, html, mount, dateTime } from './utils.js';

export const state = {
  user: null,        // { id, email, role }
  env: null,         // result of GET /api/sim/environment (null until one exists)
  stale: false,      // true when the environment changed since the latest scan
  openFindings: null,
};

const actions = {};
const forms = {};
let rerenderFn = () => {};

export function registerActions(map) { Object.assign(actions, map); }
export function registerForms(map) { Object.assign(forms, map); }
export function setRerender(fn) { rerenderFn = fn; }
export const rerender = () => rerenderFn();

export const isAdmin = () => state.user && state.user.role === 'admin';
export const canAnalyze = () => state.user && ['admin', 'analyst'].includes(state.user.role);

export function roleNote(needed) {
  return html`<div class="banner info">Your role (<b>${state.user ? state.user.role : 'unknown'}</b>) is read-only for this control. ${needed} access is required to change state.</div>`;
}

// --- event delegation: one listener per event type for the whole app ---
document.addEventListener('click', async (ev) => {
  const el = ev.target.closest('[data-action]');
  if (!el || el.disabled) return;
  const fn = actions[el.dataset.action];
  if (!fn) return;
  if (el.tagName === 'A') ev.preventDefault();
  try { await fn(el, ev); } catch (e) { reportError(e); }
});

document.addEventListener('submit', async (ev) => {
  const form = ev.target.closest('form[data-form]');
  if (!form) return;
  ev.preventDefault();
  const fn = forms[form.dataset.form];
  if (!fn) return;
  try { await fn(form, ev); } catch (e) { reportError(e); }
});

document.addEventListener('change', async (ev) => {
  const el = ev.target.closest('[data-change]');
  if (!el) return;
  const fn = actions[el.dataset.change];
  if (!fn) return;
  try { await fn(el, ev); } catch (e) { reportError(e); }
});

document.addEventListener('input', async (ev) => {
  const el = ev.target.closest('[data-input]');
  if (!el) return;
  const fn = actions[el.dataset.input];
  if (!fn) return;
  try { await fn(el, ev); } catch (e) { reportError(e); }
});

document.addEventListener('keydown', (ev) => {
  if (ev.key !== 'Enter' && ev.key !== ' ') return;
  const el = ev.target.closest && ev.target.closest('tr[data-action][tabindex]');
  if (el && ev.target === el) { ev.preventDefault(); el.click(); }
});

let errorSink = (e) => console.error(e); // replaced once toast is available
export function setErrorSink(fn) { errorSink = fn; }
export function reportError(e) { errorSink(e); }

// --- chrome (topbar environment chip, sidebar counters) ---
export async function refreshEnv() {
  try {
    state.env = await get('/api/sim/environment');
  } catch (e) {
    state.env = null;
  }
  renderChrome();
  return state.env;
}

export async function refreshStale() {
  try {
    const d = await get('/api/sim/dashboard');
    state.stale = !!d.stale;
    state.openFindings = d.security.open_findings;
  } catch (e) {
    state.stale = false;
  }
  renderChrome();
}

export function renderChrome() {
  const env = state.env;
  mount('env-chip', env
    ? html`<div class="env-chip" title="Active simulated environment"><b>${env.name} · ${env.region}</b><span>Account ${env.account_id} · sim time ${dateTime(env.sim_time).slice(0, 16)} UTC</span></div>`
    : html`<div class="env-chip"><b>No environment</b><span>Generate one in Simulator</span></div>`);
  mount('stale-slot', state.stale
    ? html`<button class="stale-chip" data-action="run-scan" title="Findings and recommendations may be out of date">State changed since last scan — run scan</button>`
    : '');
  const badge = document.getElementById('nav-count-security');
  if (badge) badge.textContent = state.openFindings === null || state.openFindings === undefined ? '' : String(state.openFindings);
  const name = document.getElementById('user-name');
  if (name && state.user) {
    name.textContent = state.user.email;
    document.getElementById('user-role').textContent = state.user.role;
    document.getElementById('user-initial').textContent = state.user.email.slice(0, 1).toUpperCase();
  }
}

export { esc };
